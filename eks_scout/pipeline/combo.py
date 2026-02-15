"""High-risk combination detection for co-occurring findings on the same workload.

Identifies workloads where multiple security findings combine to create
attack chains (e.g., privileged + hostPath = container escape). Only reports
multi-finding combinations — single-finding risks are already covered by
individual checks.
"""
import logging
from collections import defaultdict
from typing import List, Dict, Any, Set, Tuple, Optional

from eks_scout.config import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_RANK


# Finding types that all indicate "container may run as root" —
# treated as equivalent for combination matching.
ROOT_FINDING_ALIASES = {
    "Container Running As Root",
    "Container Allowed to Run As Root",
    "Container May Run As Root",
}
ROOT_CANONICAL = "Container Running As Root"


# --------------------------------------------------------------------------- #
# Built-in combination definitions
# --------------------------------------------------------------------------- #
# Each entry: (required_finding_types, risk_level, title, impact, remediation)
# All entries require >=2 distinct finding types.

BUILTIN_COMBINATIONS: List[Tuple[Set[str], str, str, str, str]] = [
    # --- Critical: direct container escape / host compromise ---
    (
        {"Privileged Container", "Pod Using HostPath Volume"},
        SEVERITY_CRITICAL,
        "Privileged Container with Host Filesystem Access",
        "Privileged mode removes container isolation. Combined with host path access, "
        "this creates a direct path for container escape, host filesystem manipulation, "
        "and potential compromise of the entire node.",
        "Remove privileged mode (securityContext.privileged: false). Remove or replace "
        "hostPath volumes with PersistentVolumes. If host access is essential, use "
        "read-only mounts with non-root users.",
    ),
    (
        {"Privileged Container", "Pod Using Host Network"},
        SEVERITY_CRITICAL,
        "Privileged Container with Host Network Access",
        "Privileged mode combined with host network bypasses container network isolation "
        "and allows control over the node's network stack, enabling traffic sniffing, "
        "spoofing, and Network Policy bypass.",
        "Disable privileged mode (securityContext.privileged: false). Remove host "
        "network usage (hostNetwork: false). If host network is essential, ensure "
        "the container runs as non-root with strict NetworkPolicies.",
    ),

    # --- Critical: SYS_ADMIN capability + host access ---
    (
        {"Dangerous Capabilities Added", "Pod Using HostPath Volume"},
        SEVERITY_CRITICAL,
        "SYS_ADMIN Capability with Host Filesystem Access",
        "SYS_ADMIN capability is effectively equivalent to privileged mode. Combined "
        "with host path access, this creates a direct path for container escape and "
        "host filesystem manipulation.",
        "Remove SYS_ADMIN from capabilities.add. Drop ALL capabilities and only add "
        "back specific ones required. Remove or replace hostPath volumes with "
        "PersistentVolumes.",
    ),
    (
        {"Dangerous Capabilities Added", "Pod Using Host Network"},
        SEVERITY_CRITICAL,
        "SYS_ADMIN Capability with Host Network Access",
        "SYS_ADMIN capability combined with host network bypasses container isolation "
        "on both privilege and network fronts, enabling full node compromise.",
        "Remove SYS_ADMIN from capabilities.add. Remove host network usage. Use "
        "standard networking and minimal capabilities.",
    ),

    # --- Critical/High: root + host access ---
    (
        {"Pod Using HostPath Volume", ROOT_CANONICAL},
        SEVERITY_HIGH,
        "Root Container with Host Filesystem Access",
        "Root privileges inside a container with hostPath access allow direct "
        "manipulation of host files. If the mounted path is sensitive (/, /etc, "
        "/var/run/docker.sock), this can lead to credential theft, node "
        "configuration changes, or container escape.",
        "Run containers as non-root (runAsNonRoot: true, runAsUser: >0). Remove or "
        "replace hostPath volumes. If hostPath is needed, mount the least sensitive "
        "path possible with readOnly: true.",
    ),

    # --- High: host isolation breakdowns ---
    (
        {"Pod Using Host Network", ROOT_CANONICAL},
        SEVERITY_HIGH,
        "Root Container with Host Network Access",
        "Root privileges combined with host network access allow manipulation of "
        "node network configurations, traffic sniffing, direct access to node-level "
        "services, and Network Policy bypass.",
        "Run containers as non-root (runAsNonRoot: true, runAsUser: >0). Avoid "
        "hostNetwork where possible. If essential, ensure non-root execution and "
        "strong NetworkPolicies.",
    ),
    (
        {"Pod Using Host PID Namespace", ROOT_CANONICAL},
        SEVERITY_HIGH,
        "Root Container with Host PID Visibility",
        "Root access to the host PID namespace allows interaction with all host "
        "processes — risking information disclosure, process manipulation, and "
        "disruption of critical node components.",
        "Run containers as non-root (runAsNonRoot: true, runAsUser: >0). Avoid "
        "hostPID unless essential for specific monitoring tools.",
    ),
    (
        {"Pod IRSA Role Potentially Overly Permissive", ROOT_CANONICAL},
        SEVERITY_HIGH,
        "Root Container with Overprivileged AWS Role",
        "A container running as root with a potentially overpermissive IRSA role "
        "means that application compromise trivially leads to AWS resource abuse. "
        "Root makes exploitation easier; the broad IAM role expands blast radius.",
        "Run containers as non-root (runAsNonRoot: true, runAsUser: >0). Review "
        "and restrict the IAM role to least privilege.",
    ),
    (
        {"Pod Using Host Network", "Pod Using Host PID Namespace"},
        SEVERITY_HIGH,
        "Multiple Host Namespace Breakouts",
        "Using multiple host namespaces (network + PID) significantly reduces "
        "container isolation, increasing attack surface for escape, information "
        "gathering, or host interference.",
        "Remove host namespace usage. Use standard networking and sidecar containers "
        "for monitoring. If unavoidable, ensure non-root users, read-only filesystems, "
        "minimal capabilities, and node isolation.",
    ),
    (
        {"Pod Using Host Network", "Pod Using HostPath Volume"},
        SEVERITY_HIGH,
        "Host Network with Host Filesystem Access",
        "Reduced isolation on both network and filesystem fronts significantly "
        "increases the attack surface and potential impact of container compromise.",
        "Remove hostPath or replace with PersistentVolumes. If host network is "
        "essential, ensure hostPath is read-only and mounts the least sensitive path. "
        "Run containers as non-root.",
    ),
    (
        {"Pod Using Host PID Namespace", "Pod Using HostPath Volume"},
        SEVERITY_HIGH,
        "Host PID Visibility with Host Filesystem Access",
        "Visibility into host processes combined with host filesystem access "
        "significantly increases attack surface for information disclosure and "
        "container escape.",
        "Remove hostPath or replace with PersistentVolumes. Avoid hostPID unless "
        "essential. Ensure minimal privileges and non-root execution.",
    ),
    (
        {"Pod Using HostPath Volume", "Container Allows Privilege Escalation"},
        SEVERITY_HIGH,
        "Host Filesystem Access with Privilege Escalation",
        "Host path access combined with privilege escalation capability means an "
        "attacker who gains initial access can escalate privileges and then "
        "manipulate host resources or escape the container.",
        "Set allowPrivilegeEscalation: false. Remove or replace hostPath with "
        "PersistentVolumes. If hostPath is needed, use readOnly mounts.",
    ),

    # --- Medium: amplifiers ---
    (
        {"Container Allows Privilege Escalation", ROOT_CANONICAL},
        SEVERITY_MEDIUM,
        "Root Container with Privilege Escalation Allowed",
        "While already running as root, explicit privilege escalation allowance "
        "may enable specific exploits targeting SUID binaries or kernel "
        "vulnerabilities.",
        "Set allowPrivilegeEscalation: false and run as non-root "
        "(runAsNonRoot: true, runAsUser: >0).",
    ),
    (
        {"Container Root Filesystem Writable", ROOT_CANONICAL},
        SEVERITY_MEDIUM,
        "Root Container with Writable Filesystem",
        "Root access with a writable filesystem makes it easier for an attacker "
        "to achieve persistence, install tooling, or modify application behavior "
        "within the container.",
        "Set readOnlyRootFilesystem: true and run as non-root. Use emptyDir or "
        "PersistentVolume mounts for required writable directories.",
    ),
]


def _normalize_finding_types(finding_types: Set[str]) -> Set[str]:
    """Normalize root-related finding types to a canonical form.

    This allows combination matching to treat all root variants identically.
    """
    normalized = set()
    for ft in finding_types:
        if ft in ROOT_FINDING_ALIASES:
            normalized.add(ROOT_CANONICAL)
        else:
            normalized.add(ft)
    return normalized


def _group_findings_by_workload(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group findings by workload identity (namespace/name).

    For container-level findings (name like "workload/container"), groups
    under the workload name. This matches the ownerReferences-based reporting
    from the pods check.

    Returns:
        Dict mapping "namespace/workload_name" -> list of findings.
    """
    groups = defaultdict(list)

    for finding in findings:
        ns = finding.get('namespace', '(cluster)')
        name = finding.get('name', '')

        # Container findings use "workload/container" format.
        # Extract the workload name for grouping.
        workload_name = name.split('/')[0] if '/' in name else name

        key = f"{ns}/{workload_name}"
        groups[key].append(finding)

    return groups


def analyze_combinations(
    findings: List[Dict[str, Any]],
    custom_combinations: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Detect high-risk finding combinations on workloads.

    Groups findings by workload identity, then checks each workload
    against combination definitions. Only multi-finding combinations
    are reported.

    Args:
        findings: List of finding dicts from the scan.
        custom_combinations: Optional list of custom combination defs
            from the config file. Each dict should have:
            - finding_types: list of finding type strings
            - risk_level: severity string
            - title: short title
            - impact: impact narrative
            - remediation: remediation guidance

    Returns:
        List of combo result dicts, each containing:
        - namespace: workload namespace
        - workload_name: workload name
        - workload_key: "namespace/name"
        - risk_level: severity of the combination
        - title: combination title
        - impact: impact narrative
        - remediation: remediation guidance
        - matched_finding_types: set of finding types that triggered the match
        - contributing_findings: list of finding dicts from this workload
    """
    # Build full combination list
    combinations = list(BUILTIN_COMBINATIONS)

    if custom_combinations:
        for custom in custom_combinations:
            types = set(custom.get('finding_types', []))
            if len(types) < 2:
                logging.warning(
                    f"Skipping custom combination with fewer than 2 finding types: {custom}"
                )
                continue
            combinations.append((
                types,
                custom.get('risk_level', SEVERITY_HIGH),
                custom.get('title', 'Custom Combination'),
                custom.get('impact', 'Multiple findings co-occur on this workload.'),
                custom.get('remediation', 'Review the contributing findings.'),
            ))

    # Group findings by workload
    workload_groups = _group_findings_by_workload(findings)

    results = []

    for workload_key, workload_findings in workload_groups.items():
        # Collect all finding types present on this workload
        raw_types = {f.get('type', '') for f in workload_findings}
        normalized_types = _normalize_finding_types(raw_types)

        # Check each combination definition
        workload_combos = []
        for required_types, risk_level, title, impact, remediation in combinations:
            # Normalize the required types too (in case they use aliases)
            required_normalized = _normalize_finding_types(required_types)
            if required_normalized.issubset(normalized_types):
                parts = workload_key.split('/', 1)
                ns = parts[0] if len(parts) > 1 else '(cluster)'
                name = parts[1] if len(parts) > 1 else parts[0]

                workload_combos.append({
                    'namespace': ns,
                    'workload_name': name,
                    'workload_key': workload_key,
                    'risk_level': risk_level,
                    'title': title,
                    'impact': impact,
                    'remediation': remediation,
                    'matched_finding_types': required_types,
                    'contributing_findings': workload_findings,
                })

        # Sort combos for this workload by severity (most severe first)
        workload_combos.sort(key=lambda c: SEVERITY_RANK.get(c['risk_level'], 99))
        results.extend(workload_combos)

    # Sort overall results: by severity, then workload key
    results.sort(key=lambda c: (SEVERITY_RANK.get(c['risk_level'], 99), c['workload_key']))

    if results:
        workload_count = len({r['workload_key'] for r in results})
        logging.info(
            f"Combo analysis: found {len(results)} high-risk combinations "
            f"across {workload_count} workloads."
        )
    else:
        logging.info("Combo analysis: no high-risk finding combinations detected.")

    return results
