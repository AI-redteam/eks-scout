"""Cross-scope combination detection for infrastructure + workload attack chains.

Infrastructure findings (namespace='(cluster)', check_id starting with 'aws.')
apply to *all* workloads. When an infra weakness exists alongside a pod-level
weakness, the combination creates an attack path that neither finding alone
represents (e.g., SCARLETEEL: host network + IMDSv1 -> AWS credential theft).
"""
import logging
from collections import defaultdict
from typing import List, Dict, Any, Set, Tuple

from eks_scout.config import (
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_RANK,
)


# --------------------------------------------------------------------------- #
# Cross-scope combination definitions
# --------------------------------------------------------------------------- #
# Each entry:
#   (infra_finding_type, pod_finding_type, risk_level, title, impact, remediation)
#
# For infra+infra combos (both namespace='(cluster)'), the engine reports once
# per matching pair rather than once per workload.

CROSS_SCOPE_COMBINATIONS: List[Tuple[str, str, str, str, str, str]] = [
    # --- Critical: IMDS credential theft ---
    (
        "IMDSv2 Not Enforced",
        "Pod Using Host Network",
        SEVERITY_CRITICAL,
        "IMDS Credential Theft via Host Network",
        "Host network access exposes the EC2 metadata service (169.254.169.254). "
        "Without IMDSv2 enforcement, any pod on the host network can steal node "
        "IAM credentials with a simple HTTP request — the core of the SCARLETEEL "
        "attack pattern.",
        "Enforce IMDSv2 on all nodes (HttpTokens: required, hop limit: 1). Remove "
        "host network access (hostNetwork: false) where not essential.",
    ),
    (
        "IMDSv2 Not Enforced",
        "Privileged Container",
        SEVERITY_CRITICAL,
        "IMDS Credential Theft via Privileged Container",
        "Privileged containers can manipulate network namespaces to reach the EC2 "
        "metadata service. Without IMDSv2, this grants access to node IAM "
        "credentials, enabling cloud-level pivot from container compromise.",
        "Enforce IMDSv2 on all nodes (HttpTokens: required, hop limit: 1). Remove "
        "privileged mode (securityContext.privileged: false).",
    ),

    # --- Critical/High: overprivileged node role ---
    (
        "Node IAM Role Has Overly Broad Policy",
        "Privileged Container",
        SEVERITY_CRITICAL,
        "Overprivileged Node Role with Container Escape",
        "A privileged container can escape to the host node. If the node IAM role "
        "has overly broad permissions, the attacker inherits those permissions — "
        "potentially gaining access to S3, EC2, IAM, and other AWS services.",
        "Restrict the node IAM role to minimum required permissions. Remove "
        "privileged mode (securityContext.privileged: false).",
    ),
    (
        "Node IAM Role Has Overly Broad Policy",
        "Pod Using HostPath Volume",
        SEVERITY_HIGH,
        "Overprivileged Node Role with Host Filesystem Access",
        "Host filesystem access allows reading node IAM credentials from disk. "
        "Combined with an overly broad node role, this enables direct AWS "
        "credential theft and cloud resource abuse.",
        "Restrict the node IAM role to minimum required permissions. Remove or "
        "replace hostPath volumes with PersistentVolumes.",
    ),
    (
        "Node IAM Role Has Overly Broad Policy",
        "Pod Using Host Network",
        SEVERITY_HIGH,
        "Overprivileged Node Role with Host Network Access",
        "Host network access enables reaching the IMDS endpoint. Combined with an "
        "overly broad node IAM role, this creates a path from pod compromise to "
        "broad AWS permissions via metadata credential theft.",
        "Restrict the node IAM role to minimum required permissions. Remove host "
        "network access (hostNetwork: false). Enforce IMDSv2.",
    ),

    # --- High: public API + cluster-admin ---
    (
        "EKS Public API Endpoint Open to Internet",
        "ClusterRoleBinding Grants High Privileges",
        SEVERITY_HIGH,
        "Public API Endpoint with Cluster Admin Privileges",
        "An internet-exposed Kubernetes API combined with cluster-admin level "
        "RBAC bindings means that compromised credentials grant full cluster "
        "control from anywhere on the internet.",
        "Restrict API endpoint to private access or allowlisted CIDRs. Review "
        "and minimize ClusterRoleBindings with high privileges.",
    ),

    # --- Medium: unencrypted secrets ---
    (
        "EKS Secrets Encryption Not Enabled",
        "Secret Contains Sensitive-Looking Keys",
        SEVERITY_MEDIUM,
        "Unencrypted Secrets with Sensitive Data",
        "Kubernetes secrets containing credentials and API keys are stored in "
        "plaintext in etcd when envelope encryption is not enabled, making them "
        "vulnerable to etcd snapshot theft or backup exposure.",
        "Enable EKS secrets encryption with a KMS key. Rotate any sensitive "
        "values currently stored in plaintext secrets.",
    ),

    # --- Critical: unrestricted SSH + broad role (infra+infra) ---
    (
        "Nodegroup SSH Access Enabled Without Source Restriction",
        "Node IAM Role Has Overly Broad Policy",
        SEVERITY_CRITICAL,
        "Unrestricted SSH with Overprivileged Node Role",
        "Unrestricted SSH access to nodes combined with an overly broad IAM role "
        "means successful SSH brute-force or key compromise grants broad AWS "
        "permissions — a direct path to full node and cloud account compromise.",
        "Restrict SSH access to specific source CIDRs or disable SSH entirely. "
        "Restrict the node IAM role to minimum required permissions. Use "
        "SSM Session Manager instead of SSH for node access.",
    ),
]


# Finding types that are always infra-scoped (namespace='(cluster)').
_INFRA_FINDING_TYPES = {
    "IMDSv2 Not Enforced",
    "Node IAM Role Has Overly Broad Policy",
    "EKS Public API Endpoint Open to Internet",
    "EKS Secrets Encryption Not Enabled",
    "Nodegroup SSH Access Enabled Without Source Restriction",
    "ClusterRoleBinding Grants High Privileges",
}


def analyze_cross_scope_combinations(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Detect cross-scope attack chains between infrastructure and workload findings.

    Infrastructure findings apply cluster-wide. When they co-exist with
    pod-level weaknesses, the combination creates attack paths that neither
    finding alone represents.

    Args:
        findings: List of finding dicts from the scan.

    Returns:
        List of combo result dicts (same shape as analyze_combinations output).
    """
    # Partition findings into infra vs workload buckets
    infra_by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    workload_by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for f in findings:
        ns = f.get('namespace', '(cluster)')
        ftype = f.get('type', '')
        if ns == '(cluster)' or ftype in _INFRA_FINDING_TYPES:
            infra_by_type[ftype].append(f)
        else:
            workload_by_type[ftype].append(f)

    results: List[Dict[str, Any]] = []

    for infra_type, pod_type, risk_level, title, impact, remediation in CROSS_SCOPE_COMBINATIONS:
        infra_findings = infra_by_type.get(infra_type, [])
        if not infra_findings:
            continue

        # Check if pod_type is also infra-scoped (infra+infra combo)
        if pod_type in _INFRA_FINDING_TYPES:
            pod_findings = infra_by_type.get(pod_type, [])
            if not pod_findings:
                continue
            # Report once for the infra+infra pair
            results.append({
                'namespace': '(cluster)',
                'workload_name': '(infrastructure)',
                'workload_key': '(cluster)/(infrastructure)',
                'risk_level': risk_level,
                'title': title,
                'impact': impact,
                'remediation': remediation,
                'matched_finding_types': {infra_type, pod_type},
                'contributing_findings': infra_findings + pod_findings,
            })
        else:
            # Standard cross-scope: infra finding + workload finding
            pod_findings = workload_by_type.get(pod_type, [])
            if not pod_findings:
                continue

            # Group workload findings by workload key to report once per workload
            workloads: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for pf in pod_findings:
                ns = pf.get('namespace', '(cluster)')
                name = pf.get('name', '')
                wl_name = name.split('/')[0] if '/' in name else name
                key = f"{ns}/{wl_name}"
                workloads[key].append(pf)

            for wl_key, wl_findings in workloads.items():
                parts = wl_key.split('/', 1)
                ns = parts[0] if len(parts) > 1 else '(cluster)'
                name = parts[1] if len(parts) > 1 else parts[0]

                results.append({
                    'namespace': ns,
                    'workload_name': name,
                    'workload_key': wl_key,
                    'risk_level': risk_level,
                    'title': title,
                    'impact': impact,
                    'remediation': remediation,
                    'matched_finding_types': {infra_type, pod_type},
                    'contributing_findings': infra_findings + wl_findings,
                })

    # Sort by severity then workload key
    results.sort(key=lambda c: (SEVERITY_RANK.get(c['risk_level'], 99), c['workload_key']))

    if results:
        workload_count = len({r['workload_key'] for r in results})
        logging.info(
            f"Cross-scope combo analysis: found {len(results)} cross-scope "
            f"combinations across {workload_count} workloads."
        )
    else:
        logging.info("Cross-scope combo analysis: no cross-scope combinations detected.")

    return results
