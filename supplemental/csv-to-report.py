#!/usr/bin/env python3
"""EKS Scout — CSV-to-Client-Report Generator.

Reads the CSV output from EKS Scout v2 and produces a professional,
client-ready Markdown report suitable for inclusion in penetration test
or configuration review deliverables.

Usage:
    python csv-to-report.py -i eks_findings_plextrac.csv -o client-report.md
    python csv-to-report.py -i findings.csv -o report.md --cluster prod-cluster
"""

import csv
import argparse
import re
from collections import defaultdict, Counter
from datetime import datetime


# ---------------------------------------------------------------------------
# Category mapping — mirrors the HTML report's getCategory() logic
# ---------------------------------------------------------------------------
CATEGORY_MAP = {
    "k8s.pods": "Pod & Container Security",
    "k8s.rbac": "RBAC Configuration",
    "k8s.netpol": "Network Policies",
    "k8s.services": "Network Exposure",
    "k8s.psa": "Pod Security Admission",
    "k8s.namespaces": "Namespace Governance",
    "k8s.serviceaccounts": "Service Accounts",
    "k8s.secrets": "Secrets & ConfigMaps",
    "aws.cluster": "EKS Cluster Configuration",
    "aws.nodegroups": "EKS Nodegroup Security",
    "aws.iam": "IAM Role Analysis",
    "aws.sg": "Security Groups",
    "aws.guardduty": "GuardDuty",
}

CATEGORY_ORDER = [
    "EKS Cluster Configuration",
    "EKS Nodegroup Security",
    "IAM Role Analysis",
    "Security Groups",
    "GuardDuty",
    "Namespace Governance",
    "Pod & Container Security",
    "Service Accounts",
    "RBAC Configuration",
    "Network Policies",
    "Network Exposure",
    "Secrets & ConfigMaps",
]

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}

# ---------------------------------------------------------------------------
# Root-finding aliases — treated as equivalent for combo matching
# ---------------------------------------------------------------------------
ROOT_FINDING_ALIASES = {
    "Container Running As Root",
    "Container Allowed to Run As Root",
    "Container May Run As Root",
}
ROOT_CANONICAL = "Container Running As Root"

# ---------------------------------------------------------------------------
# Same-workload high-risk combinations
# ---------------------------------------------------------------------------
# (required_types, severity, title, impact, remediation)
SAME_WORKLOAD_COMBOS = [
    ({"Privileged Container", "Pod Using HostPath Volume"}, "Critical",
     "Privileged Container with Host Filesystem Access",
     "Privileged mode + host path access = direct container escape and host compromise.",
     "Remove privileged mode. Replace hostPath with PersistentVolumes."),
    ({"Privileged Container", "Pod Using Host Network"}, "Critical",
     "Privileged Container with Host Network Access",
     "Privileged + host network = full control of node network stack, traffic sniffing, NP bypass.",
     "Disable privileged mode. Remove hostNetwork."),
    ({"Dangerous Capabilities Added", "Pod Using HostPath Volume"}, "Critical",
     "SYS_ADMIN Capability with Host Filesystem Access",
     "SYS_ADMIN + host path = container escape via mount manipulation.",
     "Remove SYS_ADMIN capability. Replace hostPath with PersistentVolumes."),
    ({"Dangerous Capabilities Added", "Pod Using Host Network"}, "Critical",
     "SYS_ADMIN Capability with Host Network Access",
     "SYS_ADMIN + host network = full node compromise via privilege and network fronts.",
     "Remove SYS_ADMIN capability. Remove hostNetwork."),
    ({"Pod Using HostPath Volume", ROOT_CANONICAL}, "High",
     "Root Container with Host Filesystem Access",
     "Root + hostPath = direct manipulation of host files, credential theft, container escape.",
     "Run as non-root. Remove or restrict hostPath to read-only."),
    ({"Pod Using Host Network", ROOT_CANONICAL}, "High",
     "Root Container with Host Network Access",
     "Root + host network = node network manipulation, traffic sniffing, NP bypass.",
     "Run as non-root. Remove hostNetwork."),
    ({"Pod Using Host PID Namespace", ROOT_CANONICAL}, "High",
     "Root Container with Host PID Visibility",
     "Root + host PID = interact with all host processes, information disclosure.",
     "Run as non-root. Remove hostPID."),
    ({"Pod IRSA Role Potentially Overly Permissive", ROOT_CANONICAL}, "High",
     "Root Container with Overprivileged AWS Role",
     "Root + broad IRSA role = trivial pivot from app compromise to AWS resource abuse.",
     "Run as non-root. Restrict IRSA role to least privilege."),
    ({"Pod Using Host Network", "Pod Using Host PID Namespace"}, "High",
     "Multiple Host Namespace Breakouts",
     "Host network + host PID = significantly reduced container isolation.",
     "Remove host namespace usage."),
    ({"Pod Using Host Network", "Pod Using HostPath Volume"}, "High",
     "Host Network with Host Filesystem Access",
     "Reduced isolation on both network and filesystem fronts.",
     "Remove hostPath. If hostNetwork needed, ensure read-only mounts and non-root."),
    ({"Pod Using Host PID Namespace", "Pod Using HostPath Volume"}, "High",
     "Host PID Visibility with Host Filesystem Access",
     "Host PID + host filesystem = information disclosure and container escape paths.",
     "Remove hostPath. Remove hostPID."),
    ({"Pod Using HostPath Volume", "Container Allows Privilege Escalation"}, "High",
     "Host Filesystem Access with Privilege Escalation",
     "HostPath + privilege escalation = escalate then manipulate host resources.",
     "Set allowPrivilegeEscalation: false. Remove hostPath."),
    ({"Container Allows Privilege Escalation", ROOT_CANONICAL}, "Medium",
     "Root Container with Privilege Escalation Allowed",
     "Root + privilege escalation = SUID/kernel exploit enablement.",
     "Set allowPrivilegeEscalation: false. Run as non-root."),
    ({"Container Root Filesystem Writable", ROOT_CANONICAL}, "Medium",
     "Root Container with Writable Filesystem",
     "Root + writable filesystem = persistence, tooling install, behavior modification.",
     "Set readOnlyRootFilesystem: true. Run as non-root."),
    ({"Privileged Container", "Pod Using Host IPC Namespace"}, "Critical",
     "Privileged Container with Host IPC Access",
     "Privileged + host IPC = direct manipulation of host shared memory, node compromise.",
     "Remove privileged mode. Remove hostIPC."),
    ({"Dangerous Capabilities Added", "Pod Using Host IPC Namespace"}, "Critical",
     "SYS_ADMIN Capability with Host IPC Access",
     "SYS_ADMIN + host IPC = kernel-level shared memory manipulation.",
     "Remove SYS_ADMIN. Remove hostIPC."),
    ({"Pod Using Host IPC Namespace", ROOT_CANONICAL}, "High",
     "Root Container with Host IPC Access",
     "Root + host IPC = attach to host shared memory segments as root.",
     "Run as non-root. Remove hostIPC."),
    ({"Pod Using Host IPC Namespace", "Pod Using Host PID Namespace"}, "High",
     "Host IPC with Host PID Visibility",
     "Host IPC + host PID = see all processes + manipulate their shared memory.",
     "Remove hostIPC and hostPID."),
    ({"Pod Using Host IPC Namespace", "Pod Using HostPath Volume"}, "High",
     "Host IPC with Host Filesystem Access",
     "Host IPC + hostPath = read host files + exfil via shared memory channels.",
     "Remove hostIPC. Replace hostPath with PersistentVolumes."),
    ({"Pod Using Host IPC Namespace", "Pod Using Host Network"}, "High",
     "Host IPC with Host Network Access",
     "Host IPC + host network = interact with host on all channels, collapsing isolation.",
     "Remove hostIPC and hostNetwork."),
]

# ---------------------------------------------------------------------------
# Cross-scope combinations (infrastructure + workload)
# ---------------------------------------------------------------------------
# (infra_finding_type, pod_finding_type, severity, title, impact, remediation)
_INFRA_FINDING_TYPES = {
    "IMDSv2 Not Enforced",
    "Node IAM Role Has Overly Broad Policy",
    "EKS Public API Endpoint Open to Internet",
    "EKS Secrets Encryption Not Enabled",
    "Nodegroup SSH Access Enabled Without Source Restriction",
    "ClusterRoleBinding Grants High Privileges",
}
CROSS_SCOPE_COMBOS = [
    ("IMDSv2 Not Enforced", "Pod Using Host Network", "Critical",
     "IMDS Credential Theft via Host Network",
     "Host network + IMDSv1 = steal node IAM creds via metadata service (SCARLETEEL).",
     "Enforce IMDSv2 (HttpTokens: required, hop limit: 1). Remove hostNetwork."),
    ("IMDSv2 Not Enforced", "Privileged Container", "Critical",
     "IMDS Credential Theft via Privileged Container",
     "Privileged + IMDSv1 = network namespace manipulation to reach IMDS, steal node IAM creds.",
     "Enforce IMDSv2. Remove privileged mode."),
    ("Node IAM Role Has Overly Broad Policy", "Privileged Container", "Critical",
     "Overprivileged Node Role with Container Escape",
     "Privileged container escape + broad node IAM role = AWS account compromise.",
     "Restrict node IAM role. Remove privileged mode."),
    ("Node IAM Role Has Overly Broad Policy", "Pod Using HostPath Volume", "High",
     "Overprivileged Node Role with Host Filesystem Access",
     "Read node IAM creds from filesystem + broad role = cloud resource abuse.",
     "Restrict node IAM role. Replace hostPath with PersistentVolumes."),
    ("Node IAM Role Has Overly Broad Policy", "Pod Using Host Network", "High",
     "Overprivileged Node Role with Host Network Access",
     "Host network + IMDS + broad node role = AWS pivot via metadata credential theft.",
     "Restrict node IAM role. Remove hostNetwork. Enforce IMDSv2."),
    ("EKS Public API Endpoint Open to Internet", "ClusterRoleBinding Grants High Privileges", "High",
     "Public API Endpoint with Cluster Admin Privileges",
     "Internet-exposed API + cluster-admin RBAC = full cluster control from anywhere.",
     "Restrict API to private access or allowlisted CIDRs. Minimize cluster-admin bindings."),
    ("EKS Secrets Encryption Not Enabled", "Secret Contains Sensitive-Looking Keys", "Medium",
     "Unencrypted Secrets with Sensitive Data",
     "Credentials stored plaintext in etcd = vulnerable to snapshot/backup theft.",
     "Enable KMS secrets encryption. Rotate exposed values."),
    ("Nodegroup SSH Access Enabled Without Source Restriction", "Node IAM Role Has Overly Broad Policy", "Critical",
     "Unrestricted SSH with Overprivileged Node Role",
     "Unrestricted SSH + broad IAM role = SSH compromise grants broad AWS permissions.",
     "Restrict SSH to specific CIDRs or disable. Restrict node IAM role. Use SSM instead."),
]

# ---------------------------------------------------------------------------
# Category descriptions — what each area covers and why it matters
# ---------------------------------------------------------------------------
CATEGORY_DESCRIPTIONS = {
    "EKS Cluster Configuration": (
        "The EKS control plane configuration was reviewed for API server endpoint "
        "exposure, control plane audit logging, and secrets-at-rest encryption. "
        "Misconfigurations at this level affect the entire cluster's security posture."
    ),
    "EKS Nodegroup Security": (
        "Worker node configurations were assessed including SSH access controls, "
        "Instance Metadata Service (IMDS) enforcement, and node IAM role permissions. "
        "Weaknesses here can enable lateral movement from compromised pods to the "
        "underlying EC2 infrastructure and AWS account."
    ),
    "IAM Role Analysis": (
        "IAM roles associated with the cluster, nodegroups, and workloads (via IRSA) "
        "were reviewed for overly broad permissions and trust policy weaknesses. "
        "Overpermissive IAM roles expand the blast radius of any container compromise "
        "into the broader AWS environment."
    ),
    "Security Groups": (
        "Security groups attached to cluster resources and nodegroups were examined "
        "for overly permissive inbound and outbound rules."
    ),
    "GuardDuty": (
        "Amazon GuardDuty EKS audit log monitoring and runtime monitoring status "
        "were checked. GuardDuty provides threat detection for suspicious Kubernetes "
        "API activity and container-level runtime threats."
    ),
    "Namespace Governance": (
        "Each namespace was checked for Pod Security Admission (PSA) enforcement "
        "labels, ResourceQuota objects, and LimitRange definitions. These controls "
        "establish the security baseline and resource boundaries within each namespace."
    ),
    "Pod & Container Security": (
        "Pod specifications were analyzed for host namespace usage (network, PID, IPC), "
        "hostPath volumes, privileged containers, root execution, privilege escalation "
        "settings, dangerous Linux capabilities, seccomp profiles, filesystem "
        "writability, resource limits, and image provenance. These settings directly "
        "control the isolation boundary between containers and the host node."
    ),
    "Service Accounts": (
        "Kubernetes service accounts were reviewed for IAM role associations (IRSA), "
        "token automounting configuration, and usage of default service accounts. "
        "Service account tokens provide API access credentials that can be abused "
        "if not properly scoped."
    ),
    "RBAC Configuration": (
        "Roles, ClusterRoles, RoleBindings, and ClusterRoleBindings were analyzed for "
        "cluster-admin bindings, wildcard permissions, sensitive verb/resource "
        "combinations, and bindings to default or system-level subjects. RBAC "
        "misconfigurations can grant attackers full cluster control."
    ),
    "Network Policies": (
        "NetworkPolicy coverage was evaluated per namespace, and existing policies "
        "were reviewed for overly permissive ingress and egress rules. Without "
        "NetworkPolicies, all pod-to-pod traffic is permitted by default."
    ),
    "Network Exposure": (
        "Services exposed via LoadBalancer, Ingress TLS configuration, and wildcard "
        "host rules were assessed. These findings identify the cluster's external "
        "attack surface."
    ),
    "Secrets & ConfigMaps": (
        "Kubernetes Secrets and ConfigMaps were inspected for sensitive-looking key "
        "names (passwords, tokens, API keys). ConfigMaps with sensitive data are a "
        "common misconfiguration since they lack the access controls of Secrets."
    ),
}


def get_category(check_id):
    """Derive a human-readable category from a check_id string."""
    if not check_id:
        return "Other"
    parts = check_id.split(".")
    if len(parts) < 2:
        return check_id
    prefix = parts[0] + "." + parts[1]
    return CATEGORY_MAP.get(prefix, prefix)


def parse_asset_type(tags_str):
    """Extract asset type from the Tags column."""
    if not tags_str:
        return "Unknown"
    parts = [t.strip() for t in tags_str.split(",")]
    return parts[-1] if parts else "Unknown"


def read_findings(csv_path):
    """Read the EKS Scout CSV and return a list of finding dicts."""
    findings = []
    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise SystemExit(f"Error: CSV file '{csv_path}' is empty or has no header.")

        # Support both v1 and v2 column names
        col_map = {}
        for col in reader.fieldnames:
            col_map[col] = col

        for row in reader:
            finding_name = row.get("Finding Name", "")
            severity = row.get("Severity", "Informational")
            description = row.get("Description", "")
            recommendation = row.get("Recommendation", "")
            reference = row.get("Vulnerability References", "")
            affected = row.get("Affected Components", "")
            tags = row.get("Tags", "")

            # Derive check_id from reference + tags for categorization
            check_id = _infer_check_id(finding_name, tags)

            findings.append({
                "type": finding_name,
                "severity": severity,
                "description": description,
                "recommendation": recommendation,
                "reference": reference,
                "affected": affected,
                "tags": tags,
                "asset_type": parse_asset_type(tags),
                "check_id": check_id,
                "category": get_category(check_id),
            })

    return findings


def _infer_check_id(finding_name, tags):
    """Infer a check_id from finding name and tags for categorization."""
    asset = parse_asset_type(tags)

    # AWS-level findings
    if asset in ("EKS Cluster", "EKS Cluster IAM Role"):
        return "aws.cluster"
    if asset in ("EKS Nodegroup", "EKS Nodegroup IAM Role"):
        return "aws.nodegroups"
    if asset == "IAM Role":
        return "aws.iam"
    if asset == "Security Group":
        return "aws.sg"

    # K8s findings by asset type
    if asset == "Namespace":
        if "PSA" in finding_name:
            return "k8s.psa"
        if "Network Policy" in finding_name:
            return "k8s.netpol"
        return "k8s.namespaces"
    if asset in ("Container", "Pod"):
        return "k8s.pods"
    if asset == "ServiceAccount":
        return "k8s.serviceaccounts"
    if asset in ("ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"):
        return "k8s.rbac"
    if asset == "NetworkPolicy":
        return "k8s.netpol"
    if asset in ("Service", "Ingress"):
        return "k8s.services"
    if asset in ("Secret", "ConfigMap"):
        return "k8s.secrets"

    return "other"


def _normalize_type(ftype):
    """Normalize root-related finding types to a canonical form."""
    if ftype in ROOT_FINDING_ALIASES:
        return ROOT_CANONICAL
    return ftype


def _extract_workload_key(affected):
    """Derive a workload key from the Affected Components column."""
    if "/" in affected:
        parts = affected.split("/", 1)
        return parts[0] + "/" + parts[1].split("/")[0]
    return affected


def detect_combos(findings):
    """Detect high-risk same-workload and cross-scope attack chains.

    Returns a list of combo dicts with title, severity, impact, etc.
    """
    combos = []

    # --- Same-workload combos ---
    # Group findings by workload key
    by_workload = defaultdict(set)
    by_workload_findings = defaultdict(list)
    for f in findings:
        wk = _extract_workload_key(f["affected"])
        normalized = _normalize_type(f["type"])
        by_workload[wk].add(normalized)
        by_workload_findings[wk].append(f)

    for wk, types in by_workload.items():
        for required, sev, title, impact, remediation in SAME_WORKLOAD_COMBOS:
            if required.issubset(types):
                combos.append({
                    "workload": wk,
                    "severity": sev,
                    "title": title,
                    "impact": impact,
                    "remediation": remediation,
                    "matched_types": required,
                    "scope": "same-workload",
                })

    # --- Cross-scope combos ---
    infra_types = set()
    workload_types_by_wk = defaultdict(set)
    for f in findings:
        if f["type"] in _INFRA_FINDING_TYPES:
            infra_types.add(f["type"])
        else:
            wk = _extract_workload_key(f["affected"])
            normalized = _normalize_type(f["type"])
            workload_types_by_wk[wk].add(normalized)

    for infra_type, pod_type, sev, title, impact, remediation in CROSS_SCOPE_COMBOS:
        if infra_type not in infra_types:
            continue
        # Infra+infra combo
        if pod_type in _INFRA_FINDING_TYPES:
            if pod_type in infra_types:
                combos.append({
                    "workload": "(infrastructure)",
                    "severity": sev,
                    "title": title,
                    "impact": impact,
                    "remediation": remediation,
                    "matched_types": {infra_type, pod_type},
                    "scope": "cross-scope",
                })
        else:
            # Infra + workload combo — report per affected workload
            for wk, wk_types in workload_types_by_wk.items():
                if pod_type in wk_types:
                    combos.append({
                        "workload": wk,
                        "severity": sev,
                        "title": title,
                        "impact": impact,
                        "remediation": remediation,
                        "matched_types": {infra_type, pod_type},
                        "scope": "cross-scope",
                    })

    # Sort by severity then workload
    combos.sort(key=lambda c: (SEV_ORDER.get(c["severity"], 99), c["workload"]))
    return combos


def generate_report(findings, cluster_name, csv_path):
    """Generate the full Markdown report."""
    lines = []

    # --- Executive Summary ---
    sev_counts = Counter(f["severity"] for f in findings)
    total = len(findings)
    namespaces = set()
    for f in findings:
        affected = f["affected"]
        if "/" in affected:
            ns = affected.split("/")[0]
            if ns and ns != "(cluster)":
                namespaces.add(ns)

    categories_found = set(f["category"] for f in findings)

    lines.append("# EKS Security Configuration Review — Findings Report")
    lines.append("")
    if cluster_name:
        lines.append(f"**Cluster:** {cluster_name}  ")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append(f"**Source:** `{csv_path}`  ")
    lines.append(f"**Tool:** EKS Scout v2 by Ben Stevens")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"EKS Scout identified **{total} findings** across "
        f"**{len(namespaces)} namespaces** and cluster-level resources, "
        f"spanning **{len(categories_found)} assessment categories**."
    )
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|------:|")
    for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
        count = sev_counts.get(sev, 0)
        if count > 0:
            lines.append(f"| {sev} | {count} |")
    lines.append(f"| **Total** | **{total}** |")
    lines.append("")

    # Critical/High callout
    crit = sev_counts.get("Critical", 0)
    high = sev_counts.get("High", 0)
    if crit > 0 or high > 0:
        lines.append(
            f"> **{crit + high} findings rated Critical or High** require "
            f"priority attention. These represent configurations that could "
            f"directly enable container escape, credential theft, or "
            f"unauthorized access to AWS resources."
        )
        lines.append("")

    # --- High-Risk Attack Chains ---
    combos = detect_combos(findings)
    if combos:
        combo_sev = Counter(c["severity"] for c in combos)
        workloads_affected = len({c["workload"] for c in combos})
        same_wl = [c for c in combos if c["scope"] == "same-workload"]
        cross_sc = [c for c in combos if c["scope"] == "cross-scope"]

        lines.append("## High-Risk Attack Chains")
        lines.append("")
        lines.append(
            f"Beyond individual findings, **{len(combos)} high-risk attack chains** "
            f"were identified across **{workloads_affected} workloads** where multiple "
            f"findings combine to create risks greater than any single finding alone."
        )
        lines.append("")
        if combo_sev.get("Critical", 0) > 0:
            lines.append(
                f"> **{combo_sev['Critical']} Critical attack chains** represent "
                f"direct paths to node compromise, cloud credential theft, or AWS "
                f"account takeover."
            )
            lines.append("")

        lines.append("| # | Severity | Attack Chain | Affected Workload | Impact |")
        lines.append("|--:|----------|-------------|-------------------|--------|")
        for i, c in enumerate(combos, 1):
            lines.append(
                f"| {i} | {c['severity']} | {c['title']} "
                f"| `{c['workload']}` | {c['impact']} |"
            )
        lines.append("")

        if same_wl:
            lines.append(
                f"**Same-workload chains ({len(same_wl)}):** Multiple findings on the "
                f"same pod combine to create container escape, privilege escalation, or "
                f"host compromise paths."
            )
            lines.append("")
        if cross_sc:
            lines.append(
                f"**Cross-scope chains ({len(cross_sc)}):** Cluster-level infrastructure "
                f"weaknesses combine with pod-level findings to create cloud pivot paths "
                f"(e.g., SCARLETEEL: host network + IMDSv1 = AWS credential theft)."
            )
            lines.append("")

    # --- Scope of Assessment ---
    lines.append("## Scope of Assessment")
    lines.append("")
    lines.append(
        "The following assessment areas were evaluated using passive, "
        "read-only inspection of the Kubernetes API and AWS control plane. "
        "No changes were made to the cluster during the assessment."
    )
    lines.append("")
    lines.append("| # | Category | Findings |")
    lines.append("|--:|----------|-------:|")

    cat_counts = Counter(f["category"] for f in findings)
    idx = 1
    ordered_cats = sorted(
        cat_counts.keys(),
        key=lambda c: (CATEGORY_ORDER.index(c) if c in CATEGORY_ORDER else 99, c),
    )
    for cat in ordered_cats:
        lines.append(f"| {idx} | [{cat}](#{_anchor(cat)}) | {cat_counts[cat]} |")
        idx += 1
    lines.append("")

    # --- Detailed Findings by Category ---
    lines.append("---")
    lines.append("")
    lines.append("## Detailed Findings by Category")
    lines.append("")

    # Group findings by category
    by_category = defaultdict(list)
    for f in findings:
        by_category[f["category"]].append(f)

    for cat in ordered_cats:
        cat_findings = by_category[cat]
        lines.append(f"### <a name=\"{_anchor(cat)}\"></a>{cat}")
        lines.append("")

        # Category description
        desc = CATEGORY_DESCRIPTIONS.get(cat, "")
        if desc:
            lines.append(f"*{desc}*")
            lines.append("")

        # Stats for this category
        cat_sev = Counter(f["severity"] for f in cat_findings)
        sev_parts = []
        for s in ["Critical", "High", "Medium", "Low", "Informational"]:
            c = cat_sev.get(s, 0)
            if c > 0:
                sev_parts.append(f"{c} {s}")
        lines.append(f"**{len(cat_findings)} findings** — {', '.join(sev_parts)}")
        lines.append("")

        # Deduplicate: group by finding type, collect affected resources
        by_type = defaultdict(list)
        for f in cat_findings:
            by_type[f["type"]].append(f)

        # Sort finding types by worst severity
        sorted_types = sorted(
            by_type.keys(),
            key=lambda t: min(SEV_ORDER.get(f["severity"], 99) for f in by_type[t]),
        )

        for ftype in sorted_types:
            instances = by_type[ftype]
            worst_sev = min(instances, key=lambda f: SEV_ORDER.get(f["severity"], 99))["severity"]
            count = len(instances)

            lines.append(f"#### {ftype}")
            lines.append("")
            lines.append(f"**Severity:** {worst_sev} | **Instances:** {count}")
            lines.append("")

            # Use first instance for description/recommendation
            first = instances[0]
            # Clean up description — remove instance-specific details for the general description
            general_desc = _generalize_description(first["description"], first["type"])
            lines.append(f"**Description:** {general_desc}")
            lines.append("")
            if first["recommendation"]:
                rec = first["recommendation"]
                lines.append(f"**Recommendation:** {rec}")
                lines.append("")
            if first["reference"] and first["reference"] != "N/A":
                lines.append(f"**Reference:** {first['reference']}")
                lines.append("")

            # Affected resources table
            lines.append("**Affected Resources:**")
            lines.append("")
            if count <= 20:
                lines.append("| Resource | Severity |")
                lines.append("|----------|----------|")
                for inst in sorted(instances, key=lambda i: SEV_ORDER.get(i["severity"], 99)):
                    lines.append(f"| `{inst['affected']}` | {inst['severity']} |")
            else:
                # Summarize for large counts
                lines.append(f"*{count} instances across multiple resources. "
                             f"See CSV export for the full list.*")
                # Show first 10
                lines.append("")
                lines.append("| Resource (sample) | Severity |")
                lines.append("|-------------------|----------|")
                for inst in sorted(instances, key=lambda i: SEV_ORDER.get(i["severity"], 99))[:10]:
                    lines.append(f"| `{inst['affected']}` | {inst['severity']} |")
                lines.append(f"| *...and {count - 10} more* | |")

            lines.append("")

        lines.append("---")
        lines.append("")

    # --- Appendix: Assessment Categories Explained ---
    lines.append("## Appendix: Assessment Categories")
    lines.append("")
    lines.append(
        "This section provides a reference of all assessment areas covered by "
        "EKS Scout, including areas where no findings were identified."
    )
    lines.append("")

    for cat in CATEGORY_ORDER:
        desc = CATEGORY_DESCRIPTIONS.get(cat, "")
        found = cat_counts.get(cat, 0)
        status = f"{found} findings" if found > 0 else "No findings"
        lines.append(f"**{cat}** — {status}")
        if desc:
            lines.append(f": {desc}")
        lines.append("")

    # --- Footer ---
    lines.append("---")
    lines.append("")
    lines.append(
        "*This report was generated from EKS Scout v2 CSV output. "
        "Findings should be validated in the context of the target environment. "
        "Use the companion Finding Validation Guide for manual verification commands.*"
    )
    lines.append("")

    return "\n".join(lines)


def _anchor(text):
    """Generate a markdown anchor from a heading."""
    return re.sub(r"[^a-z0-9-]", "", text.lower().replace(" ", "-").replace("&", "and"))


def _generalize_description(description, finding_type):
    """Remove instance-specific details to produce a general finding description."""
    # Strip specific resource names from the description for the general write-up
    desc = description

    # Remove "Container 'xxx' in Deployment 'yyy' (N pods) (namespace 'zzz')" patterns
    desc = re.sub(
        r"Container '[^']+' in \w+ '[^']+' \(\d+ pods?\) \(namespace '[^']+'\) ",
        "Containers ",
        desc,
    )
    # Remove "DaemonSet 'xxx' (N pods) in namespace 'yyy'" patterns
    desc = re.sub(
        r"(Deployment|DaemonSet|StatefulSet|CronJob|Job) '[^']+' \(\d+ pods?\) in namespace '[^']+' ",
        "Workloads ",
        desc,
    )
    # Remove "Namespace 'xxx'" patterns
    desc = re.sub(r"Namespace '[^']+' ", "Namespaces ", desc)
    # Remove cluster name references
    desc = re.sub(r"(EKS cluster|Cluster) '[^']+' ", "The EKS cluster ", desc)
    # Remove nodegroup name references
    desc = re.sub(r"Nodegroup '[^']+' ", "Nodegroups ", desc)
    # Remove SA name references
    desc = re.sub(
        r"(ServiceAccount|service account) '[^']+' in namespace '[^']+' ",
        "Service accounts ",
        desc,
    )
    # Remove IAM role specific names
    desc = re.sub(r"IAM role '[^']+' \([^)]+\) ", "IAM roles ", desc)
    # Remove ClusterRoleBinding names
    desc = re.sub(r"ClusterRoleBinding '[^']+' ", "ClusterRoleBindings ", desc)
    # Remove specific policy names
    desc = re.sub(r"Policy '[^']+' \(namespace '[^']+'\) ", "Policies ", desc)
    # Remove Secret/ConfigMap names
    desc = re.sub(r"(Secret|ConfigMap) '[^']+' in namespace '[^']+' ", r"\1s ", desc)

    # Clean up double spaces
    desc = re.sub(r"  +", " ", desc).strip()

    return desc


def main():
    parser = argparse.ArgumentParser(
        description=(
            "EKS Scout — Generate a professional client report from CSV findings.\n\n"
            "Reads EKS Scout v2 CSV output and produces a structured Markdown report\n"
            "suitable for inclusion in penetration test or security review deliverables."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Path to the EKS Scout CSV findings file.",
    )
    parser.add_argument(
        "-o", "--output", required=True,
        help="Path for the output Markdown report.",
    )
    parser.add_argument(
        "--cluster", default="",
        help="Cluster name to include in the report header.",
    )

    args = parser.parse_args()

    print(f"Reading findings from: {args.input}")
    findings = read_findings(args.input)
    print(f"Loaded {len(findings)} findings.")

    report = generate_report(findings, args.cluster, args.input)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)

    sev_counts = Counter(f["severity"] for f in findings)
    combos = detect_combos(findings)
    print(f"Report written to: {args.output}")
    print(f"  {sev_counts.get('Critical', 0)} Critical, "
          f"{sev_counts.get('High', 0)} High, "
          f"{sev_counts.get('Medium', 0)} Medium, "
          f"{sev_counts.get('Low', 0)} Low, "
          f"{sev_counts.get('Informational', 0)} Informational")
    if combos:
        print(f"  {len(combos)} attack chains detected "
              f"({len([c for c in combos if c['scope'] == 'same-workload'])} same-workload, "
              f"{len([c for c in combos if c['scope'] == 'cross-scope'])} cross-scope)")


if __name__ == "__main__":
    main()
