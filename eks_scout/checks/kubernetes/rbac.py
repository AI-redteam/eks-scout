"""Kubernetes RBAC security checks."""
import logging

from eks_scout.config import (
    get_config, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    SEVERITY_LOW, SEVERITY_INFO, SEVERITY_RANK
)
from eks_scout.core.findings import add_finding


def _max_severity(a, b):
    """Return the higher of two severity levels."""
    return a if SEVERITY_RANK.get(a, 99) <= SEVERITY_RANK.get(b, 99) else b

CHECK_NAME = "k8s.rbac"


def run(findings, resources, config=None):
    """Run RBAC security checks.

    Args:
        findings: List to append findings to.
        resources: Dict containing 'roles', 'role_bindings', 'cluster_roles', 'cluster_role_bindings'.
        config: Optional Config instance (uses global if not provided).
    """
    if config is None:
        config = get_config()

    roles = resources.get('roles', [])
    role_bindings = resources.get('role_bindings', [])
    cluster_roles = resources.get('cluster_roles', [])
    cluster_role_bindings = resources.get('cluster_role_bindings', [])

    logging.info("Analyzing RBAC (Roles, ClusterRoles, Bindings)...")

    sensitive_verbs = ["*", "create", "update", "patch", "delete", "deletecollection",
                       "impersonate", "bind", "escalate"]
    sensitive_resources = ["*", "secrets", "pods", "pods/exec", "pods/attach", "deployments",
                           "daemonsets", "statefulsets", "roles", "clusterroles", "rolebindings",
                           "clusterrolebindings", "serviceaccounts", "nodes",
                           "certificatesigningrequests"]
    highly_privileged_roles = ["cluster-admin", "admin", "edit"]

    _analyze_cluster_role_bindings(findings, cluster_role_bindings, highly_privileged_roles)
    _analyze_role_bindings(findings, role_bindings, highly_privileged_roles)
    _analyze_roles(findings, roles, cluster_roles, sensitive_verbs, sensitive_resources)


def _analyze_cluster_role_bindings(findings, cluster_role_bindings, highly_privileged_roles):
    """Analyze ClusterRoleBindings for high-privilege and sensitive subject bindings."""
    for crb in cluster_role_bindings:
        metadata = crb.get('metadata', {})
        crb_name = metadata.get('name')
        role_ref = crb.get('roleRef', {})
        role_name = role_ref.get('name')
        subjects = crb.get('subjects') or []

        if role_name in highly_privileged_roles:
            for subject in subjects:
                subject_name = subject.get('name')
                subject_kind = subject.get('kind')
                subject_ns = subject.get('namespace', '(cluster)')
                full_subject_name = f"{subject_kind}:{subject_name}"
                if subject_kind == "ServiceAccount":
                    full_subject_name = f"{subject_kind}:{subject_ns}/{subject_name}"

                add_finding(findings, SEVERITY_HIGH, "ClusterRoleBinding Grants High Privileges",
                            f"ClusterRoleBinding '{crb_name}' grants highly privileged cluster role '{role_name}' to '{full_subject_name}'. Granting cluster-wide admin/edit rights is highly risky.",
                            "Avoid binding cluster-admin or similar roles directly. Use namespace-scoped roles (RoleBinding) or custom cluster roles with least privilege necessary.",
                            "CIS 5.1.1", '(cluster)', crb_name, "ClusterRoleBinding",
                            check_id="k8s.rbac.cluster-admin-binding")

        # Check bindings to sensitive system groups/users
        sensitive_subjects = {
            "ServiceAccount:kube-system/default",
            "Group:system:unauthenticated",
            "Group:system:authenticated",
        }
        for subject in subjects:
            subject_name = subject.get('name')
            subject_kind = subject.get('kind')
            subject_ns = subject.get('namespace', '')
            full_subject_name = f"{subject_kind}:{subject_name}"
            if subject_kind == "ServiceAccount" and subject_ns:
                full_subject_name = f"{subject_kind}:{subject_ns}/{subject_name}"

            if full_subject_name in sensitive_subjects and role_name != 'cluster-admin':
                add_finding(findings, SEVERITY_MEDIUM, "ClusterRoleBinding to Sensitive Subject",
                            f"ClusterRoleBinding '{crb_name}' grants cluster role '{role_name}' to potentially sensitive subject '{full_subject_name}'.",
                            "Review bindings to system groups and default service accounts, especially in kube-system. Ensure the granted role is appropriate and necessary.",
                            "CIS 5.1.1 / Best Practice", '(cluster)', crb_name, "ClusterRoleBinding",
                            check_id="k8s.rbac.sensitive-subject-binding")

        # Default service account bindings (any namespace)
        for subject in subjects:
            if subject.get('kind') == "ServiceAccount" and subject.get('name') == "default":
                subject_ns = subject.get('namespace', '(unknown)')
                severity = SEVERITY_HIGH if role_name in highly_privileged_roles else SEVERITY_MEDIUM
                add_finding(findings, severity, "ClusterRoleBinding Involves Default Service Account",
                            f"ClusterRoleBinding '{crb_name}' grants cluster role '{role_name}' to the 'default' ServiceAccount in namespace '{subject_ns}'. All pods without an explicit SA in that namespace inherit these cluster-wide permissions.",
                            "Avoid granting permissions to the 'default' service account. Create and use dedicated service accounts for applications with specific, minimal roles.",
                            "CIS 5.1.3", '(cluster)', crb_name, "ClusterRoleBinding",
                            check_id="k8s.rbac.default-sa-clusterrolebinding")


def _analyze_role_bindings(findings, role_bindings, highly_privileged_roles):
    """Analyze RoleBindings for high-privilege and default SA bindings."""
    for rb in role_bindings:
        metadata = rb.get('metadata', {})
        rb_name = metadata.get('name')
        ns = metadata.get('namespace')
        role_ref = rb.get('roleRef', {})
        role_kind = role_ref.get('kind')
        role_name = role_ref.get('name')
        subjects = rb.get('subjects') or []

        is_cluster_admin_binding = role_kind == "ClusterRole" and role_name == "cluster-admin"
        is_namespace_admin_binding = role_kind == "Role" and role_name in ["admin", "edit"]

        if is_cluster_admin_binding or is_namespace_admin_binding:
            severity = SEVERITY_HIGH if is_cluster_admin_binding else SEVERITY_MEDIUM
            finding_type = "RoleBinding Grants Cluster Admin" if is_cluster_admin_binding else "RoleBinding Grants High Privileges in Namespace"
            details_role_type = "cluster role 'cluster-admin'" if is_cluster_admin_binding else f"role '{role_name}'"

            for subject in subjects:
                subject_name = subject.get('name')
                subject_kind = subject.get('kind')
                add_finding(findings, severity, finding_type,
                            f"RoleBinding '{rb_name}' in namespace '{ns}' grants {details_role_type} to {subject_kind} '{subject_name}'. This provides extensive control within the namespace (or cluster if cluster-admin).",
                            "Avoid binding cluster-admin via RoleBindings. Use custom, namespace-scoped Roles with least privilege instead of the built-in admin/edit roles where possible.",
                            "CIS 5.1.1", ns, rb_name, "RoleBinding",
                            check_id="k8s.rbac.high-privilege-rolebinding")

        # Default service account bindings
        for subject in subjects:
            if subject.get('kind') == "ServiceAccount" and subject.get('name') == "default":
                add_finding(findings, SEVERITY_MEDIUM, "RoleBinding Involves Default Service Account",
                            f"RoleBinding '{rb_name}' in namespace '{ns}' grants role '{role_name}' (Kind: {role_kind}) to the 'default' ServiceAccount.",
                            "Avoid granting permissions to the 'default' service account. Create and use dedicated service accounts for applications with specific, minimal roles.",
                            "CIS 5.1.3", ns, rb_name, "RoleBinding",
                            check_id="k8s.rbac.default-sa-binding")


def _analyze_roles(findings, roles, cluster_roles, sensitive_verbs, sensitive_resources):
    """Analyze ClusterRoles and Roles for risky permissions."""
    all_roles = [('ClusterRole', r) for r in cluster_roles] + [('Role', r) for r in roles]
    for role_type, role in all_roles:
        metadata = role.get('metadata', {})
        role_name = metadata.get('name')
        ns = metadata.get('namespace', '(cluster)')
        rules = role.get('rules') or []

        is_default_system_role = role_name.startswith("system:") or role_name in [
            "cluster-admin", "admin", "edit", "view"]

        for rule_idx, rule in enumerate(rules):
            verbs = rule.get('verbs', [])
            resources = rule.get('resources', [])
            api_groups = rule.get('apiGroups', ['core'])

            has_wildcard_verb = "*" in verbs
            has_wildcard_resource = "*" in resources
            has_wildcard_group = "*" in api_groups

            rule_sensitive_verbs = [v for v in verbs if v in sensitive_verbs]
            rule_sensitive_resources = [r for r in resources if r in sensitive_resources]
            has_sensitive_combo = bool(rule_sensitive_verbs) and bool(rule_sensitive_resources)

            finding_details = []
            if has_wildcard_verb:
                finding_details.append("wildcard verb ('*')")
            if has_wildcard_resource:
                finding_details.append("wildcard resource ('*')")
            if has_wildcard_group:
                finding_details.append("wildcard apiGroup ('*')")
            if has_sensitive_combo:
                finding_details.append(
                    f"sensitive verbs ({rule_sensitive_verbs}) on sensitive resources ({rule_sensitive_resources})")

            if finding_details:
                severity = SEVERITY_LOW
                if has_wildcard_verb or has_wildcard_resource or has_wildcard_group:
                    severity = SEVERITY_MEDIUM
                if role_type == 'ClusterRole':
                    severity = _max_severity(severity, SEVERITY_MEDIUM)
                if any(v in ["impersonate", "bind", "escalate"] for v in verbs) or \
                   (any(v in ["create", "patch", "update"] for v in verbs) and "pods/exec" in resources):
                    severity = _max_severity(severity, SEVERITY_HIGH)

                is_extremely_permissive = has_wildcard_verb and has_wildcard_resource and has_wildcard_group
                if not is_default_system_role or is_extremely_permissive:
                    details_str = f"{role_type} '{role_name}' (namespace: {ns}) contains rule {rule_idx+1} with potentially risky permissions: {', '.join(finding_details)}."
                    add_finding(findings, severity, "Role Contains Risky Permissions",
                                details_str,
                                f"Review the permissions granted by {role_type} '{role_name}', particularly rule {rule_idx+1}. Apply the principle of least privilege, avoiding wildcards and overly broad sensitive permissions.",
                                "CIS 5.1.2", ns, role_name, role_type,
                                check_id="k8s.rbac.risky-permissions")
