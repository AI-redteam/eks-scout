"""Kubernetes service account security checks."""
import logging

from eks_scout.config import (
    get_config, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    SEVERITY_LOW, SEVERITY_INFO
)
from eks_scout.core.findings import add_finding

CHECK_NAME = "k8s.serviceaccounts"


def run(findings, resources, config=None):
    """Run service account security checks.

    Args:
        findings: List to append findings to.
        resources: Dict containing 'service_accounts'.
        config: Optional Config instance (uses global if not provided).
    """
    if config is None:
        config = get_config()

    service_accounts = resources.get('service_accounts', [])

    logging.info("Analyzing Service Accounts...")
    for sa in service_accounts:
        metadata = sa.get('metadata', {})
        ns = metadata.get('namespace')
        name = metadata.get('name')
        annotations = metadata.get('annotations', {})

        # IRSA Check
        iam_role_arn = annotations.get('eks.amazonaws.com/role-arn')
        if iam_role_arn:
            if "admin" in iam_role_arn.lower() or "*" in iam_role_arn:
                add_finding(findings, SEVERITY_HIGH, "Service Account IRSA Role Potentially Overly Permissive",
                            f"ServiceAccount '{name}' in namespace '{ns}' uses IAM role '{iam_role_arn}' which might have excessive permissions (contains 'admin' or '*').",
                            "Review and apply least privilege to the IAM role associated via IRSA.",
                            "CIS 5.1.5", ns, name, "ServiceAccount",
                            check_id="k8s.serviceaccounts.irsa-overly-permissive")
            add_finding(findings, SEVERITY_INFO, "Service Account Using IRSA",
                        f"ServiceAccount '{name}' in namespace '{ns}' uses IAM role via IRSA: {iam_role_arn}",
                        "Ensure the associated IAM role follows the principle of least privilege.",
                        "AWS Best Practice", ns, name, "ServiceAccount",
                        check_id="k8s.serviceaccounts.irsa")

        # Token Automounting
        automount_token = sa.get('automountServiceAccountToken')
        if automount_token is True or automount_token is None:
            if name != "default":
                add_finding(findings, SEVERITY_MEDIUM, "Service Account Token Automount Enabled",
                            f"ServiceAccount '{name}' in namespace '{ns}' has automountServiceAccountToken enabled (or default). Tokens might be mounted unnecessarily in pods using this SA.",
                            "Set automountServiceAccountToken: false on the ServiceAccount unless pods using it specifically need the token (prefer mounting projected tokens if needed).",
                            "CIS 5.1.6", ns, name, "ServiceAccount",
                            check_id="k8s.serviceaccounts.token-automount")
            else:
                add_finding(findings, SEVERITY_MEDIUM, "Default Service Account Allows Token Automount",
                            f"The 'default' ServiceAccount in namespace '{ns}' allows token automounting by default.",
                            "Explicitly set automountServiceAccountToken: false on the 'default' ServiceAccount and use dedicated SAs for pods.",
                            "CIS 5.1.6", ns, name, "ServiceAccount",
                            check_id="k8s.serviceaccounts.default-token-automount")
