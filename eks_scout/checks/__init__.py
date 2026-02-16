"""Check registry for EKS Scout security checks."""

from eks_scout.checks.aws import cluster, nodegroups, iam, security_groups
from eks_scout.checks.kubernetes import (
    namespaces, pods, serviceaccounts, rbac,
    network_policies, network_exposure, secrets_configmaps
)

# Ordered list of all checks — executed in this order during a scan.
ALL_CHECKS = [
    ("aws.cluster", cluster),
    ("aws.nodegroups", nodegroups),
    ("aws.iam", iam),
    ("aws.security_groups", security_groups),
    ("k8s.namespaces", namespaces),
    ("k8s.pods", pods),
    ("k8s.serviceaccounts", serviceaccounts),
    ("k8s.rbac", rbac),
    ("k8s.network_policies", network_policies),
    ("k8s.network_exposure", network_exposure),
    ("k8s.secrets_configmaps", secrets_configmaps),
]


def get_all_checks():
    """Returns list of (check_id, module) tuples.

    Each module has a run(findings, resources, config) function.
    """
    return ALL_CHECKS
