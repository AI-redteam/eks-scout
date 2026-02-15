"""Kubernetes namespace security checks (PSA, ResourceQuotas, LimitRanges)."""
import logging

from eks_scout.config import (
    get_config, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    SEVERITY_LOW, SEVERITY_INFO
)
from eks_scout.core.findings import add_finding

CHECK_NAME = "k8s.namespaces"


def run(findings, resources, config=None):
    """Run namespace security checks.

    Args:
        findings: List to append findings to.
        resources: Dict containing 'namespaces', 'resource_quotas', 'limit_ranges'.
        config: Optional Config instance (uses global if not provided).
    """
    if config is None:
        config = get_config()

    namespaces = resources.get('namespaces', [])
    resource_quotas = resources.get('resource_quotas', [])
    limit_ranges = resources.get('limit_ranges', [])

    logging.info("Analyzing Namespaces (including ResourceQuotas, LimitRanges)...")
    system_namespaces = set(config.get_setting('system_namespaces',
                                                ['kube-system', 'kube-public', 'kube-node-lease']))

    # Build lookup maps
    quotas_by_ns = {}
    for rq in resource_quotas:
        ns = rq.get('metadata', {}).get('namespace')
        if ns:
            quotas_by_ns[ns] = quotas_by_ns.get(ns, 0) + 1

    limits_by_ns = {}
    for lr in limit_ranges:
        ns = lr.get('metadata', {}).get('namespace')
        if ns:
            limits_by_ns[ns] = limits_by_ns.get(ns, 0) + 1

    for ns_item in namespaces:
        metadata = ns_item.get('metadata', {})
        ns_name = metadata.get('name')
        labels = metadata.get('labels', {})

        if ns_name in system_namespaces:
            continue

        # ResourceQuota Check
        if ns_name not in quotas_by_ns:
            add_finding(findings, SEVERITY_LOW, "Namespace Lacks ResourceQuota",
                        f"Namespace '{ns_name}' does not have any ResourceQuota objects defined. This can lead to resource contention issues or potential DoS if workloads consume excessive resources.",
                        "Define appropriate ResourceQuotas for the namespace to limit the total amount of CPU, memory, storage, and object counts that can be consumed.",
                        "Best Practice / Resource Management", ns_name, ns_name, "Namespace",
                        check_id="k8s.namespaces.no-resource-quota")

        # LimitRange Check
        if ns_name not in limits_by_ns:
            add_finding(findings, SEVERITY_LOW, "Namespace Lacks LimitRange",
                        f"Namespace '{ns_name}' does not have any LimitRange objects defined. This means default resource requests/limits are not enforced for containers, potentially leading to resource exhaustion or scheduling issues.",
                        "Define a LimitRange for the namespace to set default CPU/memory requests and limits for containers, and potentially enforce min/max values.",
                        "Best Practice / Resource Management", ns_name, ns_name, "Namespace",
                        check_id="k8s.namespaces.no-limit-range")

        # PSA Check
        psa_enforce_label = labels.get('pod-security.kubernetes.io/enforce')
        expected_level = config.get_setting('psa_expected_level', 'restricted')
        if not psa_enforce_label:
            add_finding(findings, SEVERITY_MEDIUM, "PSA Label Missing",
                        f"Namespace '{ns_name}' lacks the 'pod-security.kubernetes.io/enforce' label.",
                        f"Apply Pod Security Admission labels to namespaces, enforcing at least the '{expected_level}' standard.",
                        "CIS 1.5.1 / K8s Docs", ns_name, ns_name, "Namespace",
                        check_id="k8s.namespaces.psa-missing")
        elif psa_enforce_label not in ['baseline', 'restricted']:
            add_finding(findings, SEVERITY_MEDIUM, "PSA Label Too Permissive",
                        f"Namespace '{ns_name}' has PSA enforce level '{psa_enforce_label}'. Expected '{expected_level}' or 'baseline'.",
                        "Ensure PSA enforce level is set to 'baseline' or preferably 'restricted'.",
                        "CIS 1.5.1 / K8s Docs", ns_name, ns_name, "Namespace",
                        check_id="k8s.namespaces.psa-permissive")
