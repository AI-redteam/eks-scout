"""Kubernetes network policy security checks."""
import logging

from eks_scout.config import (
    get_config, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    SEVERITY_LOW, SEVERITY_INFO
)
from eks_scout.core.findings import add_finding

CHECK_NAME = "k8s.network_policies"


def run(findings, resources, config=None):
    """Run network policy security checks.

    Args:
        findings: List to append findings to.
        resources: Dict containing 'network_policies_by_ns', 'namespaces'.
        config: Optional Config instance (uses global if not provided).
    """
    if config is None:
        config = get_config()

    network_policies_by_ns = resources.get('network_policies_by_ns', {})
    all_namespaces = resources.get('namespaces', [])

    logging.info("Analyzing Network Policies...")
    namespaces_with_policies = set(network_policies_by_ns.keys())
    all_ns_names = {ns.get('metadata', {}).get('name') for ns in all_namespaces}
    system_namespaces = set(config.get_setting('system_namespaces',
                                                ['kube-system', 'kube-public', 'kube-node-lease']))

    # Namespaces without any network policies
    for ns_name in all_ns_names:
        if ns_name not in namespaces_with_policies and ns_name not in system_namespaces:
            add_finding(findings, SEVERITY_MEDIUM, "Namespace Lacks Network Policy",
                        f"Namespace '{ns_name}' has no NetworkPolicy defined. By default, all pods within the namespace can communicate with each other, and potentially with pods in other namespaces or external services, violating the principle of least privilege.",
                        "Implement NetworkPolicies to restrict pod-to-pod communication. Start with a default deny policy for the namespace and explicitly allow required ingress/egress traffic between specific pods or namespaces.",
                        "CIS 5.3.2", ns_name, ns_name, "Namespace",
                        check_id="k8s.network_policies.no-policy")

    # Analyze existing policies
    for ns, policies in network_policies_by_ns.items():
        for policy in policies:
            metadata = policy.get('metadata', {})
            policy_name = metadata.get('name')
            spec = policy.get('spec', {})

            ingress_rules = spec.get('ingress', [])
            for rule_idx, rule in enumerate(ingress_rules):
                from_rules = rule.get('from')

                # No 'from' field or empty list = allow all sources
                if from_rules is None or from_rules == []:
                    details = f"Policy '{policy_name}' (namespace '{ns}') ingress rule #{rule_idx+1} allows traffic from ALL sources (no 'from' clause)."
                    add_finding(findings, SEVERITY_MEDIUM, "Network Policy Allows All Ingress Sources", details,
                                "Specify podSelectors, namespaceSelectors, or restrictive ipBlocks in ingress rules to limit allowed sources based on least privilege.",
                                "CIS 5.3.2", ns, policy_name, "NetworkPolicy",
                                check_id="k8s.network_policies.ingress-allow-all")
                    continue

                for from_rule_idx, from_rule in enumerate(from_rules):
                    pod_selector_all = from_rule.get('podSelector') == {}
                    ns_selector_all = from_rule.get('namespaceSelector') == {}
                    ip_block_all = from_rule.get('ipBlock', {}).get('cidr') == '0.0.0.0/0'

                    if pod_selector_all:
                        details = f"Policy '{policy_name}' (namespace '{ns}') ingress rule #{rule_idx+1}, from rule #{from_rule_idx+1}, allows traffic from ALL pods in selected namespaces (empty podSelector)."
                        add_finding(findings, SEVERITY_LOW, "Network Policy Allows Ingress From All Pods", details,
                                    "Specify labels in podSelectors to restrict allowed source pods.",
                                    "CIS 5.3.2", ns, policy_name, "NetworkPolicy",
                                    check_id="k8s.network_policies.ingress-all-pods")
                    elif ns_selector_all:
                        details = f"Policy '{policy_name}' (namespace '{ns}') ingress rule #{rule_idx+1}, from rule #{from_rule_idx+1}, allows traffic from ALL namespaces (empty namespaceSelector)."
                        add_finding(findings, SEVERITY_LOW, "Network Policy Allows Ingress From All Namespaces", details,
                                    "Specify labels in namespaceSelectors or specific podSelectors to restrict allowed source namespaces/pods.",
                                    "CIS 5.3.2", ns, policy_name, "NetworkPolicy",
                                    check_id="k8s.network_policies.ingress-all-namespaces")
                    elif ip_block_all:
                        details = f"Policy '{policy_name}' (namespace '{ns}') ingress rule #{rule_idx+1}, from rule #{from_rule_idx+1}, allows traffic from ANY IP address (0.0.0.0/0)."
                        add_finding(findings, SEVERITY_MEDIUM, "Network Policy Allows Ingress From Any IP", details,
                                    "Restrict ipBlock CIDRs to only necessary source IP ranges. Avoid allowing from 0.0.0.0/0 if possible.",
                                    "CIS 5.3.2", ns, policy_name, "NetworkPolicy",
                                    check_id="k8s.network_policies.ingress-any-ip")

            # Egress rule analysis
            egress_rules = spec.get('egress', [])
            for rule_idx, rule in enumerate(egress_rules):
                to_rules = rule.get('to')

                # No 'to' field or empty list = allow all destinations
                if to_rules is None or to_rules == []:
                    details = f"Policy '{policy_name}' (namespace '{ns}') egress rule #{rule_idx+1} allows traffic to ALL destinations (no 'to' clause)."
                    add_finding(findings, SEVERITY_MEDIUM, "Network Policy Allows All Egress Destinations", details,
                                "Specify podSelectors, namespaceSelectors, or restrictive ipBlocks in egress rules to limit allowed destinations. Unrestricted egress can facilitate data exfiltration.",
                                "CIS 5.3.2", ns, policy_name, "NetworkPolicy",
                                check_id="k8s.network_policies.egress-allow-all")
                    continue

                for to_rule_idx, to_rule in enumerate(to_rules):
                    pod_selector_all = to_rule.get('podSelector') == {}
                    ns_selector_all = to_rule.get('namespaceSelector') == {}
                    ip_block_all = to_rule.get('ipBlock', {}).get('cidr') == '0.0.0.0/0'

                    if pod_selector_all:
                        details = f"Policy '{policy_name}' (namespace '{ns}') egress rule #{rule_idx+1}, to rule #{to_rule_idx+1}, allows traffic to ALL pods in selected namespaces (empty podSelector)."
                        add_finding(findings, SEVERITY_LOW, "Network Policy Allows Egress To All Pods", details,
                                    "Specify labels in podSelectors to restrict allowed destination pods.",
                                    "CIS 5.3.2", ns, policy_name, "NetworkPolicy",
                                    check_id="k8s.network_policies.egress-all-pods")
                    elif ns_selector_all:
                        details = f"Policy '{policy_name}' (namespace '{ns}') egress rule #{rule_idx+1}, to rule #{to_rule_idx+1}, allows traffic to ALL namespaces (empty namespaceSelector)."
                        add_finding(findings, SEVERITY_LOW, "Network Policy Allows Egress To All Namespaces", details,
                                    "Specify labels in namespaceSelectors to restrict allowed destination namespaces.",
                                    "CIS 5.3.2", ns, policy_name, "NetworkPolicy",
                                    check_id="k8s.network_policies.egress-all-namespaces")
                    elif ip_block_all:
                        details = f"Policy '{policy_name}' (namespace '{ns}') egress rule #{rule_idx+1}, to rule #{to_rule_idx+1}, allows traffic to ANY IP address (0.0.0.0/0)."
                        add_finding(findings, SEVERITY_MEDIUM, "Network Policy Allows Egress To Any IP", details,
                                    "Restrict egress ipBlock CIDRs to only necessary destination IP ranges. Unrestricted egress to 0.0.0.0/0 can facilitate data exfiltration.",
                                    "CIS 5.3.2", ns, policy_name, "NetworkPolicy",
                                    check_id="k8s.network_policies.egress-any-ip")

    # Per-namespace egress coverage check
    for ns, policies in network_policies_by_ns.items():
        if ns in system_namespaces:
            continue
        has_egress_policy = any(
            'Egress' in policy.get('spec', {}).get('policyTypes', [])
            for policy in policies
        )
        if not has_egress_policy:
            add_finding(findings, SEVERITY_MEDIUM, "Namespace Lacks Egress Network Policy",
                        f"Namespace '{ns}' has network policies but none include 'Egress' in policyTypes. Outbound traffic from pods is unrestricted, which can facilitate data exfiltration.",
                        "Add a NetworkPolicy with policyTypes including 'Egress'. Start with a default deny egress policy and explicitly allow required outbound traffic (e.g., DNS on port 53, specific external services).",
                        "CIS 5.3.2", ns, ns, "Namespace",
                        check_id="k8s.network_policies.no-egress-policy")
