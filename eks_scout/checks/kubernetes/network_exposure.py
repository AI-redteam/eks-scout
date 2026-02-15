"""Kubernetes service and ingress network exposure checks."""
import logging

from eks_scout.config import (
    get_config, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    SEVERITY_LOW, SEVERITY_INFO
)
from eks_scout.core.findings import add_finding

CHECK_NAME = "k8s.network_exposure"


def run(findings, resources, config=None):
    """Run network exposure checks on services and ingresses.

    Args:
        findings: List to append findings to.
        resources: Dict containing 'services', 'ingresses'.
        config: Optional Config instance (uses global if not provided).
    """
    if config is None:
        config = get_config()

    services = resources.get('services', [])
    ingresses = resources.get('ingresses', [])

    logging.info("Analyzing Services and Ingresses for Network Exposure...")

    # Analyze Services
    for svc in services:
        metadata = svc.get('metadata', {})
        ns = metadata.get('namespace')
        name = metadata.get('name')
        spec = svc.get('spec', {})
        svc_type = spec.get('type')

        if svc_type == 'LoadBalancer':
            ports = spec.get('ports', [])
            port_list = [f"{p.get('port')}/{p.get('protocol', 'TCP')}" for p in ports]
            hostname = ""
            try:
                hostname = svc.get('status', {}).get('loadBalancer', {}).get('ingress', [{}])[0].get('hostname', '')
            except (IndexError, AttributeError, TypeError):
                pass

            details = (f"Service '{name}' in namespace '{ns}' is of Type LoadBalancer, which provisions an external AWS Load Balancer, exposing the service publicly or internally depending on LB annotations/config. "
                       f"Exposed Ports: {', '.join(port_list) or 'None defined in spec?'}. "
                       f"LoadBalancer Hostname (if available): {hostname or 'N/A'}")
            recommendation = ("Verify that this external exposure is intentional and necessary. "
                              "Ensure appropriate security groups are attached to the load balancer restricting access to trusted sources. "
                              "Consider using Ingress resources or internal load balancers if external exposure is not required. "
                              "Regularly review exposed services.")
            add_finding(findings, SEVERITY_MEDIUM, "Service Exposed via LoadBalancer",
                        details, recommendation,
                        "Best Practice / Network Exposure", ns, name, "Service",
                        check_id="k8s.network_exposure.loadbalancer")

        elif svc_type == 'NodePort':
            ports = spec.get('ports', [])
            node_ports = [str(p.get('nodePort', '?')) for p in ports if p.get('nodePort')]
            port_list = [f"{p.get('port')}/{p.get('protocol', 'TCP')} -> nodePort {p.get('nodePort', '?')}" for p in ports]

            details = (f"Service '{name}' in namespace '{ns}' is of Type NodePort, which exposes the service on every node's IP at port(s) {', '.join(node_ports) or 'auto-assigned'}. "
                       f"Port mappings: {', '.join(port_list) or 'None defined'}. "
                       "Any network client that can reach a node IP on these ports can access the service, bypassing ingress controllers and load balancer security groups.")
            recommendation = ("Verify that NodePort exposure is intentional. Prefer using ClusterIP services with an Ingress controller or internal LoadBalancer for controlled access. "
                              "If NodePort is required, ensure node security groups restrict access to the NodePort range (default 30000-32767) from trusted sources only.")
            add_finding(findings, SEVERITY_MEDIUM, "Service Exposed via NodePort",
                        details, recommendation,
                        "Best Practice / Network Exposure", ns, name, "Service",
                        check_id="k8s.network_exposure.nodeport")

    # Analyze Ingresses
    for ing in ingresses:
        metadata = ing.get('metadata', {})
        ns = metadata.get('namespace')
        name = metadata.get('name')
        spec = ing.get('spec', {})
        rules = spec.get('rules', [])
        tls_hosts = {host for tls_entry in spec.get('tls', []) for host in tls_entry.get('hosts', [])}

        if not rules:
            default_backend = spec.get('defaultBackend')
            if default_backend:
                add_finding(findings, SEVERITY_LOW, "Ingress Uses Default Backend",
                            f"Ingress '{name}' in namespace '{ns}' defines a default backend but has no specific rules. All unmatched traffic will be routed here.",
                            "Ensure the default backend is intended and secured. Define specific rules for expected traffic.",
                            "Best Practice / Configuration", ns, name, "Ingress",
                            check_id="k8s.network_exposure.ingress-default-backend")
            continue

        for rule_idx, rule in enumerate(rules):
            host = rule.get('host')

            if host == '*':
                details = (f"Ingress '{name}' in namespace '{ns}' rule #{rule_idx+1} uses a wildcard host ('*'). "
                           "This can lead to unintended traffic routing or conflicts if not carefully managed.")
                recommendation = "Avoid using wildcard hosts in Ingress rules if possible. Use specific hostnames to ensure predictable routing and isolation."
                add_finding(findings, SEVERITY_LOW, "Ingress Rule Uses Wildcard Host",
                            details, recommendation,
                            "Best Practice / Configuration", ns, name, "Ingress",
                            check_id="k8s.network_exposure.ingress-wildcard-host")

            if host and host != '*' and host not in tls_hosts:
                details = (f"Ingress '{name}' in namespace '{ns}' rule #{rule_idx+1} defines host '{host}' but this host is not included in any entry under spec.tls. "
                           "Traffic for this host may be served over unencrypted HTTP.")
                recommendation = (f"Configure TLS for host '{host}' by adding an entry to the Ingress 'spec.tls' section, referencing a valid Kubernetes secret containing the TLS certificate and key. "
                                  "Ensure HTTPS is enforced, potentially via Ingress controller annotations.")
                add_finding(findings, SEVERITY_MEDIUM, "Ingress Rule Lacks TLS Configuration",
                            details, recommendation,
                            "Best Practice / Encryption", ns, name, "Ingress",
                            check_id="k8s.network_exposure.ingress-no-tls")
