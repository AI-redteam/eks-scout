"""EKS cluster security group checks."""
import json
import logging

from eks_scout.config import (
    get_config, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    SEVERITY_LOW, SEVERITY_INFO
)
from eks_scout.core.findings import add_finding
from eks_scout.core.command import run_command

CHECK_NAME = "aws.security_groups"

# Sensitive ports and their descriptions
SENSITIVE_PORTS = {
    10250: ("kubelet API", SEVERITY_HIGH),
    10255: ("kubelet read-only", SEVERITY_MEDIUM),
    22: ("SSH", SEVERITY_MEDIUM),
    2379: ("etcd client", SEVERITY_HIGH),
    2380: ("etcd peer", SEVERITY_HIGH),
}


def run(findings, resources, config=None):
    """Run security group checks for the EKS cluster.

    Collects SG IDs from cluster VPC config and checks ingress rules
    for 0.0.0.0/0 on sensitive ports.

    Args:
        findings: List to append findings to.
        resources: Dict containing 'cluster_info', 'profile', 'region'.
        config: Optional Config instance (uses global if not provided).
    """
    if config is None:
        config = get_config()

    cluster_info = resources.get('cluster_info')
    if not cluster_info:
        logging.info("No cluster info available — skipping security group checks.")
        return

    profile = resources.get('profile')
    region = resources.get('region', 'us-east-1')
    cluster_name = resources.get('cluster_name', 'unknown')

    nodeport_range = config.get_setting('nodeport_range', [30000, 32767])

    # Collect all SG IDs from cluster VPC config
    vpc_config = cluster_info.get('resourcesVpcConfig', {})
    sg_ids = set()

    cluster_sg = vpc_config.get('clusterSecurityGroupId')
    if cluster_sg:
        sg_ids.add(cluster_sg)

    additional_sgs = vpc_config.get('securityGroupIds', [])
    if additional_sgs:
        sg_ids.update(additional_sgs)

    if not sg_ids:
        logging.info("No security group IDs found in cluster VPC config.")
        return

    logging.info(f"Checking {len(sg_ids)} cluster security groups...")

    # Describe security groups
    output = run_command(
        "aws",
        ["ec2", "describe-security-groups",
         "--group-ids"] + list(sg_ids) + [
         "--region", region,
         "--output", "json"],
        profile=profile,
        suppress_error=True,
        check_rc=False,
    )

    if not output:
        logging.warning("Could not describe security groups (permission denied or error) — skipping SG checks.")
        return

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logging.warning("Failed to parse security group response.")
        return

    security_groups = data.get('SecurityGroups', [])

    for sg in security_groups:
        sg_id = sg.get('GroupId', '')
        sg_name = sg.get('GroupName', '')
        asset_name = f"{cluster_name}/{sg_id}"

        for rule in sg.get('IpPermissions', []):
            _check_ingress_rule(findings, rule, sg_id, sg_name, asset_name,
                                cluster_name, nodeport_range)


def _check_ingress_rule(findings, rule, sg_id, sg_name, asset_name,
                         cluster_name, nodeport_range):
    """Check a single ingress rule for 0.0.0.0/0 on sensitive ports."""
    # Check if rule allows 0.0.0.0/0 or ::/0
    open_cidrs = []
    for ip_range in rule.get('IpRanges', []):
        if ip_range.get('CidrIp') == '0.0.0.0/0':
            open_cidrs.append('0.0.0.0/0')
    for ip_range in rule.get('Ipv6Ranges', []):
        if ip_range.get('CidrIpv6') == '::/0':
            open_cidrs.append('::/0')

    if not open_cidrs:
        return

    ip_protocol = rule.get('IpProtocol', '')
    from_port = rule.get('FromPort', -1)
    to_port = rule.get('ToPort', -1)
    cidr_str = ', '.join(open_cidrs)

    # All traffic (-1 protocol)
    if ip_protocol == '-1':
        add_finding(findings, SEVERITY_HIGH, "Security Group Allows All Inbound Traffic",
                    f"Security group '{sg_id}' ({sg_name}) associated with cluster '{cluster_name}' allows ALL inbound traffic from {cidr_str}.",
                    "Restrict inbound rules to only required ports and source CIDRs.",
                    "CIS EKS 5.4.4", '(cluster)', asset_name, "Security Group",
                    check_id="aws.security_groups.open-all-traffic")
        return

    # Only check TCP/UDP rules
    if ip_protocol not in ('tcp', 'udp', '6', '17'):
        return

    # Check specific sensitive ports
    for port, (desc, severity) in SENSITIVE_PORTS.items():
        if from_port <= port <= to_port:
            add_finding(findings, severity, f"Security Group Exposes {desc} to Internet",
                        f"Security group '{sg_id}' ({sg_name}) allows inbound traffic on port {port} ({desc}) from {cidr_str}.",
                        f"Remove or restrict the inbound rule for port {port}. {desc} should not be exposed to the internet.",
                        "CIS EKS 5.4.4", '(cluster)', asset_name, "Security Group",
                        check_id=f"aws.security_groups.open-{port}")

    # Check etcd range (2379-2380)
    if from_port <= 2380 and to_port >= 2379:
        pass  # Already handled by individual port checks above

    # Check NodePort range
    np_start, np_end = nodeport_range
    if from_port <= np_end and to_port >= np_start:
        # Calculate overlap
        overlap_start = max(from_port, np_start)
        overlap_end = min(to_port, np_end)
        add_finding(findings, SEVERITY_MEDIUM, "Security Group Exposes NodePort Range to Internet",
                    f"Security group '{sg_id}' ({sg_name}) allows inbound traffic on ports {overlap_start}-{overlap_end} (NodePort range) from {cidr_str}.",
                    "Restrict NodePort range access to known source CIDRs or use a LoadBalancer/Ingress controller instead of NodePort services.",
                    "CIS EKS 5.4.4", '(cluster)', asset_name, "Security Group",
                    check_id="aws.security_groups.open-nodeport-range")
