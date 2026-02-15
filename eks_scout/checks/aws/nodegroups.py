"""EKS nodegroup security checks."""
import logging

from eks_scout.config import (
    get_config, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    SEVERITY_LOW, SEVERITY_INFO
)
from eks_scout.core.findings import add_finding

CHECK_NAME = "aws.nodegroups"


def run(findings, resources, config=None):
    """Run EKS nodegroup checks.

    Args:
        findings: List to append findings to.
        resources: Dict containing 'nodegroups', 'cluster_name', 'region'.
        config: Optional Config instance (uses global if not provided).
    """
    if config is None:
        config = get_config()

    nodegroups = resources.get('nodegroups', [])
    cluster_name = resources.get('cluster_name', 'unknown')

    logging.info("Analyzing EKS Nodegroups...")
    if not nodegroups:
        logging.info("No managed nodegroups found to analyze.")
        return

    for ng in nodegroups:
        ng_name = ng.get('nodegroupName')
        node_role_arn = ng.get('nodeRole', '')
        remote_access = ng.get('remoteAccess', {})
        ec2_ssh_key = remote_access.get('ec2SshKey') if remote_access else None
        source_sgs = remote_access.get('sourceSecurityGroups') if remote_access else []

        asset_name = f"{cluster_name}/{ng_name}"
        asset_type = "EKS Nodegroup"

        # Basic info
        ami_type = ng.get('amiType')
        version_info = ng.get('releaseVersion')
        instance_types = ng.get('instanceTypes', [])
        add_finding(findings, SEVERITY_INFO, "Nodegroup Configuration Info",
                    f"Nodegroup '{ng_name}': AMI Type '{ami_type}', Version '{version_info}', Instances '{','.join(instance_types)}', Node Role '{node_role_arn.split('/')[-1]}'.",
                    "Informational finding detailing the nodegroup configuration.",
                    "N/A", '(cluster)', asset_name, asset_type)

        # SSH Access
        if ec2_ssh_key:
            if not source_sgs:
                add_finding(findings, SEVERITY_HIGH, "Nodegroup SSH Access Enabled Without Source Restriction",
                            f"Nodegroup '{ng_name}' has SSH access enabled via key '{ec2_ssh_key}' but does not restrict access to specific source Security Groups. This likely allows SSH access from any IP address with the key.",
                            "Define specific source Security Groups ('sourceSecurityGroups') for SSH access to restrict it to trusted bastion hosts or administrative networks. Alternatively, disable SSH access ('ec2SshKey: null') if not required.",
                            "CIS 4.1.1", '(cluster)', asset_name, asset_type)
            else:
                add_finding(findings, SEVERITY_MEDIUM, "Nodegroup SSH Access Enabled",
                            f"Nodegroup '{ng_name}' has SSH access enabled via key '{ec2_ssh_key}', restricted to source Security Groups: {source_sgs}.",
                            "Ensure SSH access is necessary and the source security groups allow only minimal required access (e.g., from specific bastion IPs). Regularly rotate SSH keys and disable access if not actively needed.",
                            "CIS 4.1.1", '(cluster)', asset_name, asset_type)
        else:
            add_finding(findings, SEVERITY_INFO, "Nodegroup SSH Access Disabled",
                        f"Nodegroup '{ng_name}' does not have EC2 SSH key configured in its remote access settings.",
                        "Direct SSH access to nodes via the EKS nodegroup configuration is disabled. Verify launch template overrides if applicable.",
                        "CIS 4.1.1", '(cluster)', asset_name, asset_type)

        # Node IAM Role
        if node_role_arn:
            role_name = node_role_arn.split('/')[-1]
            add_finding(findings, SEVERITY_INFO, "Nodegroup IAM Role Identified",
                        f"Nodegroup '{ng_name}' uses Node IAM role: {role_name} ({node_role_arn}).",
                        "Review policies attached (e.g., AmazonEKSWorkerNodePolicy, AmazonEC2ContainerRegistryReadOnly, AmazonEKS_CNI_Policy). Ensure no unnecessary permissions (e.g., broad EC2/S3 access). Consider deeper analysis if IAM permissions allow.",
                        "AWS Best Practice / IAM", '(cluster)', asset_name, f"{asset_type} IAM Role")

        # IMDSv2 Check Placeholder
        add_finding(findings, SEVERITY_INFO, "IMDSv2 Check Recommended",
                    f"Nodegroup '{ng_name}': Manual check recommended for IMDSv2 enforcement.",
                    "Verify if IMDSv2 is enforced (MetadataHttpTokens=required) on the underlying EC2 instances to mitigate SSRF risks. Check the Launch Template used by the nodegroup or inspect a running instance if EC2 permissions are available.",
                    "CIS 4.1.3", '(cluster)', asset_name, asset_type)
