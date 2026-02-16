"""EKS nodegroup security checks."""
import json
import logging

from eks_scout.config import (
    get_config, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    SEVERITY_LOW, SEVERITY_INFO
)
from eks_scout.core.findings import add_finding
from eks_scout.core.command import run_command

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
    profile = resources.get('profile')
    region = resources.get('region', 'us-east-1')

    overly_broad_policies = config.get_setting('overly_broad_policies', [])
    high_severity_iam_policies = config.get_setting('high_severity_iam_policies', [])

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
                    "N/A", '(cluster)', asset_name, asset_type,
                    check_id="aws.nodegroups.config-info")

        # SSH Access
        if ec2_ssh_key:
            if not source_sgs:
                add_finding(findings, SEVERITY_HIGH, "Nodegroup SSH Access Enabled Without Source Restriction",
                            f"Nodegroup '{ng_name}' has SSH access enabled via key '{ec2_ssh_key}' but does not restrict access to specific source Security Groups. This likely allows SSH access from any IP address with the key.",
                            "Define specific source Security Groups ('sourceSecurityGroups') for SSH access to restrict it to trusted bastion hosts or administrative networks. Alternatively, disable SSH access ('ec2SshKey: null') if not required.",
                            "CIS 4.1.1", '(cluster)', asset_name, asset_type,
                            check_id="aws.nodegroups.ssh-unrestricted")
            else:
                add_finding(findings, SEVERITY_MEDIUM, "Nodegroup SSH Access Enabled",
                            f"Nodegroup '{ng_name}' has SSH access enabled via key '{ec2_ssh_key}', restricted to source Security Groups: {source_sgs}.",
                            "Ensure SSH access is necessary and the source security groups allow only minimal required access (e.g., from specific bastion IPs). Regularly rotate SSH keys and disable access if not actively needed.",
                            "CIS 4.1.1", '(cluster)', asset_name, asset_type,
                            check_id="aws.nodegroups.ssh-enabled")
        else:
            add_finding(findings, SEVERITY_INFO, "Nodegroup SSH Access Disabled",
                        f"Nodegroup '{ng_name}' does not have EC2 SSH key configured in its remote access settings.",
                        "Direct SSH access to nodes via the EKS nodegroup configuration is disabled. Verify launch template overrides if applicable.",
                        "CIS 4.1.1", '(cluster)', asset_name, asset_type,
                        check_id="aws.nodegroups.ssh-disabled")

        # Node IAM Role
        if node_role_arn:
            role_name = node_role_arn.split('/')[-1]
            add_finding(findings, SEVERITY_INFO, "Nodegroup IAM Role Identified",
                        f"Nodegroup '{ng_name}' uses Node IAM role: {role_name} ({node_role_arn}).",
                        "Review policies attached (e.g., AmazonEKSWorkerNodePolicy, AmazonEC2ContainerRegistryReadOnly, AmazonEKS_CNI_Policy). Ensure no unnecessary permissions (e.g., broad EC2/S3 access). Consider deeper analysis if IAM permissions allow.",
                        "AWS Best Practice / IAM", '(cluster)', asset_name, f"{asset_type} IAM Role",
                        check_id="aws.nodegroups.iam-role")

            # 6a. Node IAM policy enumeration
            _check_node_iam_policies(findings, role_name, ng_name, asset_name, asset_type,
                                     profile, overly_broad_policies, high_severity_iam_policies)

        # 6b. IMDSv2 via launch template
        _check_imdsv2(findings, ng, ng_name, asset_name, asset_type, profile, region)


def _check_node_iam_policies(findings, role_name, ng_name, asset_name, asset_type,
                              profile, overly_broad_policies, high_severity_iam_policies):
    """Check if the node IAM role has overly broad policies attached."""
    output = run_command(
        "aws",
        ["iam", "list-attached-role-policies", "--role-name", role_name, "--output", "json"],
        profile=profile,
        suppress_error=True,
        check_rc=False,
    )

    if not output:
        logging.warning(f"Could not list IAM policies for role '{role_name}' — skipping IAM policy check.")
        return

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logging.warning(f"Failed to parse IAM policy response for role '{role_name}'.")
        return

    attached_policies = data.get('AttachedPolicies', [])
    for policy in attached_policies:
        policy_name = policy.get('PolicyName', '')
        if policy_name in overly_broad_policies:
            severity = SEVERITY_HIGH if policy_name in high_severity_iam_policies else SEVERITY_MEDIUM
            add_finding(findings, severity, "Node IAM Role Has Overly Broad Policy",
                        f"Nodegroup '{ng_name}' node role has '{policy_name}' attached. This grants excessive permissions to all pods on these nodes (unless IRSA is used).",
                        f"Remove '{policy_name}' from the node role and use IRSA (IAM Roles for Service Accounts) to grant specific permissions to individual workloads.",
                        "AWS Best Practice / Least Privilege", '(cluster)', asset_name, asset_type,
                        check_id="aws.nodegroups.overly-permissive-iam")


def _check_imdsv2(findings, ng, ng_name, asset_name, asset_type, profile, region):
    """Check IMDSv2 enforcement via launch template."""
    launch_template = ng.get('launchTemplate')

    if not launch_template:
        add_finding(findings, SEVERITY_MEDIUM, "Nodegroup Missing Launch Template",
                    f"Nodegroup '{ng_name}' does not use a custom launch template. IMDSv2 enforcement cannot be verified and may not be configured.",
                    "Create a launch template with MetadataOptions.HttpTokens set to 'required' to enforce IMDSv2 and mitigate SSRF-based credential theft.",
                    "CIS 4.1.3", '(cluster)', asset_name, asset_type,
                    check_id="aws.nodegroups.imdsv2-not-enforced")
        return

    lt_id = launch_template.get('id', '')
    lt_version = launch_template.get('version', '$Default')

    output = run_command(
        "aws",
        ["ec2", "describe-launch-template-versions",
         "--launch-template-id", lt_id,
         "--versions", str(lt_version),
         "--region", region,
         "--output", "json"],
        profile=profile,
        suppress_error=True,
        check_rc=False,
    )

    if not output:
        add_finding(findings, SEVERITY_INFO, "IMDSv2 Check Skipped",
                    f"Nodegroup '{ng_name}': Could not describe launch template '{lt_id}' (permission denied or not found). IMDSv2 status unknown.",
                    "Grant ec2:DescribeLaunchTemplateVersions permission to verify IMDSv2 enforcement.",
                    "CIS 4.1.3", '(cluster)', asset_name, asset_type,
                    check_id="aws.nodegroups.imdsv2-check-skipped")
        return

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logging.warning(f"Failed to parse launch template response for '{lt_id}'.")
        return

    versions = data.get('LaunchTemplateVersions', [])
    if not versions:
        return

    lt_data = versions[0].get('LaunchTemplateData', {})
    metadata_options = lt_data.get('MetadataOptions', {})
    http_tokens = metadata_options.get('HttpTokens', '')

    if http_tokens == 'required':
        add_finding(findings, SEVERITY_INFO, "IMDSv2 Enforced",
                    f"Nodegroup '{ng_name}' launch template enforces IMDSv2 (HttpTokens=required).",
                    "No action needed. IMDSv2 is correctly enforced.",
                    "CIS 4.1.3", '(cluster)', asset_name, asset_type,
                    check_id="aws.nodegroups.imdsv2-enforced")
    else:
        add_finding(findings, SEVERITY_HIGH, "IMDSv2 Not Enforced",
                    f"Nodegroup '{ng_name}' launch template has HttpTokens='{http_tokens or 'not set'}'. IMDSv1 is accessible, enabling SSRF-based credential theft from pods.",
                    "Update the launch template to set MetadataOptions.HttpTokens to 'required' to enforce IMDSv2.",
                    "CIS 4.1.3", '(cluster)', asset_name, asset_type,
                    check_id="aws.nodegroups.imdsv2-not-enforced")
