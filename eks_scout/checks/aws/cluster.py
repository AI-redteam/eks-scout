"""EKS cluster configuration security checks."""
import logging

from eks_scout.config import (
    get_config, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    SEVERITY_LOW, SEVERITY_INFO
)
from eks_scout.core.findings import add_finding

CHECK_NAME = "aws.cluster"


def run(findings, resources, config=None):
    """Run EKS cluster configuration checks.

    Args:
        findings: List to append findings to.
        resources: Dict containing 'cluster_info', 'cluster_name', 'region'.
        config: Optional Config instance (uses global if not provided).
    """
    if config is None:
        config = get_config()

    cluster_info = resources.get('cluster_info')
    cluster_name = resources.get('cluster_name', 'unknown')
    region = resources.get('region', 'unknown')

    logging.info("Analyzing EKS Cluster Configuration...")
    if not cluster_info:
        logging.error("Skipping EKS cluster analysis due to previous fetch error.")
        return

    version = cluster_info.get('version')
    platform_version = cluster_info.get('platformVersion')

    add_finding(findings, SEVERITY_INFO, "EKS Cluster Version",
                f"Cluster '{cluster_name}' is running Kubernetes version '{version}' and EKS platform version '{platform_version}'.",
                "Ensure the Kubernetes version is supported and patched. Regularly review EKS platform version updates and plan upgrades before end-of-support.",
                "AWS Best Practice / Version Management", '(cluster)', cluster_name, "EKS Cluster",
                check_id="aws.cluster.version")

    # Endpoint Access
    vpc_config = cluster_info.get('resourcesVpcConfig', {})
    public_access = vpc_config.get('endpointPublicAccess', False)
    private_access = vpc_config.get('endpointPrivateAccess', False)
    public_cidrs = vpc_config.get('publicAccessCidrs', [])

    if public_access:
        if not public_cidrs or "0.0.0.0/0" in public_cidrs:
            add_finding(findings, SEVERITY_HIGH, "EKS Public API Endpoint Open to Internet",
                        f"EKS cluster '{cluster_name}' API endpoint is publicly accessible from all IPs (0.0.0.0/0). This exposes the Kubernetes API server to the internet, increasing the attack surface.",
                        "Restrict public access CIDRs ('publicAccessCidrs') to a minimal set of trusted network ranges. If internal network access is sufficient, disable public access entirely and rely on the private endpoint.",
                        "CIS EKS 5.4.1", '(cluster)', cluster_name, "EKS Cluster",
                        check_id="aws.cluster.public-endpoint")
        else:
            add_finding(findings, SEVERITY_LOW, "EKS Public API Endpoint Access Enabled",
                        f"EKS cluster '{cluster_name}' API endpoint is publicly accessible from specific CIDRs: {public_cidrs}.",
                        "Ensure the allowed CIDRs are necessary, restricted to the minimum required ranges, and regularly reviewed. Prefer using the private endpoint ('endpointPrivateAccess: true') where possible.",
                        "CIS EKS 5.4.1", '(cluster)', cluster_name, "EKS Cluster",
                        check_id="aws.cluster.public-endpoint-restricted")

    if not private_access and not public_access:
        add_finding(findings, SEVERITY_HIGH, "EKS API Endpoint Access Disabled",
                    f"EKS cluster '{cluster_name}' has both public and private API endpoint access disabled. This typically indicates a misconfiguration, making the cluster control plane inaccessible.",
                    "Review cluster configuration. At least one access method (preferably private) must be enabled for the cluster to function correctly.",
                    "AWS Error", '(cluster)', cluster_name, "EKS Cluster",
                    check_id="aws.cluster.endpoint-disabled")
    elif not private_access and public_access:
        add_finding(findings, SEVERITY_MEDIUM, "EKS Private API Endpoint Access Disabled",
                    f"EKS cluster '{cluster_name}' does not have private API endpoint access enabled. Access relies solely on the public endpoint, preventing access from within the VPC without traversing public internet paths.",
                    "Enable private endpoint access ('endpointPrivateAccess: true') for improved security, network isolation, and potentially lower latency access from within the VPC.",
                    "CIS EKS 5.4.2", '(cluster)', cluster_name, "EKS Cluster",
                    check_id="aws.cluster.private-endpoint-disabled")

    # Control Plane Logging
    required_logs = config.get_setting('required_control_plane_logs',
                                       ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'])
    enabled_logs_config = cluster_info.get('logging', {}).get('clusterLogging', [])
    enabled_logs_flat = set()
    for log_group in enabled_logs_config:
        if log_group.get('enabled'):
            enabled_logs_flat.update(log_group.get('types', []))

    missing_logs = [log for log in required_logs if log not in enabled_logs_flat]
    if missing_logs:
        add_finding(findings, SEVERITY_MEDIUM, "EKS Control Plane Logging Disabled",
                    f"EKS cluster '{cluster_name}' does not have all recommended control plane log types enabled. Missing: {', '.join(missing_logs)}. This hinders security auditing, incident response, and operational troubleshooting.",
                    f"Enable all recommended control plane log types ({', '.join(required_logs)}) in the cluster's logging configuration to ensure comprehensive visibility into control plane activities.",
                    "CIS EKS 2.1.1", '(cluster)', cluster_name, "EKS Cluster",
                    check_id="aws.cluster.logging-disabled")
    else:
        add_finding(findings, SEVERITY_INFO, "EKS Control Plane Logging Enabled",
                    f"EKS cluster '{cluster_name}' has all recommended control plane log types enabled ({', '.join(required_logs)}).",
                    "Ensure these logs (especially audit logs) are being ingested, monitored, and retained appropriately in CloudWatch Logs or a dedicated SIEM system.",
                    "CIS EKS 2.1.1", '(cluster)', cluster_name, "EKS Cluster",
                    check_id="aws.cluster.logging-enabled")

    # Secrets Encryption
    encryption_config = cluster_info.get('encryptionConfig', [])
    kms_key_arn = None
    secrets_resource_encrypted = False
    if encryption_config:
        for cfg in encryption_config:
            provider_key_arn = cfg.get('provider', {}).get('keyArn')
            if provider_key_arn:
                kms_key_arn = provider_key_arn
                if 'secrets' in cfg.get('resources', []):
                    secrets_resource_encrypted = True
                    break

    if not kms_key_arn:
        add_finding(findings, SEVERITY_HIGH, "EKS Secrets Encryption Not Enabled",
                    f"EKS cluster '{cluster_name}' does not have envelope encryption for Kubernetes secrets enabled using a KMS key. Secrets are stored base64 encoded but unencrypted at rest in etcd.",
                    "Enable envelope encryption using a customer-managed KMS key to protect Kubernetes secrets at rest in the underlying etcd datastore.",
                    "CIS EKS 5.3.1", '(cluster)', cluster_name, "EKS Cluster",
                    check_id="aws.cluster.secrets-not-encrypted")
    elif not secrets_resource_encrypted:
        add_finding(findings, SEVERITY_HIGH, "EKS Secrets Resource Not Explicitly Encrypted",
                    f"EKS cluster '{cluster_name}' has envelope encryption configured with KMS key '{kms_key_arn}', but the 'secrets' resource is not explicitly listed in the encryption configuration's resources.",
                    "Ensure the 'secrets' resource type is included in the 'resources' list within the EKS encryptionConfig to guarantee secrets are encrypted at rest.",
                    "CIS EKS 5.3.1", '(cluster)', cluster_name, "EKS Cluster",
                    check_id="aws.cluster.secrets-resource-not-encrypted")
    else:
        add_finding(findings, SEVERITY_INFO, "EKS Secrets Encryption Enabled",
                    f"EKS cluster '{cluster_name}' has envelope encryption enabled for secrets using KMS key: {kms_key_arn}.",
                    "Ensure the KMS key policy follows the principle of least privilege and that key rotation is considered.",
                    "CIS EKS 5.3.1", '(cluster)', cluster_name, "EKS Cluster",
                    check_id="aws.cluster.secrets-encrypted")

    # Cluster IAM Role Analysis
    cluster_role_arn = cluster_info.get('roleArn')
    if cluster_role_arn:
        role_name = cluster_role_arn.split('/')[-1]
        add_finding(findings, SEVERITY_INFO, "EKS Cluster IAM Role Identified",
                    f"EKS cluster '{cluster_name}' uses IAM role: {role_name} ({cluster_role_arn}).",
                    "Review the policies attached to this role (e.g., AmazonEKSClusterPolicy). Ensure they are not overly permissive and adhere to least privilege. Consider deeper analysis if IAM permissions allow.",
                    "AWS Best Practice / IAM", '(cluster)', cluster_name, "EKS Cluster IAM Role",
                    check_id="aws.cluster.iam-role")
