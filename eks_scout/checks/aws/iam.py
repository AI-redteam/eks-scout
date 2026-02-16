"""IRSA (IAM Roles for Service Accounts) security checks."""
import json
import logging
from urllib.parse import unquote

from eks_scout.config import (
    get_config, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    SEVERITY_LOW, SEVERITY_INFO
)
from eks_scout.core.findings import add_finding
from eks_scout.core.command import run_command

CHECK_NAME = "aws.iam"


def run(findings, resources, config=None):
    """Run IRSA IAM checks against service accounts with role annotations.

    Iterates over ServiceAccounts with eks.amazonaws.com/role-arn annotation.
    De-duplicates by role name (one API call per unique role).
    Short-circuits after first AccessDenied.

    Args:
        findings: List to append findings to.
        resources: Dict containing 'service_accounts', 'profile'.
        config: Optional Config instance (uses global if not provided).
    """
    if config is None:
        config = get_config()

    service_accounts = resources.get('service_accounts', [])
    profile = resources.get('profile')

    overly_broad_policies = config.get_setting('overly_broad_policies', [])
    high_severity_iam_policies = config.get_setting('high_severity_iam_policies', [])

    logging.info("Analyzing IRSA IAM roles...")

    # Collect unique roles from SA annotations
    role_to_sas = {}
    for sa in service_accounts:
        metadata = sa.get('metadata', {})
        annotations = metadata.get('annotations', {})
        role_arn = annotations.get('eks.amazonaws.com/role-arn')
        if not role_arn:
            continue

        role_name = role_arn.rsplit('/', 1)[-1] if '/' in role_arn else role_arn
        if role_name not in role_to_sas:
            role_to_sas[role_name] = {
                'arn': role_arn,
                'service_accounts': [],
            }
        sa_ns = metadata.get('namespace', '')
        sa_name = metadata.get('name', '')
        role_to_sas[role_name]['service_accounts'].append(f"{sa_ns}/{sa_name}")

    if not role_to_sas:
        logging.info("No IRSA-annotated service accounts found.")
        return

    logging.info(f"Found {len(role_to_sas)} unique IRSA roles across {sum(len(v['service_accounts']) for v in role_to_sas.values())} service accounts.")

    access_denied = False
    for role_name, role_info in role_to_sas.items():
        if access_denied:
            break

        role_arn = role_info['arn']
        sa_list = role_info['service_accounts']
        sa_desc = ', '.join(sa_list[:3])
        if len(sa_list) > 3:
            sa_desc += f" (+{len(sa_list) - 3} more)"

        # 7a. Trust policy check
        access_denied = _check_trust_policy(
            findings, role_name, role_arn, sa_desc, profile, access_denied)

        if access_denied:
            break

        # 7b. Attached policy check
        access_denied = _check_role_policies(
            findings, role_name, role_arn, sa_desc, profile,
            overly_broad_policies, high_severity_iam_policies, access_denied)


def _check_trust_policy(findings, role_name, role_arn, sa_desc, profile, access_denied):
    """Check IRSA trust policy for missing :sub condition.

    Returns True if access was denied (to short-circuit further calls).
    """
    output = run_command(
        "aws",
        ["iam", "get-role", "--role-name", role_name, "--output", "json"],
        profile=profile,
        suppress_error=True,
        check_rc=False,
    )

    if not output:
        logging.warning(f"Could not get IAM role '{role_name}' — skipping trust policy check (likely AccessDenied).")
        return True

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logging.warning(f"Failed to parse IAM role response for '{role_name}'.")
        return False

    role_data = data.get('Role', {})
    trust_policy = role_data.get('AssumeRolePolicyDocument', {})

    # Trust policy may be URL-encoded
    if isinstance(trust_policy, str):
        try:
            trust_policy = json.loads(unquote(trust_policy))
        except (json.JSONDecodeError, ValueError):
            return False

    statements = trust_policy.get('Statement', [])
    for stmt in statements:
        conditions = stmt.get('Condition', {})
        # Look for OIDC conditions typical of IRSA
        all_conditions = {}
        for cond_type in ('StringEquals', 'StringLike'):
            all_conditions.update(conditions.get(cond_type, {}))

        has_aud = any(':aud' in k for k in all_conditions)
        has_sub = any(':sub' in k for k in all_conditions)

        if has_aud and not has_sub:
            add_finding(findings, SEVERITY_HIGH, "IRSA Trust Policy Missing Subject Condition",
                        f"IAM role '{role_name}' ({role_arn}) used by {sa_desc} has an OIDC trust policy with ':aud' condition but no ':sub' condition. Any service account in the cluster can assume this role.",
                        "Add a StringEquals condition for ':sub' (e.g., 'system:serviceaccount:<namespace>:<sa-name>') to restrict which service accounts can assume this role.",
                        "AWS Best Practice / IRSA", '(cluster)', role_name, "IAM Role",
                        check_id="aws.iam.irsa-trust-policy-weak")

    return False


def _check_role_policies(findings, role_name, role_arn, sa_desc, profile,
                          overly_broad_policies, high_severity_iam_policies, access_denied):
    """Check if IRSA role has overly broad policies attached.

    Returns True if access was denied (to short-circuit further calls).
    """
    output = run_command(
        "aws",
        ["iam", "list-attached-role-policies", "--role-name", role_name, "--output", "json"],
        profile=profile,
        suppress_error=True,
        check_rc=False,
    )

    if not output:
        logging.warning(f"Could not list policies for IRSA role '{role_name}' — skipping.")
        return True

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logging.warning(f"Failed to parse policy list for IRSA role '{role_name}'.")
        return False

    attached_policies = data.get('AttachedPolicies', [])
    for policy in attached_policies:
        policy_name = policy.get('PolicyName', '')
        if policy_name in overly_broad_policies:
            severity = SEVERITY_HIGH if policy_name in high_severity_iam_policies else SEVERITY_MEDIUM
            add_finding(findings, severity, "IRSA Role Has Overly Broad Policy",
                        f"IRSA role '{role_name}' ({role_arn}) used by {sa_desc} has '{policy_name}' attached. Pods using this role have excessive AWS permissions.",
                        f"Remove '{policy_name}' and create a scoped policy with only the permissions the workload needs.",
                        "AWS Best Practice / Least Privilege", '(cluster)', role_name, "IAM Role",
                        check_id="aws.iam.irsa-overly-permissive")

    return False
