"""Kubernetes secrets and configmaps security checks."""
import logging

from eks_scout.config import (
    get_config, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    SEVERITY_LOW, SEVERITY_INFO
)
from eks_scout.core.findings import add_finding

CHECK_NAME = "k8s.secrets_configmaps"


def run(findings, resources, config=None):
    """Run secrets and configmaps security checks.

    Args:
        findings: List to append findings to.
        resources: Dict containing 'secrets', 'configmaps'.
        config: Optional Config instance (uses global if not provided).
    """
    if config is None:
        config = get_config()

    secrets = resources.get('secrets', [])
    configmaps = resources.get('configmaps', [])

    logging.info("Analyzing Secrets and ConfigMaps (Basic Checks)...")
    sensitive_key_patterns = config.get_setting('sensitive_key_patterns',
                                                ['password', 'secret', 'token', 'key', 'passwd', 'pwd',
                                                 'auth', 'credential', 'apikey', 'access_key', 'secret_key'])

    for secret in secrets:
        metadata = secret.get('metadata', {})
        ns = metadata.get('namespace')
        name = metadata.get('name')
        secret_type = secret.get('type', 'Opaque')

        if secret_type in ['kubernetes.io/basic-auth', 'kubernetes.io/ssh-auth',
                           'kubernetes.io/dockerconfigjson', 'kubernetes.io/tls']:
            add_finding(findings, SEVERITY_INFO, "Potentially Sensitive Secret Type Used",
                        f"Secret '{name}' in namespace '{ns}' has type '{secret_type}', which typically stores credentials or sensitive data.",
                        "Ensure access to this secret is tightly controlled via RBAC. Ensure applications retrieve specific keys if possible, rather than mounting the entire secret.",
                        "Best Practice", ns, name, "Secret",
                        check_id="k8s.secrets_configmaps.sensitive-secret-type")

    for cm in configmaps:
        metadata = cm.get('metadata', {})
        ns = metadata.get('namespace')
        name = metadata.get('name')
        data = cm.get('data', {})

        if data:
            cm_keys = list(data.keys())
            found_sensitive_keys = [key for key in cm_keys
                                    if any(pattern in key.lower() for pattern in sensitive_key_patterns)]

            if found_sensitive_keys:
                add_finding(findings, SEVERITY_MEDIUM, "Potential Sensitive Data in ConfigMap Keys",
                            f"ConfigMap '{name}' in namespace '{ns}' contains keys that suggest sensitive data might be stored insecurely: {found_sensitive_keys}. ConfigMaps are often less protected by RBAC than Secrets.",
                            "Do not store secrets or sensitive configuration (passwords, tokens, keys) in ConfigMaps. Use Kubernetes Secrets instead and ensure appropriate RBAC.",
                            "CIS 5.4.1", ns, name, "ConfigMap",
                            check_id="k8s.secrets_configmaps.sensitive-configmap-keys")
