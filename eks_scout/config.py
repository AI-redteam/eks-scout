"""Configuration and constants for EKS Scout."""
import os
import json
import logging
import re
from typing import Dict, Any, List, Optional

# Severity level constants
SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Informational"

# Try to import YAML support (optional dependency)
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    logging.debug("PyYAML not installed - YAML config support disabled. JSON config still supported.")


class Config:
    """
    Global configuration for EKS Scout.

    Supports both JSON (.json) and YAML (.yaml, .yml) configuration files.
    YAML support requires optional PyYAML package (pip install pyyaml).

    Configuration file format (YAML or JSON):
    ```yaml
    checks:
      "k8s.pods.privileged": true
      "k8s.pods.capabilities": true
      "aws.guardduty.findings": false
      "*": true  # Wildcard - enable all not explicitly listed

    severity_overrides:
      "k8s.pods.latest-tag": "MEDIUM"

    settings:
      psa_expected_level: "restricted"
      allowed_registries:
        - "amazonaws.com"
        - "docker.io"
      sensitive_capabilities:
        - "SYS_ADMIN"
        - "NET_ADMIN"
    ```
    """

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration.

        Args:
            config_file: Path to configuration file (JSON or YAML).
                         If None, uses default configuration.
        """
        self.checks_enabled: Dict[str, bool] = {}
        self.severity_overrides: Dict[str, str] = {}
        self.custom_settings: Dict[str, Any] = {}
        self.suppressions: List[Dict[str, Any]] = []

        # Always load defaults first, then overlay with config file
        self._load_defaults()
        if config_file and os.path.exists(config_file):
            self._load_config(config_file)

    def _load_defaults(self):
        """Load default configuration (all checks enabled)."""
        # All checks enabled by default
        self.checks_enabled = {"*": True}

        # Default settings
        self.custom_settings = {
            "psa_expected_level": "restricted",
            "allowed_registries": [
                "amazonaws.com",
                "docker.io",
                "gcr.io",
                "quay.io",
                "ghcr.io",
                "mcr.microsoft.com"
            ],
            "sensitive_capabilities": [
                "SYS_ADMIN",
                "NET_ADMIN",
                "SYS_PTRACE",
                "SYS_MODULE",
                "DAC_READ_SEARCH",
                "DAC_OVERRIDE",
                "SYS_RAWIO",
                "SYS_BOOT"
            ],
            "sensitive_hostpaths": [
                "/",
                "/etc",
                "/var",
                "/usr",
                "/proc",
                "/root",
                "/var/run/docker.sock"
            ]
        }

    def _load_config(self, config_file: str):
        """
        Load configuration from JSON or YAML file.

        Args:
            config_file: Path to configuration file
        """
        try:
            with open(config_file, 'r') as f:
                # Determine file type by extension
                if config_file.endswith(('.yaml', '.yml')):
                    if not HAS_YAML:
                        logging.error(f"Cannot load YAML config '{config_file}': PyYAML not installed. "
                                    "Install with: pip install pyyaml")
                        self._load_defaults()
                        return
                    config_data = yaml.safe_load(f)
                elif config_file.endswith('.json'):
                    config_data = json.load(f)
                else:
                    # Try JSON first, then YAML if available
                    content = f.read()
                    try:
                        config_data = json.loads(content)
                    except json.JSONDecodeError:
                        if HAS_YAML:
                            config_data = yaml.safe_load(content)
                        else:
                            raise ValueError(f"Could not parse config file '{config_file}' as JSON or YAML")

            # yaml.safe_load returns None for empty files
            if config_data is None:
                logging.warning(f"Config file '{config_file}' is empty. Using defaults.")
                return

            # Overlay config file values on top of defaults
            if config_data.get('checks'):
                self.checks_enabled.update(config_data['checks'])
            if config_data.get('severity_overrides'):
                self.severity_overrides.update(config_data['severity_overrides'])
            if config_data.get('settings'):
                self.custom_settings.update(config_data['settings'])

            # Load suppressions (list of rule dicts)
            raw_suppressions = config_data.get('suppressions', [])
            if raw_suppressions:
                self.suppressions = self._compile_suppressions(raw_suppressions)

            logging.info(f"Loaded configuration from {config_file}")
            logging.debug(f"Enabled checks: {len([k for k, v in self.checks_enabled.items() if v and k != '*'])}")
            logging.debug(f"Severity overrides: {len(self.severity_overrides)}")
            logging.debug(f"Suppression rules: {len(self.suppressions)}")

        except FileNotFoundError:
            logging.warning(f"Config file not found: {config_file}. Using defaults.")
            self._load_defaults()
        except Exception as e:
            logging.error(f"Failed to load config file {config_file}: {e}")
            logging.warning("Using default configuration.")
            self._load_defaults()

    def is_check_enabled(self, check_id: str) -> bool:
        """
        Check if a specific check is enabled.

        Args:
            check_id: Check identifier (e.g., 'k8s.pods.privileged')

        Returns:
            True if check is enabled, False otherwise
        """
        # Check specific check ID first
        if check_id in self.checks_enabled:
            return self.checks_enabled[check_id]

        # Fall back to wildcard
        return self.checks_enabled.get("*", True)

    def get_severity(self, check_id: str, default: str) -> str:
        """
        Get severity for a check, applying overrides if configured.

        Args:
            check_id: Check identifier
            default: Default severity if no override exists

        Returns:
            Severity level (with override applied if configured)
        """
        return self.severity_overrides.get(check_id, default)

    def get_setting(self, key: str, default: Any = None) -> Any:
        """
        Get custom setting value.

        Args:
            key: Setting key
            default: Default value if setting not found

        Returns:
            Setting value or default
        """
        return self.custom_settings.get(key, default)

    def get_suppressions(self) -> List[Dict[str, Any]]:
        """Get compiled suppression rules.

        Returns:
            List of suppression rule dicts, each with optional keys:
            type, namespace, name_pattern (compiled regex), labels, reason.
        """
        return self.suppressions

    def _compile_suppressions(self, raw_rules: List[Dict]) -> List[Dict[str, Any]]:
        """Compile suppression rules, pre-compiling regex patterns.

        Args:
            raw_rules: List of raw suppression rule dicts from config.

        Returns:
            List of compiled suppression rules.
        """
        compiled = []
        for i, rule in enumerate(raw_rules):
            if not isinstance(rule, dict):
                logging.warning(f"Suppression rule #{i+1} is not a dict, skipping.")
                continue

            compiled_rule = {
                'reason': rule.get('reason', 'No reason provided'),
            }

            if 'type' in rule:
                compiled_rule['type'] = rule['type']
            if 'namespace' in rule:
                compiled_rule['namespace'] = rule['namespace']
            if 'name' in rule:
                try:
                    # Anchor the pattern so "app" matches exactly, not "my-app-deploy"
                    pattern = rule['name']
                    if not pattern.startswith('^'):
                        pattern = '^' + pattern
                    if not pattern.endswith('$'):
                        pattern = pattern + '$'
                    compiled_rule['name_pattern'] = re.compile(pattern)
                except re.error as e:
                    logging.warning(f"Suppression rule #{i+1} has invalid regex '{rule['name']}': {e}")
                    continue
            if 'labels' in rule and isinstance(rule['labels'], dict):
                compiled_rule['labels'] = rule['labels']

            compiled.append(compiled_rule)

        return compiled


# Global config instance (will be initialized in main())
_config: Optional[Config] = None


def get_config() -> Config:
    """
    Get global configuration instance.

    Returns:
        Global Config instance
    """
    global _config
    if _config is None:
        _config = Config()
    return _config


def set_config(config: Config):
    """
    Set global configuration instance.

    Args:
        config: Config instance to set as global
    """
    global _config
    _config = config
