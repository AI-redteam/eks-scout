"""Configuration and constants for EKS Scout."""
import os
import json
import logging
from typing import Dict, Any, Optional

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

        if config_file and os.path.exists(config_file):
            self._load_config(config_file)
        else:
            self._load_defaults()

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

            # Load configuration sections
            self.checks_enabled = config_data.get('checks', {})
            self.severity_overrides = config_data.get('severity_overrides', {})
            self.custom_settings = config_data.get('settings', {})

            # Merge custom settings with defaults
            self._load_defaults()  # Load defaults first
            # Then override with custom settings
            if config_data.get('settings'):
                self.custom_settings.update(config_data['settings'])

            logging.info(f"Loaded configuration from {config_file}")
            logging.debug(f"Enabled checks: {len([k for k, v in self.checks_enabled.items() if v and k != '*'])}")
            logging.debug(f"Severity overrides: {len(self.severity_overrides)}")

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
