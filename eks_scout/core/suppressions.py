"""Suppression engine for filtering false positives.

Supports two suppression mechanisms:
1. Config-file rules: match by finding type, namespace, resource name (regex), labels.
2. Kubernetes annotations: eks-scout.io/ignore on resources.
"""
import logging
from typing import Dict, Any, List, Optional, Tuple


# Annotation key used for suppression
IGNORE_ANNOTATION = "eks-scout.io/ignore"


def check_annotation_suppression(metadata: Dict[str, Any], finding_type: str) -> Tuple[bool, str]:
    """Check if a resource's annotations suppress a finding.

    Supports two annotation formats:
        eks-scout.io/ignore: "true"           — suppress ALL findings for this resource
        eks-scout.io/ignore: "Finding A,Finding B"  — suppress only listed finding types

    Args:
        metadata: Resource metadata dict (must contain 'annotations' key).
        finding_type: The finding type string to check.

    Returns:
        (should_suppress, reason) tuple.
    """
    annotations = metadata.get('annotations', {})
    if not annotations:
        return False, ""

    ignore_value = annotations.get(IGNORE_ANNOTATION)
    if ignore_value is None:
        return False, ""

    ignore_value = ignore_value.strip()

    # "true" suppresses all findings
    if ignore_value.lower() == "true":
        return True, f"Resource annotated with {IGNORE_ANNOTATION}: true"

    # Comma-separated list of finding types to suppress
    suppressed_types = [t.strip() for t in ignore_value.split(",")]
    if finding_type in suppressed_types:
        return True, f"Resource annotated with {IGNORE_ANNOTATION} for '{finding_type}'"

    return False, ""


def check_config_suppression(
    finding: Dict[str, Any],
    suppression_rules: List[Dict[str, Any]],
    resource_metadata: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str]:
    """Check if a finding matches any config-file suppression rule.

    Args:
        finding: Finding dict with keys: type, namespace, name, severity, etc.
        suppression_rules: Compiled suppression rules from Config.get_suppressions().
        resource_metadata: Optional resource metadata for label matching.

    Returns:
        (should_suppress, reason) tuple.
    """
    for rule in suppression_rules:
        if _rule_matches(rule, finding, resource_metadata):
            return True, rule.get('reason', 'Matched suppression rule')

    return False, ""


def should_suppress(
    finding: Dict[str, Any],
    suppression_rules: List[Dict[str, Any]],
    resource_metadata: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str]:
    """Check if a finding should be suppressed by any mechanism.

    Checks annotation-based suppression first (if metadata provided),
    then config-file rules.

    Args:
        finding: Finding dict.
        suppression_rules: Compiled suppression rules from config.
        resource_metadata: Optional Kubernetes resource metadata dict.

    Returns:
        (should_suppress, reason) tuple.
    """
    # Check annotation-based suppression
    if resource_metadata:
        suppressed, reason = check_annotation_suppression(
            resource_metadata, finding.get('type', ''))
        if suppressed:
            logging.debug(f"Suppressed finding '{finding.get('type')}' on "
                          f"'{finding.get('namespace')}/{finding.get('name')}': {reason}")
            return True, reason

    # Check config-file rules
    suppressed, reason = check_config_suppression(finding, suppression_rules, resource_metadata)
    if suppressed:
        logging.debug(f"Suppressed finding '{finding.get('type')}' on "
                      f"'{finding.get('namespace')}/{finding.get('name')}': {reason}")
        return True, reason

    return False, ""


def filter_findings(
    findings: List[Dict[str, Any]],
    suppression_rules: List[Dict[str, Any]],
    resource_metadata_map: Optional[Dict[str, Dict[str, Any]]] = None,
    show_suppressed: bool = False,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Filter a list of findings through suppression rules.

    Args:
        findings: List of finding dicts.
        suppression_rules: Compiled suppression rules from config.
        resource_metadata_map: Optional dict mapping "namespace/name" -> metadata.
            Used for label-based suppression matching.
        show_suppressed: If True, include suppressed findings with status "Suppressed".

    Returns:
        (active_findings, suppressed_findings) tuple.
    """
    if not suppression_rules:
        return findings, []

    active = []
    suppressed = []

    for finding in findings:
        # Look up resource metadata if available
        metadata = None
        if resource_metadata_map:
            ns = finding.get('namespace', '')
            name = finding.get('name', '')
            # Try namespace/name key, then just name for cluster-scoped
            metadata = resource_metadata_map.get(f"{ns}/{name}")
            if metadata is None and ns == '(cluster)':
                metadata = resource_metadata_map.get(name)

        is_suppressed, reason = should_suppress(finding, suppression_rules, metadata)

        if is_suppressed:
            if show_suppressed:
                finding_copy = dict(finding)
                finding_copy['status'] = 'Suppressed'
                finding_copy['suppression_reason'] = reason
                suppressed.append(finding_copy)
            else:
                suppressed.append(finding)
        else:
            active.append(finding)

    if suppressed:
        logging.info(f"Suppressed {len(suppressed)} findings based on suppression rules.")

    return active, suppressed


def _rule_matches(
    rule: Dict[str, Any],
    finding: Dict[str, Any],
    resource_metadata: Optional[Dict[str, Any]] = None,
) -> bool:
    """Check if a single suppression rule matches a finding.

    All specified criteria in a rule must match (AND logic).

    Args:
        rule: Compiled suppression rule dict.
        finding: Finding dict.
        resource_metadata: Optional resource metadata for label matching.

    Returns:
        True if all criteria in the rule match.
    """
    # Check finding type
    if 'type' in rule:
        if finding.get('type') != rule['type']:
            return False

    # Check namespace
    if 'namespace' in rule:
        if finding.get('namespace') != rule['namespace']:
            return False

    # Check name (regex)
    if 'name_pattern' in rule:
        name = finding.get('name', '')
        if not rule['name_pattern'].search(name):
            return False

    # Check labels (requires resource metadata)
    if 'labels' in rule:
        if not resource_metadata:
            return False
        resource_labels = resource_metadata.get('labels', {})
        for label_key, label_value in rule['labels'].items():
            if resource_labels.get(label_key) != label_value:
                return False

    return True
