"""Finding data structures and management for EKS Scout."""
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any, Optional, Set
from eks_scout.config import get_config


@dataclass
class Finding:
    """
    Represents a single security finding.

    Attributes:
        severity: Severity level (Critical, High, Medium, Low, Informational)
        type: Finding name/title (e.g., "Privileged Container")
        namespace: Kubernetes namespace or "(cluster)" for cluster-scoped
        name: Resource name (e.g., "pod-name" or "pod-name/container-name")
        asset_type: Type of asset (e.g., "Pod", "Service", "EKS Cluster")
        details: Detailed description of the finding
        recommendation: Remediation guidance
        reference: CIS benchmark reference or best practice reference
        check_id: Unique check identifier (e.g., "k8s.pods.privileged")
    """
    severity: str
    type: str
    namespace: str
    name: str
    asset_type: str
    details: str
    recommendation: str
    reference: str
    check_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert finding to dictionary (for backwards compatibility and export).

        Returns:
            Dictionary representation of the finding
        """
        return asdict(self)

    def __hash__(self):
        """
        Generate hash for deduplication.

        Findings are considered duplicate if they have the same:
        - type (finding name)
        - namespace
        - name (resource name)
        """
        return hash((self.type, self.namespace, self.name))

    def __eq__(self, other):
        """Check equality for deduplication."""
        if not isinstance(other, Finding):
            return False
        return (self.type == other.type and
                self.namespace == other.namespace and
                self.name == other.name)


class FindingManager:
    """
    Manages collection, deduplication, and organization of security findings.

    Features:
        - Automatic deduplication
        - Severity override application
        - Finding statistics and filtering
    """

    def __init__(self):
        """Initialize finding manager."""
        self.findings: List[Finding] = []
        self._seen_findings: Set[Finding] = set()  # For deduplication

    def add_finding(
        self,
        severity: str,
        finding_type: str,
        details: str,
        recommendation: str,
        reference: str,
        namespace: str,
        name: str,
        asset_type: str = "Kubernetes Resource",
        check_id: Optional[str] = None
    ) -> bool:
        """
        Add a finding with optional severity override and automatic deduplication.

        Args:
            severity: Base severity level
            finding_type: Finding name/title
            details: Detailed description
            recommendation: Remediation guidance
            reference: CIS benchmark or best practice reference
            namespace: Kubernetes namespace or "(cluster)"
            name: Resource name
            asset_type: Type of asset (default: "Kubernetes Resource")
            check_id: Unique check identifier

        Returns:
            True if finding was added, False if duplicate
        """
        config = get_config()

        # Apply severity override if configured
        if check_id:
            severity = config.get_severity(check_id, severity)

        # Normalize namespace
        if not namespace:
            namespace = "(cluster)"

        # Create finding
        finding = Finding(
            severity=severity,
            type=finding_type,
            namespace=namespace,
            name=name,
            asset_type=asset_type,
            details=details,
            recommendation=recommendation,
            reference=reference,
            check_id=check_id
        )

        # Deduplication check
        if finding in self._seen_findings:
            return False

        # Add finding
        self._seen_findings.add(finding)
        self.findings.append(finding)
        return True

    def get_findings(self) -> List[Dict[str, Any]]:
        """
        Get all findings as list of dicts (backwards compatible format).

        Returns:
            List of finding dictionaries
        """
        return [f.to_dict() for f in self.findings]

    def get_finding_objects(self) -> List[Finding]:
        """
        Get all findings as Finding objects.

        Returns:
            List of Finding objects
        """
        return self.findings.copy()

    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """
        Get findings filtered by severity level.

        Args:
            severity: Severity level to filter by

        Returns:
            List of findings with matching severity
        """
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_namespace(self, namespace: str) -> List[Finding]:
        """
        Get findings for a specific namespace.

        Args:
            namespace: Namespace to filter by

        Returns:
            List of findings in the namespace
        """
        return [f for f in self.findings if f.namespace == namespace]

    def get_findings_by_check(self, check_id: str) -> List[Finding]:
        """
        Get findings from a specific check.

        Args:
            check_id: Check identifier

        Returns:
            List of findings from that check
        """
        return [f for f in self.findings if f.check_id == check_id]

    def get_severity_counts(self) -> Dict[str, int]:
        """
        Get count of findings by severity level.

        Returns:
            Dictionary mapping severity -> count
        """
        counts = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive finding statistics.

        Returns:
            Dictionary with statistics:
                - total: Total finding count
                - by_severity: Counts by severity level
                - by_asset_type: Counts by asset type
                - by_namespace: Counts by namespace
                - unique_checks: Number of unique checks that produced findings
        """
        stats = {
            "total": len(self.findings),
            "by_severity": self.get_severity_counts(),
            "by_asset_type": {},
            "by_namespace": {},
            "unique_checks": len(set(f.check_id for f in self.findings if f.check_id))
        }

        # Count by asset type
        for finding in self.findings:
            asset_type = finding.asset_type
            stats["by_asset_type"][asset_type] = stats["by_asset_type"].get(asset_type, 0) + 1

        # Count by namespace
        for finding in self.findings:
            ns = finding.namespace
            stats["by_namespace"][ns] = stats["by_namespace"].get(ns, 0) + 1

        return stats

    def clear(self):
        """Clear all findings."""
        self.findings = []
        self._seen_findings = set()

    def __len__(self):
        """Get number of findings."""
        return len(self.findings)

    def __iter__(self):
        """Iterate over findings."""
        return iter(self.findings)


# Backwards compatibility function for legacy code
def add_finding(findings_list: List[Dict], severity: str, finding_type: str,
                details: str, recommendation: str, reference: str,
                namespace: str, name: str, asset_type: str = "Kubernetes Resource",
                check_id: Optional[str] = None):
    """
    Legacy add_finding function for backwards compatibility.

    This function maintains compatibility with the old main.py inline code.

    Args:
        findings_list: List to append finding dictionary to
        severity: Severity level
        finding_type: Finding name
        details: Description
        recommendation: Remediation guidance
        reference: CIS reference
        namespace: Namespace or "(cluster)"
        name: Resource name
        asset_type: Asset type
        check_id: Unique check identifier for severity overrides
    """
    # Apply severity override if check_id is provided
    if check_id:
        config = get_config()
        severity = config.get_severity(check_id, severity)

    finding = Finding(
        severity=severity,
        type=finding_type,
        details=details,
        recommendation=recommendation,
        reference=reference,
        namespace=namespace if namespace else "(cluster)",
        name=name,
        asset_type=asset_type,
        check_id=check_id
    )
    findings_list.append(finding.to_dict())
