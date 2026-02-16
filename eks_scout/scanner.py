"""Scanner orchestrator — fetches resources, runs checks, collects findings."""
import logging
from typing import Dict, Any, List, Optional

from eks_scout.config import Config, get_config, set_config
from eks_scout.core.command import run_cmd
from eks_scout.core.fetchers import KubernetesResourceFetcher, AWSResourceFetcher
from eks_scout.core.suppressions import filter_findings
from eks_scout.checks import get_all_checks
from eks_scout.pipeline.combo import analyze_combinations
from eks_scout.pipeline.cross_scope_combo import analyze_cross_scope_combinations


def check_dependencies(profile=None, context=None):
    """Verify kubectl and AWS CLI are available and working.

    Args:
        profile: AWS CLI profile name.
        context: kubectl context name.

    Returns:
        True if both dependencies are available, False otherwise.
    """
    logging.info("Checking dependencies...")

    kubectl_ok = run_cmd("kubectl version --client -o json",
                         context=context, check_rc=False, suppress_error=True)
    if kubectl_ok is None:
        logging.error(
            f"kubectl command not found or not working (context: {context or 'default'}). "
            "Please install and configure kubectl.")
        return False

    aws_ok = run_cmd("aws sts get-caller-identity",
                     profile=profile, check_rc=False, suppress_error=True)
    if aws_ok is None:
        logging.error(
            f"AWS CLI command not found or not working/authenticated "
            f"(profile: {profile or 'default'}). Please install/configure AWS CLI.")
        return False

    logging.info("Dependencies check passed.")
    return True


def fetch_resources(cluster_name, region, profile=None, context=None):
    """Fetch all AWS and Kubernetes resources.

    Args:
        cluster_name: EKS cluster name.
        region: AWS region.
        profile: AWS CLI profile name.
        context: kubectl context name.

    Returns:
        Dict of all fetched resources keyed by resource type.
    """
    logging.info("--- Fetching Kubernetes Resources (Parallel) ---")
    k8s_fetcher = KubernetesResourceFetcher(context=context)
    k8s_resources = k8s_fetcher.fetch_all()

    logging.info("--- Fetching AWS EKS Resources ---")
    aws_fetcher = AWSResourceFetcher(profile=profile, region=region)
    aws_resources = aws_fetcher.fetch_all(cluster_name)

    # Merge into single resource dict
    resources = {
        **k8s_resources,
        **aws_resources,
        'cluster_name': cluster_name,
        'region': region,
        'profile': profile,
    }
    return resources


def build_metadata_map(resources: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Build a lookup map of resource metadata for suppression matching.

    Maps "namespace/name" -> metadata dict for all fetched K8s resources.
    For pods, also indexes by workload identity (Deployment/DaemonSet/StatefulSet
    name inferred from ownerReferences) so that workload-level findings can
    look up annotations from the underlying pods.

    Args:
        resources: Dict of fetched resources from fetch_resources().

    Returns:
        Dict mapping resource key to metadata dict.
    """
    import re
    metadata_map = {}

    # K8s resource lists to index (except pods, handled separately)
    resource_keys = [
        'service_accounts', 'services', 'ingresses',
        'secrets', 'configmaps', 'namespaces',
        'roles', 'role_bindings', 'cluster_roles', 'cluster_role_bindings',
        'network_policies', 'resource_quotas', 'limit_ranges',
        'cronjobs', 'jobs',
    ]

    for key in resource_keys:
        items = resources.get(key, [])
        if not isinstance(items, list):
            continue
        for item in items:
            metadata = item.get('metadata', {})
            ns = metadata.get('namespace', '(cluster)')
            name = metadata.get('name', '')
            if name:
                lookup_key = f"{ns}/{name}" if ns != '(cluster)' else name
                metadata_map[lookup_key] = metadata

    # Index pods by both their actual name and their workload identity.
    # Pod findings use workload names (e.g., "my-deploy" not "my-deploy-abc123-xyz"),
    # so we need workload-keyed entries for suppression lookups to work.
    for pod in resources.get('pods', []):
        metadata = pod.get('metadata', {})
        ns = metadata.get('namespace', '(cluster)')
        pod_name = metadata.get('name', '')

        if pod_name:
            # Index by actual pod name
            pod_key = f"{ns}/{pod_name}" if ns != '(cluster)' else pod_name
            metadata_map[pod_key] = metadata

            # Also index by workload identity (inferred from ownerReferences)
            owner_refs = metadata.get('ownerReferences', [])
            if owner_refs:
                owner = owner_refs[0]
                owner_kind = owner.get('kind', '')
                owner_name = owner.get('name', '')

                if owner_kind == 'ReplicaSet':
                    deploy_name = re.sub(r'-[a-z0-9]{5,10}$', '', owner_name)
                    workload_name = deploy_name if deploy_name != owner_name else owner_name
                elif owner_kind in ('DaemonSet', 'StatefulSet', 'Job'):
                    workload_name = owner_name
                else:
                    workload_name = owner_name

                workload_key = f"{ns}/{workload_name}" if ns != '(cluster)' else workload_name
                # Only set if not already present (first pod wins — they share templates)
                if workload_key not in metadata_map:
                    metadata_map[workload_key] = metadata

    return metadata_map


def run_checks(resources, config=None):
    """Run all enabled security checks against fetched resources.

    Args:
        resources: Dict of fetched resources from fetch_resources().
        config: Optional Config instance (uses global if not provided).

    Returns:
        List of finding dicts.
    """
    if config is None:
        config = get_config()

    all_findings = []
    checks = get_all_checks()

    logging.info("--- Analyzing Resources ---")
    for check_id, check_module in checks:
        if not config.is_check_enabled(check_id):
            logging.debug(f"Check '{check_id}' is disabled, skipping.")
            continue

        try:
            check_module.run(all_findings, resources, config)
        except Exception as e:
            logging.error(f"Check '{check_id}' failed with error: {e}")
            logging.debug(f"Check error details:", exc_info=True)

    return all_findings


def scan(cluster_name, region, profile=None, context=None, config_file=None,
         show_suppressed=False):
    """Run a full security scan.

    This is the main entry point for programmatic usage.

    Args:
        cluster_name: EKS cluster name.
        region: AWS region.
        profile: AWS CLI profile name.
        context: kubectl context name.
        config_file: Path to configuration file.
        show_suppressed: If True, include suppressed findings in results.

    Returns:
        ScanResult with active findings, suppressed findings, and resources.
        Returns None if dependencies are not met.
    """
    # Load configuration
    config = Config(config_file) if config_file else Config()
    set_config(config)

    # Check dependencies
    if not check_dependencies(profile=profile, context=context):
        return None

    # Fetch resources
    resources = fetch_resources(cluster_name, region, profile=profile, context=context)

    # Run checks
    all_findings = run_checks(resources, config)

    # Apply suppressions
    suppression_rules = config.get_suppressions()
    metadata_map = build_metadata_map(resources) if suppression_rules else None

    active_findings, suppressed_findings = filter_findings(
        all_findings,
        suppression_rules,
        resource_metadata_map=metadata_map,
        show_suppressed=show_suppressed,
    )

    # Run combo analysis on active findings
    logging.info("--- Analyzing Finding Combinations ---")
    custom_combos = config.get_setting('custom_combinations', None)
    combo_results = analyze_combinations(active_findings, custom_combinations=custom_combos)
    cross_scope_results = analyze_cross_scope_combinations(active_findings)
    combo_results = combo_results + cross_scope_results

    return ScanResult(
        findings=active_findings,
        suppressed=suppressed_findings,
        resources=resources,
        show_suppressed=show_suppressed,
        combos=combo_results,
    )


class ScanResult:
    """Container for scan results."""

    def __init__(self, findings, suppressed, resources, show_suppressed=False,
                 combos=None):
        self.findings = findings
        self.suppressed = suppressed
        self.resources = resources
        self.show_suppressed = show_suppressed
        self.combos = combos or []

    @property
    def all_findings(self):
        """All findings including suppressed (if show_suppressed is True)."""
        if self.show_suppressed:
            return self.findings + self.suppressed
        return self.findings

    @property
    def total_count(self):
        return len(self.findings)

    @property
    def suppressed_count(self):
        return len(self.suppressed)

    @property
    def combo_count(self):
        return len(self.combos)

    @property
    def combo_workload_count(self):
        """Number of unique workloads with high-risk combinations."""
        return len({c['workload_key'] for c in self.combos})
