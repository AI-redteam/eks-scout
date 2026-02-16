"""Resource fetching abstraction layer with parallel execution support."""
import json
import logging
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from eks_scout.core.command import run_command


class KubernetesResourceFetcher:
    """
    Fetches Kubernetes resources via kubectl with parallel execution support.

    Uses ThreadPoolExecutor to fetch multiple resource types concurrently,
    reducing total fetch time significantly (e.g., from 30s to 10s).
    """

    def __init__(self, context: Optional[str] = None, max_workers: int = 10):
        """
        Initialize Kubernetes resource fetcher.

        Args:
            context: kubectl context to use
            max_workers: Maximum number of parallel fetch operations (default: 10)
        """
        self.context = context
        self.max_workers = max_workers

    def fetch_all(self) -> Dict[str, Any]:
        """
        Fetch all required Kubernetes resources in parallel.

        Returns:
            Dictionary of fetched resources:
                - namespaces: List of namespace objects
                - pods: List of pod objects (all namespaces)
                - services: List of service objects
                - network_policies: List of NetworkPolicy objects
                - network_policies_by_ns: Dict mapping namespace -> policies
                - ... (all other resource types)
        """
        logging.info("Fetching Kubernetes resources in parallel...")

        # Define all resources to fetch
        fetch_tasks = [
            ("namespaces", ["get", "namespaces", "-o", "json"], False),
            ("pods", ["get", "pods", "--all-namespaces", "-o", "json"], False),
            ("service_accounts", ["get", "serviceaccounts", "--all-namespaces", "-o", "json"], False),
            ("roles", ["get", "roles", "--all-namespaces", "-o", "json"], False),
            ("role_bindings", ["get", "rolebindings", "--all-namespaces", "-o", "json"], False),
            ("cluster_roles", ["get", "clusterroles", "-o", "json"], False),
            ("cluster_role_bindings", ["get", "clusterrolebindings", "-o", "json"], False),
            ("network_policies", ["get", "networkpolicies", "--all-namespaces", "-o", "json"], False),
            ("services", ["get", "services", "--all-namespaces", "-o", "json"], False),
            ("ingresses", ["get", "ingresses", "--all-namespaces", "-o", "json"], False),
            ("secrets", ["get", "secrets", "--all-namespaces", "-o", "json"], False),
            ("configmaps", ["get", "configmaps", "--all-namespaces", "-o", "json"], False),
            ("cronjobs", ["get", "cronjobs", "--all-namespaces", "-o", "json"], False),
            ("jobs", ["get", "jobs", "--all-namespaces", "-o", "json"], False),
            ("resource_quotas", ["get", "resourcequotas", "--all-namespaces", "-o", "json"], False),
            ("limit_ranges", ["get", "limitranges", "--all-namespaces", "-o", "json"], False),
        ]

        # Fetch resources in parallel
        resources = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_resource = {
                executor.submit(self._fetch_resource, name, args): name
                for name, args, _ in fetch_tasks
            }

            # Collect results as they complete
            for future in as_completed(future_to_resource):
                resource_name = future_to_resource[future]
                try:
                    resources[resource_name] = future.result()
                    logging.debug(f"Fetched {resource_name}: {len(resources[resource_name])} items")
                except Exception as e:
                    logging.error(f"Failed to fetch {resource_name}: {e}")
                    resources[resource_name] = []

        # Post-process: organize network policies by namespace
        resources["network_policies_by_ns"] = self._organize_policies_by_namespace(
            resources.get("network_policies", [])
        )

        logging.info(f"Kubernetes resource fetch complete. Retrieved {len(resources)} resource types.")
        return resources

    def _fetch_resource(self, resource_name: str, args: List[str]) -> List[Dict]:
        """
        Fetch a single Kubernetes resource type.

        Args:
            resource_name: Human-readable resource name (for logging)
            args: kubectl arguments

        Returns:
            List of resource objects
        """
        output = run_command(
            "kubectl",
            args,
            context=self.context,
            suppress_error=True
        )

        if not output:
            logging.warning(f"Could not retrieve {resource_name}")
            return []

        try:
            data = json.loads(output)
            return data.get('items', [])
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse JSON for {resource_name}: {e}")
            return []

    def _organize_policies_by_namespace(self, policies: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Organize NetworkPolicies by namespace for easier lookup.

        Args:
            policies: List of NetworkPolicy objects

        Returns:
            Dictionary mapping namespace -> list of policies
        """
        by_ns = {}
        for policy in policies:
            ns = policy.get('metadata', {}).get('namespace')
            if ns:
                if ns not in by_ns:
                    by_ns[ns] = []
                by_ns[ns].append(policy)
        return by_ns


class AWSResourceFetcher:
    """
    Fetches AWS resources via AWS CLI with parallel execution support.

    Uses ThreadPoolExecutor to fetch EKS cluster info and nodegroups concurrently.
    """

    def __init__(self, profile: Optional[str] = None, region: Optional[str] = None, max_workers: int = 5):
        """
        Initialize AWS resource fetcher.

        Args:
            profile: AWS CLI profile to use
            region: AWS region
            max_workers: Maximum number of parallel fetch operations (default: 5)
        """
        self.profile = profile
        self.region = region
        self.max_workers = max_workers

    def fetch_all(self, cluster_name: str) -> Dict[str, Any]:
        """
        Fetch all required AWS resources.

        Args:
            cluster_name: EKS cluster name

        Returns:
            Dictionary of fetched AWS resources:
                - cluster_info: EKS cluster description
                - nodegroups: List of managed nodegroup descriptions
        """
        logging.info("Fetching AWS EKS resources...")

        resources = {}

        # Fetch cluster info first (needed for other operations)
        resources["cluster_info"] = self._fetch_cluster_info(cluster_name)

        if not resources["cluster_info"]:
            logging.error("Failed to fetch cluster info - cannot proceed with AWS resource fetching")
            resources["nodegroups"] = []
            return resources

        # Fetch nodegroups
        resources["nodegroups"] = self._fetch_nodegroups(cluster_name)

        logging.info(f"AWS resource fetch complete. Cluster: {cluster_name}, Nodegroups: {len(resources['nodegroups'])}")
        return resources

    def _fetch_cluster_info(self, cluster_name: str) -> Optional[Dict]:
        """
        Fetch EKS cluster information.

        Args:
            cluster_name: EKS cluster name

        Returns:
            Cluster description dictionary or None if failed
        """
        output = run_command(
            "aws",
            ["eks", "describe-cluster", "--name", cluster_name,
             "--region", self.region, "--output", "json"],
            profile=self.profile,
            suppress_error=True
        )

        if not output:
            logging.error(f"Failed to describe EKS cluster '{cluster_name}'")
            return None

        try:
            data = json.loads(output)
            return data.get('cluster')
        except json.JSONDecodeError:
            logging.error("Failed to parse cluster info JSON")
            return None

    def _fetch_nodegroups(self, cluster_name: str) -> List[Dict]:
        """
        Fetch EKS managed nodegroups in parallel.

        Args:
            cluster_name: EKS cluster name

        Returns:
            List of nodegroup descriptions
        """
        # First, list all nodegroups
        output_list = run_command(
            "aws",
            ["eks", "list-nodegroups", "--cluster-name", cluster_name,
             "--region", self.region, "--output", "json"],
            profile=self.profile,
            suppress_error=True
        )

        if not output_list:
            logging.info("No managed nodegroups found or permission denied")
            return []

        try:
            data_list = json.loads(output_list)
            ng_names = data_list.get('nodegroups', [])
        except json.JSONDecodeError:
            logging.error("Failed to parse nodegroup list JSON")
            return []

        if not ng_names:
            logging.info("No managed nodegroups in cluster")
            return []

        # Fetch details for each nodegroup in parallel
        nodegroups = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ng = {
                executor.submit(self._fetch_nodegroup_details, cluster_name, ng_name): ng_name
                for ng_name in ng_names
            }

            for future in as_completed(future_to_ng):
                ng_name = future_to_ng[future]
                try:
                    ng_details = future.result()
                    if ng_details:
                        nodegroups.append(ng_details)
                except Exception as e:
                    logging.error(f"Failed to fetch nodegroup {ng_name}: {e}")

        return nodegroups

    def _fetch_nodegroup_details(self, cluster_name: str, ng_name: str) -> Optional[Dict]:
        """
        Fetch details for a single nodegroup.

        Args:
            cluster_name: EKS cluster name
            ng_name: Nodegroup name

        Returns:
            Nodegroup description or None if failed
        """
        output = run_command(
            "aws",
            ["eks", "describe-nodegroup", "--cluster-name", cluster_name,
             "--nodegroup-name", ng_name, "--region", self.region,
             "--output", "json"],
            profile=self.profile,
            suppress_error=True
        )

        if not output:
            logging.warning(f"Could not describe nodegroup '{ng_name}'")
            return None

        try:
            data = json.loads(output)
            return data.get('nodegroup')
        except json.JSONDecodeError:
            logging.warning(f"Failed to parse nodegroup {ng_name} JSON")
            return None


# Backwards compatibility functions for legacy code
def get_k8s_resources(resource_type: str, context: Optional[str] = None,
                      namespace: Optional[str] = None, use_all_namespaces: bool = False) -> List[Dict]:
    """
    Legacy function for fetching Kubernetes resources.

    This maintains compatibility with the old main.py inline code.

    Args:
        resource_type: Resource type (e.g., "pods", "services")
        context: kubectl context
        namespace: Specific namespace (optional)
        use_all_namespaces: Fetch from all namespaces

    Returns:
        List of resource objects
    """
    args = ["get", resource_type, "-o", "json"]

    if namespace:
        args.extend(["-n", namespace])
    elif use_all_namespaces:
        args.append("--all-namespaces")

    output = run_command("kubectl", args, context=context, suppress_error=True)

    if not output:
        logging.warning(f"Could not retrieve {resource_type}")
        return []

    try:
        data = json.loads(output)
        return data.get('items', [])
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse JSON for {resource_type}: {e}")
        return []
