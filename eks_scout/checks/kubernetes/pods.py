"""Kubernetes pod and container security checks.

Reports findings at the workload level (Deployment, DaemonSet, StatefulSet)
using ownerReferences, not at the individual pod level. This eliminates
duplicate findings across pod replicas.
"""
import logging
import re
from collections import defaultdict

from eks_scout.config import (
    get_config, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    SEVERITY_LOW, SEVERITY_INFO
)
from eks_scout.core.findings import add_finding

CHECK_NAME = "k8s.pods"


def run(findings, resources, config=None):
    """Run pod and container security checks.

    Groups pods by their owning workload (Deployment, DaemonSet, StatefulSet)
    and reports one finding per workload instead of per pod.

    Args:
        findings: List to append findings to.
        resources: Dict containing 'pods'.
        config: Optional Config instance (uses global if not provided).
    """
    if config is None:
        config = get_config()

    pods = resources.get('pods', [])
    jobs = resources.get('jobs', [])
    cronjobs = resources.get('cronjobs', [])

    logging.info("Analyzing Pods...")
    sensitive_hostpaths = config.get_setting('sensitive_hostpaths',
                                             ['/', '/etc', '/var', '/usr', '/proc', '/root', '/var/run/docker.sock'])
    allowed_registries = config.get_setting('allowed_registries',
                                            ['amazonaws.com', 'docker.io', 'gcr.io', 'quay.io', 'ghcr.io', 'mcr.microsoft.com'])

    # Build lookup maps for Job→CronJob ownership chain
    jobs_by_name = {}
    for job in jobs:
        jmeta = job.get('metadata', {})
        jns = jmeta.get('namespace', '')
        jname = jmeta.get('name', '')
        if jname:
            jobs_by_name[f"{jns}/{jname}"] = job

    # Group pods by workload
    workloads = _group_pods_by_workload(pods, jobs_by_name)

    logging.info(f"Grouped {len(pods)} pods into {len(workloads)} workloads.")

    covered_cronjobs = set()
    for workload_key, workload_info in workloads.items():
        _check_workload(findings, workload_info, sensitive_hostpaths, allowed_registries, config)
        if workload_info['kind'] == 'CronJob':
            covered_cronjobs.add((workload_info['namespace'], workload_info['name']))

    # Analyze CronJob templates that haven't run yet (no pods observed)
    for cj in cronjobs:
        cj_meta = cj.get('metadata', {})
        cj_ns = cj_meta.get('namespace', '')
        cj_name = cj_meta.get('name', '')

        if (cj_ns, cj_name) in covered_cronjobs:
            continue

        pod_template = (cj.get('spec', {})
                          .get('jobTemplate', {})
                          .get('spec', {})
                          .get('template', {}))
        if not pod_template:
            continue

        synthetic_pod = {
            'metadata': {**pod_template.get('metadata', {}), 'namespace': cj_ns, 'name': cj_name},
            'spec': pod_template.get('spec', {}),
        }
        workload_info = {
            'kind': 'CronJob',
            'name': cj_name,
            'namespace': cj_ns,
            'pods': [synthetic_pod],
            'pod_names': [f"{cj_name} (template)"],
            'representative_pod': synthetic_pod,
        }
        _check_workload(findings, workload_info, sensitive_hostpaths, allowed_registries, config)


def _get_workload_identity(pod, jobs_by_name=None):
    """Determine the workload that owns a pod using ownerReferences.

    Follows the Job → CronJob ownership chain when jobs_by_name is provided.

    Returns:
        (workload_kind, workload_name, namespace) tuple.
        For pods owned by ReplicaSets, infers the Deployment name.
        For pods owned by Jobs owned by CronJobs, returns the CronJob identity.
        For standalone pods, returns ("Pod", pod_name, namespace).
    """
    metadata = pod.get('metadata', {})
    ns = metadata.get('namespace', '')
    pod_name = metadata.get('name', '')
    owner_refs = metadata.get('ownerReferences', [])

    if not owner_refs:
        return ("Pod", pod_name, ns)

    owner = owner_refs[0]  # Primary owner
    owner_kind = owner.get('kind', '')
    owner_name = owner.get('name', '')

    if owner_kind == 'ReplicaSet':
        # Infer Deployment name by stripping the ReplicaSet hash suffix
        # ReplicaSet names follow pattern: <deployment-name>-<hash>
        deploy_name = re.sub(r'-[a-z0-9]{5,10}$', '', owner_name)
        if deploy_name != owner_name:
            return ("Deployment", deploy_name, ns)
        # If regex didn't match, it might be a standalone ReplicaSet
        return ("ReplicaSet", owner_name, ns)

    if owner_kind == 'Job':
        # Follow Job → CronJob ownership chain
        if jobs_by_name:
            job = jobs_by_name.get(f"{ns}/{owner_name}")
            if job:
                job_owners = job.get('metadata', {}).get('ownerReferences', [])
                if job_owners and job_owners[0].get('kind') == 'CronJob':
                    return ("CronJob", job_owners[0].get('name', owner_name), ns)
        return ("Job", owner_name, ns)

    if owner_kind in ('DaemonSet', 'StatefulSet'):
        return (owner_kind, owner_name, ns)

    # Unknown owner kind — use it as-is
    return (owner_kind, owner_name, ns)


def _group_pods_by_workload(pods, jobs_by_name=None):
    """Group pods by their owning workload.

    Args:
        pods: List of pod dicts.
        jobs_by_name: Optional dict mapping "namespace/name" -> job dict for
                      following Job → CronJob ownership chains.

    Returns:
        Dict mapping (kind, name, namespace) -> {
            'kind': str,
            'name': str,
            'namespace': str,
            'pods': list of pod dicts,
            'pod_names': list of pod name strings,
            'representative_pod': first pod dict (for spec analysis),
        }
    """
    groups = defaultdict(lambda: {'pods': [], 'pod_names': []})

    for pod in pods:
        workload_key = _get_workload_identity(pod, jobs_by_name)
        kind, name, ns = workload_key

        group = groups[workload_key]
        group['kind'] = kind
        group['name'] = name
        group['namespace'] = ns
        group['pods'].append(pod)
        group['pod_names'].append(pod.get('metadata', {}).get('name', ''))

    # Set representative pod for each group
    for group in groups.values():
        group['representative_pod'] = group['pods'][0]

    return groups


def _workload_label(info):
    """Human-readable workload label for finding messages."""
    count = len(info['pods'])
    kind = info['kind']
    name = info['name']
    if count == 1 and kind == "Pod":
        return f"Pod '{name}'"
    return f"{kind} '{name}' ({count} pods)"


def _check_workload(findings, workload_info, sensitive_hostpaths, allowed_registries, config):
    """Run security checks against one workload group.

    Analyzes the representative pod's spec (all replicas share the same template).
    Reports findings with workload identity and pod count.
    """
    pod = workload_info['representative_pod']
    metadata = pod.get('metadata', {})
    spec = pod.get('spec', {})
    ns = workload_info['namespace']
    workload_name = workload_info['name']
    label = _workload_label(workload_info)
    annotations = metadata.get('annotations', {})

    # For the finding 'name' field, use workload identity
    finding_name = workload_name

    # IRSA Check
    iam_role_arn = annotations.get('eks.amazonaws.com/role-arn')
    if iam_role_arn:
        if "admin" in iam_role_arn.lower() or "*" in iam_role_arn:
            add_finding(findings, SEVERITY_HIGH, "Pod IRSA Role Potentially Overly Permissive",
                        f"{label} in namespace '{ns}' uses IAM role '{iam_role_arn}' which might have excessive permissions (contains 'admin' or '*').",
                        "Review and apply least privilege to the IAM role associated via IRSA.",
                        "AWS Best Practice", ns, finding_name, "Pod",
                        check_id="k8s.pods.irsa-overly-permissive")
        add_finding(findings, SEVERITY_INFO, "Pod Using IRSA",
                    f"{label} in namespace '{ns}' uses IAM role via IRSA: {iam_role_arn}",
                    "Ensure the associated IAM role follows the principle of least privilege.",
                    "AWS Best Practice", ns, finding_name, "Pod",
                    check_id="k8s.pods.irsa")

    # Host Network
    if spec.get('hostNetwork', False):
        add_finding(findings, SEVERITY_HIGH, "Pod Using Host Network",
                    f"{label} in namespace '{ns}' is configured with hostNetwork: true.",
                    "Avoid using hostNetwork. If required, isolate the node.",
                    "CIS 5.2.5", ns, finding_name, "Pod",
                    check_id="k8s.pods.host-network")

    # Host PID/IPC
    if spec.get('hostPID', False):
        add_finding(findings, SEVERITY_MEDIUM, "Pod Using Host PID Namespace",
                    f"{label} in namespace '{ns}' is configured with hostPID: true.",
                    "Avoid using hostPID unless essential.",
                    "CIS 5.2.3", ns, finding_name, "Pod",
                    check_id="k8s.pods.host-pid")
    if spec.get('hostIPC', False):
        add_finding(findings, SEVERITY_MEDIUM, "Pod Using Host IPC Namespace",
                    f"{label} in namespace '{ns}' is configured with hostIPC: true.",
                    "Avoid using hostIPC unless essential.",
                    "CIS 5.2.4", ns, finding_name, "Pod",
                    check_id="k8s.pods.host-ipc")

    # HostPath Volumes
    if spec.get('volumes'):
        for volume in spec.get('volumes', []):
            host_path = volume.get('hostPath')
            if host_path:
                path = host_path.get('path', '')
                severity = SEVERITY_MEDIUM
                details = f"{label} in namespace '{ns}' uses hostPath volume: '{path}'."
                if path in sensitive_hostpaths or path.startswith('/var/run'):
                    severity = SEVERITY_HIGH
                    details = f"{label} in namespace '{ns}' uses sensitive hostPath volume: '{path}'."

                add_finding(findings, severity, "Pod Using HostPath Volume",
                            details,
                            "Avoid hostPath volumes. If necessary, use readOnly mounts and specific paths. Consider alternatives like PVs.",
                            "CIS 5.2.12", ns, finding_name, "Pod",
                            check_id="k8s.pods.hostpath-volume")

    # Container checks
    containers = spec.get('containers', []) + spec.get('initContainers', [])
    for container in containers:
        _check_container(findings, container, spec, ns, finding_name, label,
                         allowed_registries, config)


def _check_container(findings, container, pod_spec, ns, workload_name, workload_label,
                     allowed_registries, config):
    """Run security checks on a single container within a workload."""
    c_name = container.get('name')
    full_name = f"{workload_name}/{c_name}"

    pod_sc = pod_spec.get('securityContext', {})
    c_sc = container.get('securityContext', {})

    # Privileged Container (container-level only field)
    if c_sc.get('privileged', False):
        add_finding(findings, SEVERITY_CRITICAL, "Privileged Container",
                    f"Container '{c_name}' in {workload_label} (namespace '{ns}') is running in privileged mode.",
                    "Do not run privileged containers. Refactor the application if possible.",
                    "CIS 5.2.2", ns, full_name, "Container",
                    check_id="k8s.pods.privileged")

    # Run as Root — check container-level first, fall back to pod-level
    run_as_non_root = c_sc.get('runAsNonRoot', pod_sc.get('runAsNonRoot'))
    run_as_user = c_sc.get('runAsUser', pod_sc.get('runAsUser'))

    if run_as_user == 0:
        add_finding(findings, SEVERITY_MEDIUM, "Container Running As Root",
                    f"Container '{c_name}' in {workload_label} (namespace '{ns}') is explicitly configured to run as root (runAsUser: 0).",
                    "Configure container's securityContext with runAsNonRoot: true and specify a runAsUser > 0.",
                    "CIS 5.2.7", ns, full_name, "Container",
                    check_id="k8s.pods.running-as-root")
    elif run_as_non_root is False:
        add_finding(findings, SEVERITY_MEDIUM, "Container Allowed to Run As Root",
                    f"Container '{c_name}' in {workload_label} (namespace '{ns}') is explicitly allowed to run as root (runAsNonRoot: false).",
                    "Set securityContext.runAsNonRoot: true.",
                    "CIS 5.2.7", ns, full_name, "Container",
                    check_id="k8s.pods.allowed-run-as-root")
    elif run_as_non_root is None and run_as_user is None:
        add_finding(findings, SEVERITY_LOW, "Container May Run As Root",
                    f"Container '{c_name}' in {workload_label} (namespace '{ns}') has no runAsNonRoot or runAsUser specified (default allows root). Image may run as root.",
                    "Explicitly set securityContext.runAsNonRoot: true and specify a runAsUser > 0.",
                    "CIS 5.2.7", ns, full_name, "Container",
                    check_id="k8s.pods.may-run-as-root")

    # Missing Resource Limits
    resources = container.get('resources', {})
    limits = resources.get('limits')
    if not limits or not limits.get('cpu') or not limits.get('memory'):
        add_finding(findings, SEVERITY_LOW, "Container Missing Resource Limits",
                    f"Container '{c_name}' in {workload_label} (namespace '{ns}') lacks CPU and/or memory limits.",
                    "Define CPU and memory limits for all containers.",
                    "Best Practice", ns, full_name, "Container",
                    check_id="k8s.pods.missing-resource-limits")

    # AllowPrivilegeEscalation (container-level only; default is true)
    allow_privilege_escalation = c_sc.get('allowPrivilegeEscalation', True)

    if allow_privilege_escalation:
        add_finding(findings, SEVERITY_MEDIUM, "Container Allows Privilege Escalation",
                    f"Container '{c_name}' in {workload_label} (namespace '{ns}') allows privilege escalation (allowPrivilegeEscalation is not set to false).",
                    "Set securityContext.allowPrivilegeEscalation: false.",
                    "CIS 5.2.6", ns, full_name, "Container",
                    check_id="k8s.pods.privilege-escalation")

    # Linux Capabilities
    capabilities = c_sc.get('capabilities', {})
    added_caps = [c.upper() for c in capabilities.get('add', [])]
    dropped_caps = [c.upper() for c in capabilities.get('drop', [])]

    if added_caps:
        sensitive_caps = config.get_setting('sensitive_capabilities',
                                            ['SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE',
                                             'DAC_READ_SEARCH', 'DAC_OVERRIDE', 'SYS_RAWIO', 'SYS_BOOT'])
        dangerous = [c for c in added_caps if c in sensitive_caps]
        if dangerous:
            severity = SEVERITY_HIGH if 'SYS_ADMIN' in dangerous else SEVERITY_MEDIUM
            add_finding(findings, severity, "Dangerous Capabilities Added",
                        f"Container '{c_name}' in {workload_label} (namespace '{ns}') adds dangerous Linux capabilities: {dangerous}."
                        + (" SYS_ADMIN is effectively equivalent to privileged mode." if 'SYS_ADMIN' in dangerous else ""),
                        "Remove dangerous capabilities from securityContext.capabilities.add. Use the minimum capabilities required.",
                        "CIS 5.2.9", ns, full_name, "Container",
                        check_id="k8s.pods.dangerous-capabilities")

    if 'ALL' not in dropped_caps:
        add_finding(findings, SEVERITY_LOW, "Capabilities Not Dropped",
                    f"Container '{c_name}' in {workload_label} (namespace '{ns}') does not drop all Linux capabilities (capabilities.drop does not include 'ALL').",
                    "Set securityContext.capabilities.drop: ['ALL'] and only add back the specific capabilities required.",
                    "CIS 5.2.10", ns, full_name, "Container",
                    check_id="k8s.pods.capabilities-not-dropped")

    # Seccomp Profile — container-level overrides pod-level
    c_seccomp = c_sc.get('seccompProfile')
    pod_seccomp = pod_sc.get('seccompProfile')
    effective_seccomp = c_seccomp if c_seccomp is not None else pod_seccomp

    if effective_seccomp:
        seccomp_type = effective_seccomp.get('type', '')
        if seccomp_type == 'Unconfined':
            add_finding(findings, SEVERITY_MEDIUM, "Seccomp Profile Unconfined",
                        f"Container '{c_name}' in {workload_label} (namespace '{ns}') has seccomp profile set to 'Unconfined', disabling syscall filtering.",
                        "Set securityContext.seccompProfile.type to 'RuntimeDefault' or 'Localhost' to restrict available syscalls.",
                        "CIS 5.6.2", ns, full_name, "Container",
                        check_id="k8s.pods.seccomp-unconfined")
    else:
        add_finding(findings, SEVERITY_LOW, "Seccomp Profile Not Set",
                    f"Container '{c_name}' in {workload_label} (namespace '{ns}') does not have a seccomp profile configured. The container runtime default may or may not apply.",
                    "Explicitly set securityContext.seccompProfile.type to 'RuntimeDefault' to ensure syscall filtering is active.",
                    "CIS 5.6.2", ns, full_name, "Container",
                    check_id="k8s.pods.seccomp-not-set")

    # ReadOnly Root Filesystem (container-level only; default is false)
    read_only_root_filesystem = c_sc.get('readOnlyRootFilesystem', False)

    if not read_only_root_filesystem:
        add_finding(findings, SEVERITY_LOW, "Container Root Filesystem Writable",
                    f"Container '{c_name}' in {workload_label} (namespace '{ns}') does not have a read-only root filesystem.",
                    "Set securityContext.readOnlyRootFilesystem: true and use volumeMounts for writable directories.",
                    "CIS 5.6.3", ns, full_name, "Container",
                    check_id="k8s.pods.writable-root-fs")

    # Image Checks
    image = container.get('image', '')
    if ':' not in image or ':latest' in image.lower():
        add_finding(findings, SEVERITY_LOW, "Image Uses Latest Tag",
                    f"Container '{c_name}' in {workload_label} (namespace '{ns}') uses image '{image}' potentially with 'latest' tag or no tag.",
                    "Use specific, immutable image tags (e.g., git SHA or semantic version) instead of 'latest'.",
                    "Best Practice", ns, full_name, "Container",
                    check_id="k8s.pods.latest-tag")

    registry = image.split('/')[0] if '/' in image else 'docker.io'
    if '.' in registry and not any(allowed in registry for allowed in allowed_registries):
        add_finding(findings, SEVERITY_LOW, "Image From Potentially Unapproved Registry",
                    f"Container '{c_name}' in {workload_label} (namespace '{ns}') uses image '{image}' from a potentially non-standard registry ('{registry}').",
                    "Ensure images are pulled only from approved, trusted registries.",
                    "Best Practice / Supply Chain", ns, full_name, "Container",
                    check_id="k8s.pods.unapproved-registry")
