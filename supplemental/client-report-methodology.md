# AWS EKS Security Configuration Review — Methodology

## 1. Introduction

This document outlines the comprehensive methodology employed to assess the security posture of the AWS Elastic Kubernetes Service (EKS) environment. The review involved a detailed examination of the Kubernetes cluster configuration, its interaction with AWS services, and the security settings of deployed workloads. This was achieved through systematic interrogation of the Kubernetes API using `kubectl` commands and querying AWS service configurations via the AWS Command Line Interface (CLI), followed by careful analysis of the gathered data.

The primary objective was to identify security misconfigurations, deviations from established best practices, and potential vulnerabilities that could expose the environment to risk. The assessment was conducted using **passive, read-only operations only** — no changes were made to the cluster or AWS resources during the assessment.

The assessment encompassed the following key areas.

## 2. Detailed Methodology

### 2.1. EKS Cluster-Level Configuration Analysis

A thorough inspection of the core EKS cluster settings was performed. This involved:

* **API Server Endpoint Security:** The accessibility of the Kubernetes API server endpoint was carefully evaluated, including whether it was publicly exposed or restricted to private VPC access. For public endpoints, the configured IP address whitelisting (CIDR restrictions) was scrutinized.
* **Control Plane Logging:** The status of critical control plane logging (api, audit, authenticator, controllerManager, scheduler) was verified to ensure comprehensive audit trails are captured for security monitoring and incident response.
* **Secrets Encryption:** The configuration for envelope encryption of Kubernetes Secrets using AWS Key Management Service (KMS) was examined to confirm that sensitive data stored in `etcd` is appropriately protected at rest. Both the presence of encryption configuration and the explicit inclusion of the `secrets` resource type were verified.
* **Cluster IAM Role:** The IAM role assigned to the EKS cluster control plane was identified and noted for cross-referencing with IAM policy analysis.

### 2.2. EKS Nodegroup and Worker Node Security

The configuration of EKS nodegroups was reviewed to ensure worker nodes adhere to security best practices:

* **Remote Access Controls:** Settings related to SSH access to worker nodes were inspected, including the assignment of EC2 SSH keys and the use of source security groups to restrict access to authorized administrative networks. Nodegroups with SSH enabled but no source restriction were flagged as they allow SSH from any IP with the key.
* **Node IAM Role Policy Analysis:** The IAM roles assigned to worker nodegroups were identified and their attached policies were enumerated. Roles with overly broad managed policies (e.g., `AmazonS3FullAccess`, `SecretsManagerReadWrite`, `AdministratorAccess`) were flagged, as these permissions are inherited by all pods on the node unless IRSA is used.
* **Instance Metadata Service (IMDSv2):** Launch template configurations were examined for IMDSv2 enforcement (`HttpTokens: required`). When IMDSv1 remains accessible (`HttpTokens: optional`), pods with host network access or privileged mode can steal node IAM credentials via the EC2 metadata service — a well-documented cloud attack pattern (SCARLETEEL).

### 2.3. IAM Roles for Service Accounts (IRSA) Analysis

IAM roles associated with Kubernetes service accounts via IRSA annotations were subjected to focused analysis:

* **Trust Policy Validation:** OIDC trust policies were inspected for the presence of `:sub` conditions that restrict which service accounts can assume the role. Roles with only `:aud` conditions (or no conditions at all) allow any service account in the cluster to assume them.
* **Attached Policy Review:** Managed and inline policies attached to IRSA roles were enumerated. Roles with overly broad policies (e.g., `AdministratorAccess`) were flagged as they grant excessive AWS permissions to the associated pods.

### 2.4. Kubernetes Namespace Security and Governance

Each namespace within the cluster was methodically reviewed for security and resource governance controls:

* **Pod Security Admission (PSA):** Namespace labels were inspected to verify the application and enforcement level (e.g., `baseline`, `restricted`) of Pod Security Admission standards, which dictate baseline security requirements for pods.
* **Resource Quotas and Limit Ranges:** The presence of `ResourceQuota` objects (to cap overall resource consumption) and `LimitRange` objects (to define default container resource requests/limits) was checked in each namespace to prevent resource exhaustion and ensure workload stability.

### 2.5. Pod and Container Security Hardening

A granular analysis of pod specifications across all relevant namespaces was undertaken. This involved inspecting the YAML definitions of individual pods to identify insecure configurations within container settings:

* **Host Namespace Exposure:** Pods were examined for the use of host namespaces (`hostNetwork`, `hostPID`, `hostIPC`) that break container isolation and grant access to the underlying node's network stack, process table, or shared memory.
* **Host Filesystem Access:** `hostPath` volume mounts were identified, with particular attention to sensitive paths (`/`, `/etc`, `/var/run/docker.sock`, `/proc`) that could enable container escape or credential theft.
* **Privilege Levels:** Containers were checked for privileged mode (`securityContext.privileged: true`), which grants unrestricted host access equivalent to root on the node.
* **Linux Capabilities:** Container capability configurations were analyzed. Dangerous capabilities like `SYS_ADMIN`, `NET_ADMIN`, and `SYS_PTRACE` were flagged. Containers not dropping all capabilities (`drop: [ALL]`) were identified.
* **User Context:** The effective user ID of containers was assessed, specifically identifying containers running as root, explicitly allowed to run as root, or lacking `runAsNonRoot` enforcement.
* **Privilege Escalation:** Configurations allowing privilege escalation within containers (`allowPrivilegeEscalation` not set to `false`) were identified.
* **Seccomp Profiles:** Container seccomp profile configuration was checked. Containers without a profile or with `Unconfined` profiles lack syscall filtering, increasing the kernel attack surface.
* **Filesystem Security:** The root filesystem mount status was checked for containers not configured with a `readOnlyRootFilesystem`.
* **Resource Management:** Containers were inspected for the absence of CPU and memory resource limits, which can lead to resource contention or denial-of-service conditions.
* **Image Provenance:** Container image specifications were reviewed for the use of mutable tags like `:latest` and for images potentially sourced from unverified or non-standard registries.

### 2.6. Service Account Configuration Review

Service accounts in each namespace were examined, focusing on:

* **IAM Roles for Service Accounts (IRSA):** Annotations linking Kubernetes service accounts to AWS IAM roles were identified for subsequent IAM policy review.
* **Token Automounting:** The `automountServiceAccountToken` setting was checked, particularly for the `default` service account and other potentially widely used accounts, to minimize unnecessary exposure of API credentials to pods.

### 2.7. RBAC (Role-Based Access Control) Posture Assessment

A comprehensive review of Kubernetes RBAC settings was conducted by querying and analyzing all `Roles`, `ClusterRoles`, `RoleBindings`, and `ClusterRoleBindings`:

* **Highly Privileged Bindings:** Bindings granting `cluster-admin` or broad administrative roles to users, groups, or service accounts were identified and scrutinized.
* **Overly Permissive Role Definitions:** Role and ClusterRole definitions were inspected for rules containing wildcards (`*`) for verbs, resources, or API groups, or granting high-risk permissions such as `escalate`, `bind`, `impersonate`, `pods/exec`, or broad `secrets` access.
* **Sensitive Subject Bindings:** Bindings to sensitive system principals like `system:unauthenticated`, `system:authenticated`, or default service accounts in critical namespaces were carefully evaluated.
* **Default Service Account Bindings:** ClusterRoleBindings and RoleBindings involving `default` service accounts were flagged, as these grant permissions to any pod that does not specify an explicit service account.

### 2.8. Network Segmentation and Policies

The implementation and effectiveness of network segmentation were evaluated through an inspection of `NetworkPolicy` resources:

* **Default Network Stance:** Namespaces lacking any NetworkPolicies were identified, as this typically allows unrestricted pod-to-pod communication.
* **Permissive Ingress Rules:** Existing NetworkPolicies were reviewed for rules that permit overly broad ingress — allowing traffic from all sources, all pods, all namespaces, or from unrestricted IP CIDRs (e.g., `0.0.0.0/0`).
* **Permissive Egress Rules:** Egress rules were similarly evaluated for overly broad destination allowances that could facilitate data exfiltration.

### 2.9. Network Exposure of Services

The mechanisms by which applications are exposed both internally and externally were carefully examined:

* **Externally Exposed Services:** Kubernetes `Service` objects of `Type: LoadBalancer` were identified, as these result in the provisioning of external cloud load balancers.
* **Ingress Configuration:** `Ingress` resources were analyzed for secure configuration, including verifying that rules exposing applications over HTTP have corresponding TLS configurations to enforce HTTPS, and checking for the use of wildcard hosts (`*`) which can introduce routing ambiguities.

### 2.10. Configuration and Secret Management Practices

A review of how configuration data and secrets are managed was performed:

* **ConfigMap Data Scrutiny:** Keys within `ConfigMap` objects were inspected for common patterns (e.g., "password", "token", "key") that might indicate the insecure storage of sensitive information in ConfigMaps rather than Secrets.
* **Secret Key Analysis:** `Secret` objects were inspected for data keys with sensitive-looking names (passwords, tokens, API keys) to verify they are properly managed, rotated, and access-controlled via RBAC.

### 2.11. High-Risk Combination Detection

Beyond individual findings, the assessment included automated detection of **multi-finding attack chains** — cases where two or more findings on the same workload combine to create a risk greater than either finding alone. This covers 20 same-workload combinations including:

* **Container escape paths:** Privileged mode + hostPath, SYS_ADMIN + hostPath, etc.
* **Host isolation breakdowns:** Multiple host namespaces (network + PID + IPC), host namespaces + hostPath volumes.
* **Privilege amplifiers:** Root execution + host access, privilege escalation + host filesystem.

These combinations are reported with severity levels reflecting the combined risk, along with specific impact narratives and remediation guidance.

### 2.12. Cross-Scope Attack Chain Detection

The assessment also identified **infrastructure-to-workload attack chains** — cases where cluster-level weaknesses combine with pod-level findings to create cloud pivot paths. This covers 8 cross-scope combinations including:

* **IMDS credential theft:** IMDSv1 exposure + host network or privileged container = node IAM credential theft (SCARLETEEL attack pattern).
* **Overprivileged node role exploitation:** Broad node IAM role + container escape vectors = AWS account compromise.
* **Cluster takeover paths:** Public API endpoint + cluster-admin RBAC bindings = full control from the internet.
* **Infrastructure compound risks:** Unrestricted SSH + overprivileged node role, unencrypted secrets + sensitive data in secrets.

These cross-scope attack chains represent some of the highest-impact findings, as they map direct paths from container compromise to cloud account compromise.

## 3. Conclusion

This multi-faceted approach, involving detailed queries and careful analysis of the resulting data from both the AWS and Kubernetes control planes, aimed to provide a comprehensive understanding of the EKS environment's security configuration and identify areas for improvement. The combination of individual finding detection, same-workload attack chain analysis, and cross-scope infrastructure-to-workload mapping provides a thorough picture of both granular misconfigurations and systemic risk patterns.
