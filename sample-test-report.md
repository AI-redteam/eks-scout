# EKS Security Configuration Review — Findings Report

**Cluster:** test-cluster  
**Generated:** 2026-02-16 09:49:18  
**Source:** `eks_findings_plextrac.csv`  
**Tool:** EKS Scout v2 by Ben Stevens

## Executive Summary

EKS Scout identified **189 findings** across **7 namespaces** and cluster-level resources, spanning **11 assessment categories**.

| Severity | Count |
|----------|------:|
| Critical | 4 |
| High | 15 |
| Medium | 116 |
| Low | 47 |
| Informational | 7 |
| **Total** | **189** |

> **19 findings rated Critical or High** require priority attention. These represent configurations that could directly enable container escape, credential theft, or unauthorized access to AWS resources.

## High-Risk Attack Chains

Beyond individual findings, **52 high-risk attack chains** were identified across **5 workloads** where multiple findings combine to create risks greater than any single finding alone.

> **19 Critical attack chains** represent direct paths to node compromise, cloud credential theft, or AWS account takeover.

| # | Severity | Attack Chain | Affected Workload | Impact |
|--:|----------|-------------|-------------------|--------|
| 1 | Critical | SYS_ADMIN Capability with Host Network Access | `insecure-app/net-debug` | SYS_ADMIN + host network = full node compromise via privilege and network fronts. |
| 2 | Critical | IMDS Credential Theft via Host Network | `insecure-app/net-debug` | Host network + IMDSv1 = steal node IAM creds via metadata service (SCARLETEEL). |
| 3 | Critical | Privileged Container with Host Filesystem Access | `insecure-app/vulnerable-app` | Privileged mode + host path access = direct container escape and host compromise. |
| 4 | Critical | Privileged Container with Host Network Access | `insecure-app/vulnerable-app` | Privileged + host network = full control of node network stack, traffic sniffing, NP bypass. |
| 5 | Critical | IMDS Credential Theft via Host Network | `insecure-app/vulnerable-app` | Host network + IMDSv1 = steal node IAM creds via metadata service (SCARLETEEL). |
| 6 | Critical | IMDS Credential Theft via Privileged Container | `insecure-app/vulnerable-app` | Privileged + IMDSv1 = network namespace manipulation to reach IMDS, steal node IAM creds. |
| 7 | Critical | Overprivileged Node Role with Container Escape | `insecure-app/vulnerable-app` | Privileged container escape + broad node IAM role = AWS account compromise. |
| 8 | Critical | Privileged Container with Host Filesystem Access | `kube-system/aws-node` | Privileged mode + host path access = direct container escape and host compromise. |
| 9 | Critical | Privileged Container with Host Network Access | `kube-system/aws-node` | Privileged + host network = full control of node network stack, traffic sniffing, NP bypass. |
| 10 | Critical | SYS_ADMIN Capability with Host Filesystem Access | `kube-system/aws-node` | SYS_ADMIN + host path = container escape via mount manipulation. |
| 11 | Critical | SYS_ADMIN Capability with Host Network Access | `kube-system/aws-node` | SYS_ADMIN + host network = full node compromise via privilege and network fronts. |
| 12 | Critical | IMDS Credential Theft via Host Network | `kube-system/aws-node` | Host network + IMDSv1 = steal node IAM creds via metadata service (SCARLETEEL). |
| 13 | Critical | IMDS Credential Theft via Privileged Container | `kube-system/aws-node` | Privileged + IMDSv1 = network namespace manipulation to reach IMDS, steal node IAM creds. |
| 14 | Critical | Overprivileged Node Role with Container Escape | `kube-system/aws-node` | Privileged container escape + broad node IAM role = AWS account compromise. |
| 15 | Critical | Privileged Container with Host Filesystem Access | `kube-system/kube-proxy` | Privileged mode + host path access = direct container escape and host compromise. |
| 16 | Critical | Privileged Container with Host Network Access | `kube-system/kube-proxy` | Privileged + host network = full control of node network stack, traffic sniffing, NP bypass. |
| 17 | Critical | IMDS Credential Theft via Host Network | `kube-system/kube-proxy` | Host network + IMDSv1 = steal node IAM creds via metadata service (SCARLETEEL). |
| 18 | Critical | IMDS Credential Theft via Privileged Container | `kube-system/kube-proxy` | Privileged + IMDSv1 = network namespace manipulation to reach IMDS, steal node IAM creds. |
| 19 | Critical | Overprivileged Node Role with Container Escape | `kube-system/kube-proxy` | Privileged container escape + broad node IAM role = AWS account compromise. |
| 20 | High | Root Container with Host Network Access | `insecure-app/net-debug` | Root + host network = node network manipulation, traffic sniffing, NP bypass. |
| 21 | High | Overprivileged Node Role with Host Network Access | `insecure-app/net-debug` | Host network + IMDS + broad node role = AWS pivot via metadata credential theft. |
| 22 | High | Root Container with Host Filesystem Access | `insecure-app/vulnerable-app` | Root + hostPath = direct manipulation of host files, credential theft, container escape. |
| 23 | High | Root Container with Host Network Access | `insecure-app/vulnerable-app` | Root + host network = node network manipulation, traffic sniffing, NP bypass. |
| 24 | High | Root Container with Host PID Visibility | `insecure-app/vulnerable-app` | Root + host PID = interact with all host processes, information disclosure. |
| 25 | High | Multiple Host Namespace Breakouts | `insecure-app/vulnerable-app` | Host network + host PID = significantly reduced container isolation. |
| 26 | High | Host Network with Host Filesystem Access | `insecure-app/vulnerable-app` | Reduced isolation on both network and filesystem fronts. |
| 27 | High | Host PID Visibility with Host Filesystem Access | `insecure-app/vulnerable-app` | Host PID + host filesystem = information disclosure and container escape paths. |
| 28 | High | Host Filesystem Access with Privilege Escalation | `insecure-app/vulnerable-app` | HostPath + privilege escalation = escalate then manipulate host resources. |
| 29 | High | Overprivileged Node Role with Host Filesystem Access | `insecure-app/vulnerable-app` | Read node IAM creds from filesystem + broad role = cloud resource abuse. |
| 30 | High | Overprivileged Node Role with Host Network Access | `insecure-app/vulnerable-app` | Host network + IMDS + broad node role = AWS pivot via metadata credential theft. |
| 31 | High | Root Container with Host Filesystem Access | `kube-system/aws-node` | Root + hostPath = direct manipulation of host files, credential theft, container escape. |
| 32 | High | Root Container with Host Network Access | `kube-system/aws-node` | Root + host network = node network manipulation, traffic sniffing, NP bypass. |
| 33 | High | Host Network with Host Filesystem Access | `kube-system/aws-node` | Reduced isolation on both network and filesystem fronts. |
| 34 | High | Host Filesystem Access with Privilege Escalation | `kube-system/aws-node` | HostPath + privilege escalation = escalate then manipulate host resources. |
| 35 | High | Overprivileged Node Role with Host Filesystem Access | `kube-system/aws-node` | Read node IAM creds from filesystem + broad role = cloud resource abuse. |
| 36 | High | Overprivileged Node Role with Host Network Access | `kube-system/aws-node` | Host network + IMDS + broad node role = AWS pivot via metadata credential theft. |
| 37 | High | Root Container with Host Filesystem Access | `kube-system/kube-proxy` | Root + hostPath = direct manipulation of host files, credential theft, container escape. |
| 38 | High | Root Container with Host Network Access | `kube-system/kube-proxy` | Root + host network = node network manipulation, traffic sniffing, NP bypass. |
| 39 | High | Host Network with Host Filesystem Access | `kube-system/kube-proxy` | Reduced isolation on both network and filesystem fronts. |
| 40 | High | Host Filesystem Access with Privilege Escalation | `kube-system/kube-proxy` | HostPath + privilege escalation = escalate then manipulate host resources. |
| 41 | High | Overprivileged Node Role with Host Filesystem Access | `kube-system/kube-proxy` | Read node IAM creds from filesystem + broad role = cloud resource abuse. |
| 42 | High | Overprivileged Node Role with Host Network Access | `kube-system/kube-proxy` | Host network + IMDS + broad node role = AWS pivot via metadata credential theft. |
| 43 | Medium | Root Container with Privilege Escalation Allowed | `insecure-app/insecure-cronjob` | Root + privilege escalation = SUID/kernel exploit enablement. |
| 44 | Medium | Root Container with Writable Filesystem | `insecure-app/insecure-cronjob` | Root + writable filesystem = persistence, tooling install, behavior modification. |
| 45 | Medium | Root Container with Privilege Escalation Allowed | `insecure-app/net-debug` | Root + privilege escalation = SUID/kernel exploit enablement. |
| 46 | Medium | Root Container with Writable Filesystem | `insecure-app/net-debug` | Root + writable filesystem = persistence, tooling install, behavior modification. |
| 47 | Medium | Root Container with Privilege Escalation Allowed | `insecure-app/vulnerable-app` | Root + privilege escalation = SUID/kernel exploit enablement. |
| 48 | Medium | Root Container with Writable Filesystem | `insecure-app/vulnerable-app` | Root + writable filesystem = persistence, tooling install, behavior modification. |
| 49 | Medium | Root Container with Privilege Escalation Allowed | `kube-system/aws-node` | Root + privilege escalation = SUID/kernel exploit enablement. |
| 50 | Medium | Root Container with Writable Filesystem | `kube-system/aws-node` | Root + writable filesystem = persistence, tooling install, behavior modification. |
| 51 | Medium | Root Container with Privilege Escalation Allowed | `kube-system/kube-proxy` | Root + privilege escalation = SUID/kernel exploit enablement. |
| 52 | Medium | Root Container with Writable Filesystem | `kube-system/kube-proxy` | Root + writable filesystem = persistence, tooling install, behavior modification. |

**Same-workload chains (35):** Multiple findings on the same pod combine to create container escape, privilege escalation, or host compromise paths.

**Cross-scope chains (17):** Cluster-level infrastructure weaknesses combine with pod-level findings to create cloud pivot paths (e.g., SCARLETEEL: host network + IMDSv1 = AWS credential theft).

## Scope of Assessment

The following assessment areas were evaluated using passive, read-only inspection of the Kubernetes API and AWS control plane. No changes were made to the cluster during the assessment.

| # | Category | Findings |
|--:|----------|-------:|
| 1 | [EKS Cluster Configuration](#eks-cluster-configuration) | 5 |
| 2 | [EKS Nodegroup Security](#eks-nodegroup-security) | 6 |
| 3 | [IAM Role Analysis](#iam-role-analysis) | 2 |
| 4 | [Namespace Governance](#namespace-governance) | 6 |
| 5 | [Pod & Container Security](#pod-and-container-security) | 70 |
| 6 | [Service Accounts](#service-accounts) | 44 |
| 7 | [RBAC Configuration](#rbac-configuration) | 45 |
| 8 | [Network Policies](#network-policies) | 4 |
| 9 | [Network Exposure](#network-exposure) | 2 |
| 10 | [Secrets & ConfigMaps](#secrets-and-configmaps) | 2 |
| 11 | [Pod Security Admission](#pod-security-admission) | 3 |

---

## Detailed Findings by Category

### <a name="eks-cluster-configuration"></a>EKS Cluster Configuration

*The EKS control plane configuration was reviewed for API server endpoint exposure, control plane audit logging, and secrets-at-rest encryption. Misconfigurations at this level affect the entire cluster's security posture.*

**5 findings** — 1 Medium, 1 Low, 3 Informational

#### EKS Control Plane Logging Disabled

**Severity:** Medium | **Instances:** 1

**Description:** The EKS cluster does not have all recommended control plane log types enabled. Missing: authenticator, controllerManager, scheduler. This hinders security auditing, incident response, and operational troubleshooting.

**Recommendation:** Enable all recommended control plane log types (api, audit, authenticator, controllerManager, scheduler) in the cluster's logging configuration to ensure comprehensive visibility into control plane activities.

**Reference:** CIS EKS 2.1.1

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `eks-enterprise-lab` | Medium |

#### EKS Public API Endpoint Access Enabled

**Severity:** Low | **Instances:** 1

**Description:** The EKS cluster API endpoint is publicly accessible from specific CIDRs: ['203.0.113.50/32'].

**Recommendation:** Ensure the allowed CIDRs are necessary, restricted to the minimum required ranges, and regularly reviewed. Prefer using the private endpoint ('endpointPrivateAccess: true') where possible.

**Reference:** CIS EKS 5.4.1

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `eks-enterprise-lab` | Low |

#### EKS Cluster Version

**Severity:** Informational | **Instances:** 1

**Description:** The EKS cluster is running Kubernetes version '1.29' and EKS platform version 'eks.61'.

**Recommendation:** Ensure the Kubernetes version is supported and patched. Regularly review EKS platform version updates and plan upgrades before end-of-support.

**Reference:** AWS Best Practice / Version Management

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `eks-enterprise-lab` | Informational |

#### EKS Secrets Encryption Enabled

**Severity:** Informational | **Instances:** 1

**Description:** The EKS cluster has envelope encryption enabled for secrets using KMS key: arn:aws:kms:us-east-1:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.

**Recommendation:** Ensure the KMS key policy follows the principle of least privilege and that key rotation is considered.

**Reference:** CIS EKS 5.3.1

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `eks-enterprise-lab` | Informational |

#### EKS Cluster IAM Role Identified

**Severity:** Informational | **Instances:** 1

**Description:** The EKS cluster uses IAM role: eks-enterprise-lab-cluster-20260216024953786600000003 (arn:aws:iam::123456789012:role/eks-enterprise-lab-cluster-20260216024953786600000003).

**Recommendation:** Review the policies attached to this role (e.g., AmazonEKSClusterPolicy). Ensure they are not overly permissive and adhere to least privilege. Consider deeper analysis if IAM permissions allow.

**Reference:** AWS Best Practice / IAM

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `eks-enterprise-lab` | Informational |

---

### <a name="eks-nodegroup-security"></a>EKS Nodegroup Security

*Worker node configurations were assessed including SSH access controls, Instance Metadata Service (IMDS) enforcement, and node IAM role permissions. Weaknesses here can enable lateral movement from compromised pods to the underlying EC2 infrastructure and AWS account.*

**6 findings** — 1 High, 2 Medium, 3 Informational

#### IMDSv2 Not Enforced

**Severity:** High | **Instances:** 1

**Description:** Nodegroups launch template has HttpTokens='optional'. IMDSv1 is accessible, enabling SSRF-based credential theft from pods.

**Recommendation:** Update the launch template to set MetadataOptions.HttpTokens to 'required' to enforce IMDSv2.

**Reference:** AWS Best Practice

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `eks-enterprise-lab/main-20260216030203877900000024` | High |

#### Node IAM Role Has Overly Broad Policy

**Severity:** Medium | **Instances:** 2

**Description:** Nodegroups node role has 'SecretsManagerReadWrite' attached. This grants excessive permissions to all pods on these nodes (unless IRSA is used).

**Recommendation:** Remove 'SecretsManagerReadWrite' from the node role and use IRSA (IAM Roles for Service Accounts) to grant specific permissions to individual workloads.

**Reference:** AWS Best Practice / Least Privilege

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `eks-enterprise-lab/main-20260216030203877900000024` | Medium |
| `eks-enterprise-lab/main-20260216030203877900000024` | Medium |

#### Nodegroup Configuration Info

**Severity:** Informational | **Instances:** 1

**Description:** Nodegroup 'main-20260216030203877900000024': AMI Type 'AL2_x86_64', Version '1.29.15-20251209', Instances 't3.medium', Node Role 'main-eks-node-group-20260216024953786500000001'.

**Recommendation:** Informational finding detailing the nodegroup configuration.

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `eks-enterprise-lab/main-20260216030203877900000024` | Informational |

#### Nodegroup SSH Access Disabled

**Severity:** Informational | **Instances:** 1

**Description:** Nodegroups does not have EC2 SSH key configured in its remote access settings.

**Recommendation:** Direct SSH access to nodes via the EKS nodegroup configuration is disabled. Verify launch template overrides if applicable.

**Reference:** CIS EKS 5.4.3

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `eks-enterprise-lab/main-20260216030203877900000024` | Informational |

#### Nodegroup IAM Role Identified

**Severity:** Informational | **Instances:** 1

**Description:** Nodegroups uses Node IAM role: main-eks-node-group-20260216024953786500000001 (arn:aws:iam::123456789012:role/main-eks-node-group-20260216024953786500000001).

**Recommendation:** Review policies attached (e.g., AmazonEKSWorkerNodePolicy, AmazonEC2ContainerRegistryReadOnly, AmazonEKS_CNI_Policy). Ensure no unnecessary permissions (e.g., broad EC2/S3 access). Consider deeper analysis if IAM permissions allow.

**Reference:** AWS Best Practice / IAM

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `eks-enterprise-lab/main-20260216030203877900000024` | Informational |

---

### <a name="iam-role-analysis"></a>IAM Role Analysis

*IAM roles associated with the cluster, nodegroups, and workloads (via IRSA) were reviewed for overly broad permissions and trust policy weaknesses. Overpermissive IAM roles expand the blast radius of any container compromise into the broader AWS environment.*

**2 findings** — 2 High

#### IRSA Trust Policy Missing Subject Condition

**Severity:** High | **Instances:** 1

**Description:** IAM roles used by insecure-app/insecure-sa has an OIDC trust policy with ':aud' condition but no ':sub' condition. Any service account in the cluster can assume this role.

**Recommendation:** Add a StringEquals condition for ':sub' (e.g., 'system:serviceaccount:<namespace>:<sa-name>') to restrict which service accounts can assume this role.

**Reference:** AWS Best Practice / IRSA

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `eks-enterprise-lab-irsa-overpermissive` | High |

#### IRSA Role Has Overly Broad Policy

**Severity:** High | **Instances:** 1

**Description:** IRSA role 'eks-enterprise-lab-irsa-overpermissive' (arn:aws:iam::123456789012:role/eks-enterprise-lab-irsa-overpermissive) used by insecure-app/insecure-sa has 'AdministratorAccess' attached. Pods using this role have excessive AWS permissions.

**Recommendation:** Remove 'AdministratorAccess' and create a scoped policy with only the permissions the workload needs.

**Reference:** AWS Best Practice / Least Privilege

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `eks-enterprise-lab-irsa-overpermissive` | High |

---

### <a name="namespace-governance"></a>Namespace Governance

*Each namespace was checked for Pod Security Admission (PSA) enforcement labels, ResourceQuota objects, and LimitRange definitions. These controls establish the security baseline and resource boundaries within each namespace.*

**6 findings** — 6 Low

#### Namespace Lacks ResourceQuota

**Severity:** Low | **Instances:** 3

**Description:** Namespaces does not have any ResourceQuota objects defined. This can lead to resource contention issues or potential DoS if workloads consume excessive resources.

**Recommendation:** Define appropriate ResourceQuotas for the namespace to limit the total amount of CPU, memory, storage, and object counts that can be consumed.

**Reference:** Best Practice / Resource Management

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `default/default` | Low |
| `insecure-app/insecure-app` | Low |
| `psa-warn/psa-warn` | Low |

#### Namespace Lacks LimitRange

**Severity:** Low | **Instances:** 3

**Description:** Namespaces does not have any LimitRange objects defined. This means default resource requests/limits are not enforced for containers, potentially leading to resource exhaustion or scheduling issues.

**Recommendation:** Define a LimitRange for the namespace to set default CPU/memory requests and limits for containers, and potentially enforce min/max values.

**Reference:** Best Practice / Resource Management

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `default/default` | Low |
| `insecure-app/insecure-app` | Low |
| `psa-warn/psa-warn` | Low |

---

### <a name="pod-and-container-security"></a>Pod & Container Security

*Pod specifications were analyzed for host namespace usage (network, PID, IPC), hostPath volumes, privileged containers, root execution, privilege escalation settings, dangerous Linux capabilities, seccomp profiles, filesystem writability, resource limits, and image provenance. These settings directly control the isolation boundary between containers and the host node.*

**70 findings** — 4 Critical, 7 High, 22 Medium, 37 Low

#### Privileged Container

**Severity:** Critical | **Instances:** 4

**Description:** Containers is running in privileged mode.

**Recommendation:** Do not run privileged containers. Refactor the application if possible.

**Reference:** CIS 5.2.2

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/vulnerable-app/app` | Critical |
| `kube-system/aws-node/aws-eks-nodeagent` | Critical |
| `kube-system/aws-node/aws-vpc-cni-init` | Critical |
| `kube-system/kube-proxy/kube-proxy` | Critical |

#### Pod Using Host Network

**Severity:** High | **Instances:** 4

**Description:** Workloads is configured with hostNetwork: true.

**Recommendation:** Avoid using hostNetwork. If required, isolate the node.

**Reference:** CIS 5.2.5

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/net-debug` | High |
| `insecure-app/vulnerable-app` | High |
| `kube-system/aws-node` | High |
| `kube-system/kube-proxy` | High |

#### Dangerous Capabilities Added

**Severity:** High | **Instances:** 3

**Description:** Containers adds dangerous Linux capabilities: ['SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE']. SYS_ADMIN is effectively equivalent to privileged mode.

**Recommendation:** Remove dangerous capabilities from securityContext.capabilities.add. Use the minimum capabilities required.

**Reference:** CIS 5.2.9

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/net-debug/debug` | High |
| `kube-system/aws-node/aws-node` | Medium |
| `kube-system/aws-node/aws-eks-nodeagent` | Medium |

#### Pod Using HostPath Volume

**Severity:** High | **Instances:** 10

**Description:** Workloads uses sensitive hostPath volume: '/'.

**Recommendation:** Avoid hostPath volumes. If necessary, use readOnly mounts and specific paths. Consider alternatives like PVs.

**Reference:** CIS 5.2.12

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/vulnerable-app` | High |
| `kube-system/aws-node` | High |
| `kube-system/aws-node` | Medium |
| `kube-system/aws-node` | Medium |
| `kube-system/aws-node` | Medium |
| `kube-system/aws-node` | Medium |
| `kube-system/aws-node` | Medium |
| `kube-system/kube-proxy` | Medium |
| `kube-system/kube-proxy` | Medium |
| `kube-system/kube-proxy` | Medium |

#### Container Running As Root

**Severity:** Medium | **Instances:** 3

**Description:** Containers is explicitly configured to run as root (runAsUser: 0).

**Recommendation:** Configure container's securityContext with runAsNonRoot: true and specify a runAsUser > 0.

**Reference:** CIS 5.2.7

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/insecure-cronjob/job` | Medium |
| `insecure-app/net-debug/debug` | Medium |
| `insecure-app/vulnerable-app/app` | Medium |

#### Container Allows Privilege Escalation

**Severity:** Medium | **Instances:** 7

**Description:** Containers allows privilege escalation (allowPrivilegeEscalation is not set to false).

**Recommendation:** Set securityContext.allowPrivilegeEscalation: false.

**Reference:** CIS 5.2.6

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/insecure-cronjob/job` | Medium |
| `insecure-app/net-debug/debug` | Medium |
| `insecure-app/vulnerable-app/app` | Medium |
| `kube-system/aws-node/aws-node` | Medium |
| `kube-system/aws-node/aws-eks-nodeagent` | Medium |
| `kube-system/aws-node/aws-vpc-cni-init` | Medium |
| `kube-system/kube-proxy/kube-proxy` | Medium |

#### Seccomp Profile Unconfined

**Severity:** Medium | **Instances:** 1

**Description:** Containers has seccomp profile set to 'Unconfined', disabling syscall filtering.

**Recommendation:** Set securityContext.seccompProfile.type to 'RuntimeDefault' or 'Localhost' to restrict available syscalls.

**Reference:** CIS 5.6.2

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/net-debug/debug` | Medium |

#### Pod Using Host PID Namespace

**Severity:** Medium | **Instances:** 1

**Description:** Workloads is configured with hostPID: true.

**Recommendation:** Avoid using hostPID unless essential.

**Reference:** CIS 5.2.3

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/vulnerable-app` | Medium |

#### Container Missing Resource Limits

**Severity:** Low | **Instances:** 8

**Description:** Containers lacks CPU and/or memory limits.

**Recommendation:** Define CPU and memory limits for all containers.

**Reference:** Best Practice

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/insecure-cronjob/job` | Low |
| `insecure-app/net-debug/debug` | Low |
| `insecure-app/vulnerable-app/app` | Low |
| `kube-system/aws-node/aws-node` | Low |
| `kube-system/aws-node/aws-eks-nodeagent` | Low |
| `kube-system/aws-node/aws-vpc-cni-init` | Low |
| `kube-system/coredns/coredns` | Low |
| `kube-system/kube-proxy/kube-proxy` | Low |

#### Capabilities Not Dropped

**Severity:** Low | **Instances:** 7

**Description:** Containers does not drop all Linux capabilities (capabilities.drop does not include 'ALL').

**Recommendation:** Set securityContext.capabilities.drop: ['ALL'] and only add back the specific capabilities required.

**Reference:** CIS 5.2.10

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/insecure-cronjob/job` | Low |
| `insecure-app/net-debug/debug` | Low |
| `insecure-app/vulnerable-app/app` | Low |
| `kube-system/aws-node/aws-node` | Low |
| `kube-system/aws-node/aws-eks-nodeagent` | Low |
| `kube-system/aws-node/aws-vpc-cni-init` | Low |
| `kube-system/kube-proxy/kube-proxy` | Low |

#### Seccomp Profile Not Set

**Severity:** Low | **Instances:** 7

**Description:** Containers does not have a seccomp profile configured. The container runtime default may or may not apply.

**Recommendation:** Explicitly set securityContext.seccompProfile.type to 'RuntimeDefault' to ensure syscall filtering is active.

**Reference:** CIS 5.6.2

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/insecure-cronjob/job` | Low |
| `insecure-app/vulnerable-app/app` | Low |
| `kube-system/aws-node/aws-node` | Low |
| `kube-system/aws-node/aws-eks-nodeagent` | Low |
| `kube-system/aws-node/aws-vpc-cni-init` | Low |
| `kube-system/coredns/coredns` | Low |
| `kube-system/kube-proxy/kube-proxy` | Low |

#### Container Root Filesystem Writable

**Severity:** Low | **Instances:** 7

**Description:** Containers does not have a read-only root filesystem.

**Recommendation:** Set securityContext.readOnlyRootFilesystem: true and use volumeMounts for writable directories.

**Reference:** CIS 5.6.3

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/insecure-cronjob/job` | Low |
| `insecure-app/net-debug/debug` | Low |
| `insecure-app/vulnerable-app/app` | Low |
| `kube-system/aws-node/aws-node` | Low |
| `kube-system/aws-node/aws-eks-nodeagent` | Low |
| `kube-system/aws-node/aws-vpc-cni-init` | Low |
| `kube-system/kube-proxy/kube-proxy` | Low |

#### Image Uses Latest Tag

**Severity:** Low | **Instances:** 3

**Description:** Containers uses image 'busybox:latest' potentially with 'latest' tag or no tag.

**Recommendation:** Use specific, immutable image tags (e.g., git SHA or semantic version) instead of 'latest'.

**Reference:** Best Practice

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/insecure-cronjob/job` | Low |
| `insecure-app/net-debug/debug` | Low |
| `insecure-app/vulnerable-app/app` | Low |

#### Container May Run As Root

**Severity:** Low | **Instances:** 5

**Description:** Containers has no runAsNonRoot or runAsUser specified (default allows root). Image may run as root.

**Recommendation:** Explicitly set securityContext.runAsNonRoot: true and specify a runAsUser > 0.

**Reference:** CIS 5.2.7

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `kube-system/aws-node/aws-node` | Low |
| `kube-system/aws-node/aws-eks-nodeagent` | Low |
| `kube-system/aws-node/aws-vpc-cni-init` | Low |
| `kube-system/coredns/coredns` | Low |
| `kube-system/kube-proxy/kube-proxy` | Low |

---

### <a name="service-accounts"></a>Service Accounts

*Kubernetes service accounts were reviewed for IAM role associations (IRSA), token automounting configuration, and usage of default service accounts. Service account tokens provide API access credentials that can be abused if not properly scoped.*

**44 findings** — 43 Medium, 1 Informational

#### Default Service Account Allows Token Automount

**Severity:** Medium | **Instances:** 6

**Description:** The 'default' ServiceAccount in namespace 'default' allows token automounting by default.

**Recommendation:** Explicitly set automountServiceAccountToken: false on the 'default' ServiceAccount and use dedicated SAs for pods.

**Reference:** CIS 5.1.6

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `default/default` | Medium |
| `insecure-app/default` | Medium |
| `kube-node-lease/default` | Medium |
| `kube-public/default` | Medium |
| `kube-system/default` | Medium |
| `psa-warn/default` | Medium |

#### Service Account Token Automount Enabled

**Severity:** Medium | **Instances:** 37

**Description:** Service accounts has automountServiceAccountToken enabled (or default). Tokens might be mounted unnecessarily in pods using this SA.

**Recommendation:** Set automountServiceAccountToken: false on the ServiceAccount unless pods using it specifically need the token (prefer mounting projected tokens if needed).

**Reference:** CIS 5.1.6

**Affected Resources:**

*37 instances across multiple resources. See CSV export for the full list.*

| Resource (sample) | Severity |
|-------------------|----------|
| `insecure-app/insecure-sa` | Medium |
| `kube-system/attachdetach-controller` | Medium |
| `kube-system/aws-cloud-provider` | Medium |
| `kube-system/aws-node` | Medium |
| `kube-system/certificate-controller` | Medium |
| `kube-system/clusterrole-aggregation-controller` | Medium |
| `kube-system/coredns` | Medium |
| `kube-system/cronjob-controller` | Medium |
| `kube-system/daemon-set-controller` | Medium |
| `kube-system/deployment-controller` | Medium |
| *...and 27 more* | |

#### Service Account Using IRSA

**Severity:** Informational | **Instances:** 1

**Description:** Service accounts uses IAM role via IRSA: arn:aws:iam::123456789012:role/eks-enterprise-lab-irsa-overpermissive

**Recommendation:** Ensure the associated IAM role follows the principle of least privilege.

**Reference:** AWS Best Practice

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/insecure-sa` | Informational |

---

### <a name="rbac-configuration"></a>RBAC Configuration

*Roles, ClusterRoles, RoleBindings, and ClusterRoleBindings were analyzed for cluster-admin bindings, wildcard permissions, sensitive verb/resource combinations, and bindings to default or system-level subjects. RBAC misconfigurations can grant attackers full cluster control.*

**45 findings** — 5 High, 37 Medium, 3 Low

#### ClusterRoleBinding Grants High Privileges

**Severity:** High | **Instances:** 3

**Description:** ClusterRoleBindings grants highly privileged cluster role 'cluster-admin' to 'Group:system:masters'. Granting cluster-wide admin/edit rights is highly risky.

**Recommendation:** Avoid binding cluster-admin or similar roles directly. Use namespace-scoped roles (RoleBinding) or custom cluster roles with least privilege necessary.

**Reference:** CIS 5.1.1

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `cluster-admin` | High |
| `eks:addon-cluster-admin` | High |
| `insecure-admin-binding` | High |

#### Role Contains Risky Permissions

**Severity:** High | **Instances:** 37

**Description:** ClusterRole 'cluster-admin' (namespace: (cluster)) contains rule 1 with potentially risky permissions: wildcard verb ('*'), wildcard resource ('*'), wildcard apiGroup ('*'), sensitive verbs (['*']) on sensitive resources (['*']).

**Recommendation:** Review the permissions granted by ClusterRole 'cluster-admin', particularly rule 1. Apply the principle of least privilege, avoiding wildcards and overly broad sensitive permissions.

**Reference:** CIS 5.1.3

**Affected Resources:**

*37 instances across multiple resources. See CSV export for the full list.*

| Resource (sample) | Severity |
|-------------------|----------|
| `rbac-escalation-role` | High |
| `rbac-escalation-role` | High |
| `cluster-admin` | Medium |
| `eks:addon-manager` | Medium |
| `eks:addon-manager` | Medium |
| `eks:addon-manager` | Medium |
| `eks:addon-manager` | Medium |
| `eks:az-poller` | Medium |
| `eks:fargate-manager` | Medium |
| `eks:fargate-scheduler` | Medium |
| *...and 27 more* | |

#### ClusterRoleBinding Involves Default Service Account

**Severity:** Medium | **Instances:** 1

**Description:** ClusterRoleBindings grants cluster role 'wildcard-role' to the 'default' ServiceAccount in namespace 'insecure-app'. All pods without an explicit SA in that namespace inherit these cluster-wide permissions.

**Recommendation:** Avoid granting permissions to the 'default' service account. Create and use dedicated service accounts for applications with specific, minimal roles.

**Reference:** CIS 5.1.5

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `default-sa-wildcard-binding` | Medium |

#### ClusterRoleBinding to Sensitive Subject

**Severity:** Medium | **Instances:** 4

**Description:** ClusterRoleBindings grants cluster role 'system:basic-user' to potentially sensitive subject 'Group:system:authenticated'.

**Recommendation:** Review bindings to system groups and default service accounts, especially in kube-system. Ensure the granted role is appropriate and necessary.

**Reference:** CIS 5.1.1 / Best Practice

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `system:basic-user` | Medium |
| `system:discovery` | Medium |
| `system:public-info-viewer` | Medium |
| `system:public-info-viewer` | Medium |

---

### <a name="network-policies"></a>Network Policies

*NetworkPolicy coverage was evaluated per namespace, and existing policies were reviewed for overly permissive ingress and egress rules. Without NetworkPolicies, all pod-to-pod traffic is permitted by default.*

**4 findings** — 4 Medium

#### Namespace Lacks Network Policy

**Severity:** Medium | **Instances:** 2

**Description:** Namespaces has no NetworkPolicy defined. By default, all pods within the namespace can communicate with each other, and potentially with pods in other namespaces or external services, violating the principle of least privilege.

**Recommendation:** Implement NetworkPolicies to restrict pod-to-pod communication. Start with a default deny policy for the namespace and explicitly allow required ingress/egress traffic between specific pods or namespaces.

**Reference:** CIS 5.3.2

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `psa-warn/psa-warn` | Medium |
| `default/default` | Medium |

#### Network Policy Allows All Ingress Sources

**Severity:** Medium | **Instances:** 1

**Description:** Policies ingress rule #1 allows traffic from ALL sources (no 'from' clause).

**Recommendation:** Specify podSelectors, namespaceSelectors, or restrictive ipBlocks in ingress rules to limit allowed sources based on least privilege.

**Reference:** CIS 5.3.2

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/allow-all` | Medium |

#### Network Policy Allows All Egress Destinations

**Severity:** Medium | **Instances:** 1

**Description:** Policies egress rule #1 allows traffic to ALL destinations (no 'to' clause).

**Recommendation:** Specify podSelectors, namespaceSelectors, or restrictive ipBlocks in egress rules to limit allowed destinations. Unrestricted egress can facilitate data exfiltration.

**Reference:** CIS 5.3.2

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/allow-all` | Medium |

---

### <a name="network-exposure"></a>Network Exposure

*Services exposed via LoadBalancer, Ingress TLS configuration, and wildcard host rules were assessed. These findings identify the cluster's external attack surface.*

**2 findings** — 2 Medium

#### Service Exposed via LoadBalancer

**Severity:** Medium | **Instances:** 1

**Description:** Service 'vulnerable-service' in namespace 'insecure-app' is of Type LoadBalancer, which provisions an external AWS Load Balancer, exposing the service publicly or internally depending on LB annotations/config. Exposed Ports: 80/TCP. LoadBalancer Hostname (if available): a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4-12345678.us-east-1.elb.amazonaws.com

**Recommendation:** Verify that this external exposure is intentional and necessary. Ensure appropriate security groups are attached to the load balancer restricting access to trusted sources. Consider using Ingress resources or internal load balancers if external exposure is not required. Regularly review exposed services.

**Reference:** Best Practice / Network Exposure

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/vulnerable-service` | Medium |

#### Ingress Rule Lacks TLS Configuration

**Severity:** Medium | **Instances:** 1

**Description:** Ingress 'vulnerable-ingress' in namespace 'insecure-app' rule #1 defines host '*.example.com' but this host is not included in any entry under spec.tls. Traffic for this host may be served over unencrypted HTTP.

**Recommendation:** Configure TLS for host '*.example.com' by adding an entry to the Ingress 'spec.tls' section, referencing a valid Kubernetes secret containing the TLS certificate and key. Ensure HTTPS is enforced, potentially via Ingress controller annotations.

**Reference:** Best Practice / Encryption

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/vulnerable-ingress` | Medium |

---

### <a name="secrets-and-configmaps"></a>Secrets & ConfigMaps

*Kubernetes Secrets and ConfigMaps were inspected for sensitive-looking key names (passwords, tokens, API keys). ConfigMaps with sensitive data are a common misconfiguration since they lack the access controls of Secrets.*

**2 findings** — 2 Medium

#### Secret Contains Sensitive-Looking Keys

**Severity:** Medium | **Instances:** 1

**Description:** Secrets contains data keys that suggest sensitive data: ['api_token', 'password']. Verify these are properly managed and rotated.

**Recommendation:** Ensure secrets with sensitive data keys are tightly controlled via RBAC, rotated regularly, and not exposed unnecessarily.

**Reference:** CIS 5.4.1

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/db-secret` | Medium |

#### Potential Sensitive Data in ConfigMap Keys

**Severity:** Medium | **Instances:** 1

**Description:** ConfigMaps contains keys that suggest sensitive data might be stored insecurely: ['database_password', 'jwt_token']. ConfigMaps are often less protected by RBAC than Secrets.

**Recommendation:** Do not store secrets or sensitive configuration (passwords, tokens, keys) in ConfigMaps. Use Kubernetes Secrets instead and ensure appropriate RBAC.

**Reference:** CIS 5.4.1

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `insecure-app/app-config` | Medium |

---

### <a name="pod-security-admission"></a>Pod Security Admission

**3 findings** — 3 Medium

#### PSA Label Missing

**Severity:** Medium | **Instances:** 3

**Description:** Namespaces lacks the 'pod-security.kubernetes.io/enforce' label.

**Recommendation:** Apply Pod Security Admission labels to namespaces, enforcing at least the 'restricted' standard.

**Reference:** CIS 5.2.1

**Affected Resources:**

| Resource | Severity |
|----------|----------|
| `default/default` | Medium |
| `insecure-app/insecure-app` | Medium |
| `psa-warn/psa-warn` | Medium |

---

## Appendix: Assessment Categories

This section provides a reference of all assessment areas covered by EKS Scout, including areas where no findings were identified.

**EKS Cluster Configuration** — 5 findings
: The EKS control plane configuration was reviewed for API server endpoint exposure, control plane audit logging, and secrets-at-rest encryption. Misconfigurations at this level affect the entire cluster's security posture.

**EKS Nodegroup Security** — 6 findings
: Worker node configurations were assessed including SSH access controls, Instance Metadata Service (IMDS) enforcement, and node IAM role permissions. Weaknesses here can enable lateral movement from compromised pods to the underlying EC2 infrastructure and AWS account.

**IAM Role Analysis** — 2 findings
: IAM roles associated with the cluster, nodegroups, and workloads (via IRSA) were reviewed for overly broad permissions and trust policy weaknesses. Overpermissive IAM roles expand the blast radius of any container compromise into the broader AWS environment.

**Security Groups** — No findings
: Security groups attached to cluster resources and nodegroups were examined for overly permissive inbound and outbound rules.

**GuardDuty** — No findings
: Amazon GuardDuty EKS audit log monitoring and runtime monitoring status were checked. GuardDuty provides threat detection for suspicious Kubernetes API activity and container-level runtime threats.

**Namespace Governance** — 6 findings
: Each namespace was checked for Pod Security Admission (PSA) enforcement labels, ResourceQuota objects, and LimitRange definitions. These controls establish the security baseline and resource boundaries within each namespace.

**Pod & Container Security** — 70 findings
: Pod specifications were analyzed for host namespace usage (network, PID, IPC), hostPath volumes, privileged containers, root execution, privilege escalation settings, dangerous Linux capabilities, seccomp profiles, filesystem writability, resource limits, and image provenance. These settings directly control the isolation boundary between containers and the host node.

**Service Accounts** — 44 findings
: Kubernetes service accounts were reviewed for IAM role associations (IRSA), token automounting configuration, and usage of default service accounts. Service account tokens provide API access credentials that can be abused if not properly scoped.

**RBAC Configuration** — 45 findings
: Roles, ClusterRoles, RoleBindings, and ClusterRoleBindings were analyzed for cluster-admin bindings, wildcard permissions, sensitive verb/resource combinations, and bindings to default or system-level subjects. RBAC misconfigurations can grant attackers full cluster control.

**Network Policies** — 4 findings
: NetworkPolicy coverage was evaluated per namespace, and existing policies were reviewed for overly permissive ingress and egress rules. Without NetworkPolicies, all pod-to-pod traffic is permitted by default.

**Network Exposure** — 2 findings
: Services exposed via LoadBalancer, Ingress TLS configuration, and wildcard host rules were assessed. These findings identify the cluster's external attack surface.

**Secrets & ConfigMaps** — 2 findings
: Kubernetes Secrets and ConfigMaps were inspected for sensitive-looking key names (passwords, tokens, API keys). ConfigMaps with sensitive data are a common misconfiguration since they lack the access controls of Secrets.

---

*This report was generated from EKS Scout v2 CSV output. Findings should be validated in the context of the target environment. Use the companion Finding Validation Guide for manual verification commands.*
