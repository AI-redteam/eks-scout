# EKS Scout — Finding Validation Guide

This guide provides commands and steps to manually validate every finding type reported by EKS Scout v2. For each finding, use the "Affected Components" details from the scanner's output to fill in the placeholders in the validation commands.

## Table of Contents

1.  [EKS Cluster Configuration](#1-eks-cluster-configuration)
    * [EKS Public API Endpoint Open to Internet](#eks-public-api-endpoint-open-to-internet)
    * [EKS Public API Endpoint Access Enabled](#eks-public-api-endpoint-access-enabled)
    * [EKS API Endpoint Access Disabled](#eks-api-endpoint-access-disabled)
    * [EKS Private API Endpoint Access Disabled](#eks-private-api-endpoint-access-disabled)
    * [EKS Control Plane Logging Disabled](#eks-control-plane-logging-disabled)
    * [EKS Secrets Encryption Not Enabled](#eks-secrets-encryption-not-enabled)
    * [EKS Secrets Resource Not Explicitly Encrypted](#eks-secrets-resource-not-explicitly-encrypted)
2.  [EKS Nodegroup Configuration](#2-eks-nodegroup-configuration)
    * [Nodegroup SSH Access Enabled Without Source Restriction](#nodegroup-ssh-access-enabled-without-source-restriction)
    * [Nodegroup SSH Access Enabled](#nodegroup-ssh-access-enabled)
    * [IMDSv2 Not Enforced](#imdsv2-not-enforced)
    * [Node IAM Role Has Overly Broad Policy](#node-iam-role-has-overly-broad-policy)
3.  [IAM Role Analysis (IRSA)](#3-iam-role-analysis-irsa)
    * [IRSA Trust Policy Missing Subject Condition](#irsa-trust-policy-missing-subject-condition)
    * [IRSA Role Has Overly Broad Policy](#irsa-role-has-overly-broad-policy)
4.  [Kubernetes Namespace Security](#4-kubernetes-namespace-security)
    * [PSA Label Missing](#psa-label-missing)
    * [PSA Label Too Permissive](#psa-label-too-permissive)
    * [Namespace Lacks ResourceQuota](#namespace-lacks-resourcequota)
    * [Namespace Lacks LimitRange](#namespace-lacks-limitrange)
5.  [Kubernetes Pod & Container Security](#5-kubernetes-pod--container-security)
    * [Pod Using Host Network](#pod-using-host-network)
    * [Pod Using Host PID Namespace](#pod-using-host-pid-namespace)
    * [Pod Using Host IPC Namespace](#pod-using-host-ipc-namespace)
    * [Pod Using HostPath Volume](#pod-using-hostpath-volume)
    * [Privileged Container](#privileged-container)
    * [Dangerous Capabilities Added](#dangerous-capabilities-added)
    * [Capabilities Not Dropped](#capabilities-not-dropped)
    * [Container Running As Root](#container-running-as-root)
    * [Container Allowed to Run As Root](#container-allowed-to-run-as-root)
    * [Container May Run As Root](#container-may-run-as-root)
    * [Container Allows Privilege Escalation](#container-allows-privilege-escalation)
    * [Seccomp Profile Not Set](#seccomp-profile-not-set)
    * [Seccomp Profile Unconfined](#seccomp-profile-unconfined)
    * [Container Root Filesystem Writable](#container-root-filesystem-writable)
    * [Container Missing Resource Limits](#container-missing-resource-limits)
    * [Image Uses Latest Tag](#image-uses-latest-tag)
    * [Image From Potentially Unapproved Registry](#image-from-potentially-unapproved-registry)
    * [Pod IRSA Role Potentially Overly Permissive](#pod-irsa-role-potentially-overly-permissive)
6.  [Kubernetes Service Accounts](#6-kubernetes-service-accounts)
    * [Service Account Using IRSA](#service-account-using-irsa)
    * [Service Account IRSA Role Potentially Overly Permissive](#service-account-irsa-role-potentially-overly-permissive)
    * [Service Account Token Automount Enabled](#service-account-token-automount-enabled)
    * [Default Service Account Allows Token Automount](#default-service-account-allows-token-automount)
7.  [Kubernetes RBAC](#7-kubernetes-rbac)
    * [ClusterRoleBinding Grants High Privileges](#clusterrolebinding-grants-high-privileges)
    * [ClusterRoleBinding to Sensitive Subject](#clusterrolebinding-to-sensitive-subject)
    * [ClusterRoleBinding Involves Default Service Account](#clusterrolebinding-involves-default-service-account)
    * [RoleBinding Grants Cluster Admin](#rolebinding-grants-cluster-admin)
    * [RoleBinding Grants High Privileges in Namespace](#rolebinding-grants-high-privileges-in-namespace)
    * [RoleBinding Involves Default Service Account](#rolebinding-involves-default-service-account)
    * [Role Contains Risky Permissions](#role-contains-risky-permissions)
8.  [Kubernetes Network Policies](#8-kubernetes-network-policies)
    * [Namespace Lacks Network Policy](#namespace-lacks-network-policy)
    * [Network Policy Allows All Ingress Sources](#network-policy-allows-all-ingress-sources)
    * [Network Policy Allows Ingress From All Pods](#network-policy-allows-ingress-from-all-pods)
    * [Network Policy Allows Ingress From All Namespaces](#network-policy-allows-ingress-from-all-namespaces)
    * [Network Policy Allows Ingress From Any IP](#network-policy-allows-ingress-from-any-ip)
    * [Network Policy Allows All Egress Destinations](#network-policy-allows-all-egress-destinations)
9.  [Kubernetes Network Exposure](#9-kubernetes-network-exposure)
    * [Service Exposed via LoadBalancer](#service-exposed-via-loadbalancer)
    * [Ingress Uses Default Backend](#ingress-uses-default-backend)
    * [Ingress Rule Uses Wildcard Host](#ingress-rule-uses-wildcard-host)
    * [Ingress Rule Lacks TLS Configuration](#ingress-rule-lacks-tls-configuration)
10. [Kubernetes Secrets & ConfigMaps](#10-kubernetes-secrets--configmaps)
    * [Secret Contains Sensitive-Looking Keys](#secret-contains-sensitive-looking-keys)
    * [Potential Sensitive Data in ConfigMap Keys](#potential-sensitive-data-in-configmap-keys)
11. [High-Risk Combinations & Attack Chains](#11-high-risk-combinations--attack-chains)
    * [Validating Same-Workload Combinations](#validating-same-workload-combinations)
    * [Validating Cross-Scope Attack Chains](#validating-cross-scope-attack-chains)

---

## 1. EKS Cluster Configuration

### EKS Public API Endpoint Open to Internet
* **Description:** The EKS API server endpoint is publicly accessible and not restricted to specific CIDRs, or is open to `0.0.0.0/0`.
* **Validation Command:**
    ```bash
    aws eks describe-cluster --name <cluster_name> --region <region> \
      --query "cluster.resourcesVpcConfig.{EndpointPublicAccess:endpointPublicAccess, PublicAccessCidrs:publicAccessCidrs}"
    ```
* **What to Look For:** `EndpointPublicAccess` is `true` and `PublicAccessCidrs` includes `0.0.0.0/0` or is an empty list (which defaults to all IPs).

### EKS Public API Endpoint Access Enabled
* **Description:** The API server endpoint is publicly accessible but restricted by specific CIDR blocks.
* **Validation Command:**
    ```bash
    aws eks describe-cluster --name <cluster_name> --region <region> \
      --query "cluster.resourcesVpcConfig.{EndpointPublicAccess:endpointPublicAccess, PublicAccessCidrs:publicAccessCidrs}"
    ```
* **What to Look For:** `EndpointPublicAccess` is `true` and `PublicAccessCidrs` contains specific IP ranges (not `0.0.0.0/0`).

### EKS API Endpoint Access Disabled
* **Description:** Both public and private access to the API endpoint are disabled — usually a misconfiguration.
* **Validation Command:**
    ```bash
    aws eks describe-cluster --name <cluster_name> --region <region> \
      --query "cluster.resourcesVpcConfig.{EndpointPublicAccess:endpointPublicAccess, EndpointPrivateAccess:endpointPrivateAccess}"
    ```
* **What to Look For:** Both `EndpointPublicAccess` and `EndpointPrivateAccess` are `false`.

### EKS Private API Endpoint Access Disabled
* **Description:** Private access to the API endpoint is disabled, relying solely on public access.
* **Validation Command:**
    ```bash
    aws eks describe-cluster --name <cluster_name> --region <region> \
      --query "cluster.resourcesVpcConfig.endpointPrivateAccess"
    ```
* **What to Look For:** Output is `false`.

### EKS Control Plane Logging Disabled
* **Description:** One or more recommended control plane log types are not enabled.
* **Validation Command:**
    ```bash
    aws eks describe-cluster --name <cluster_name> --region <region> \
      --query "cluster.logging.clusterLogging"
    ```
* **What to Look For:** For each required type (`api`, `audit`, `authenticator`, `controllerManager`, `scheduler`), check if an entry exists with `enabled: true`.

### EKS Secrets Encryption Not Enabled
* **Description:** Envelope encryption for Kubernetes secrets using a KMS key is not configured.
* **Validation Command:**
    ```bash
    aws eks describe-cluster --name <cluster_name> --region <region> \
      --query "cluster.encryptionConfig"
    ```
* **What to Look For:** Output is `null`, an empty list `[]`, or does not contain a provider with a `keyArn`.

### EKS Secrets Resource Not Explicitly Encrypted
* **Description:** Encryption is configured with a KMS key, but `secrets` is not explicitly included in the resources to encrypt.
* **Validation Command:**
    ```bash
    aws eks describe-cluster --name <cluster_name> --region <region> \
      --query "cluster.encryptionConfig"
    ```
* **What to Look For:** Verify that at least one `encryptionConfig` entry with a `provider.keyArn` also includes `"secrets"` in its `resources` array.

## 2. EKS Nodegroup Configuration

### Nodegroup SSH Access Enabled Without Source Restriction
* **Description:** SSH access is enabled for a nodegroup without source Security Group restrictions — SSH is reachable from any IP with the key.
* **Validation Command:**
    ```bash
    aws eks describe-nodegroup --cluster-name <cluster_name> --nodegroup-name <nodegroup_name> --region <region> \
      --query "nodegroup.remoteAccess"
    ```
* **What to Look For:** `ec2SshKey` has a value and `sourceSecurityGroups` is `null` or empty.

### Nodegroup SSH Access Enabled
* **Description:** SSH access is enabled and restricted by source Security Groups.
* **Validation Command:**
    ```bash
    aws eks describe-nodegroup --cluster-name <cluster_name> --nodegroup-name <nodegroup_name> --region <region> \
      --query "nodegroup.remoteAccess"
    ```
* **What to Look For:** `ec2SshKey` has a value and `sourceSecurityGroups` contains Security Group IDs. Review those SGs separately.

### IMDSv2 Not Enforced
* **Description:** The nodegroup's launch template has `HttpTokens: optional`, leaving IMDSv1 accessible and enabling SSRF-based credential theft from pods.
* **Validation Command:**
    ```bash
    # Get the launch template used by the nodegroup
    aws eks describe-nodegroup --cluster-name <cluster_name> --nodegroup-name <nodegroup_name> --region <region> \
      --query "nodegroup.launchTemplate.{id:id, version:version}"

    # Then check the launch template's metadata options
    aws ec2 describe-launch-template-versions --launch-template-id <template_id> --versions <version> --region <region> \
      --query "LaunchTemplateVersions[0].LaunchTemplateData.MetadataOptions"
    ```
* **What to Look For:** `HttpTokens` is `optional` (or not set, which defaults to `optional`). Should be `required` to enforce IMDSv2. Also check `HttpPutResponseHopLimit` — a value > 1 can allow containers to reach IMDS even with IMDSv2.

### Node IAM Role Has Overly Broad Policy
* **Description:** The nodegroup's IAM role has managed policies attached that grant excessive permissions (e.g., `AmazonS3FullAccess`, `SecretsManagerReadWrite`).
* **Validation Command:**
    ```bash
    # Get the node role name from the nodegroup
    aws eks describe-nodegroup --cluster-name <cluster_name> --nodegroup-name <nodegroup_name> --region <region> \
      --query "nodegroup.nodeRole"

    # List attached managed policies
    aws iam list-attached-role-policies --role-name <role_name>

    # List inline policies
    aws iam list-role-policies --role-name <role_name>
    ```
* **What to Look For:** Policies beyond the standard EKS node policies (`AmazonEKSWorkerNodePolicy`, `AmazonEC2ContainerRegistryReadOnly`, `AmazonEKS_CNI_Policy`). Any broad policies like `*FullAccess`, `Administrator*`, or custom policies with `*` actions are red flags.

## 3. IAM Role Analysis (IRSA)

### IRSA Trust Policy Missing Subject Condition
* **Description:** An IRSA role's OIDC trust policy has an `:aud` condition but no `:sub` condition, allowing any service account in the cluster to assume it.
* **Validation Command:**
    ```bash
    aws iam get-role --role-name <role_name> --query "Role.AssumeRolePolicyDocument"
    ```
* **What to Look For:** In the trust policy's `Condition` block, look for `StringEquals` entries. There should be both a `:aud` condition (e.g., `sts.amazonaws.com`) AND a `:sub` condition (e.g., `system:serviceaccount:<namespace>:<sa-name>`). If only `:aud` exists, any SA can assume the role.

### IRSA Role Has Overly Broad Policy
* **Description:** An IRSA role has overly broad managed policies attached (e.g., `AdministratorAccess`).
* **Validation Command:**
    ```bash
    aws iam list-attached-role-policies --role-name <role_name>
    aws iam list-role-policies --role-name <role_name>

    # For each policy, review the actual permissions:
    aws iam get-policy-version --policy-arn <policy_arn> --version-id $(aws iam get-policy --policy-arn <policy_arn> --query "Policy.DefaultVersionId" --output text)
    ```
* **What to Look For:** Any policies granting `*` actions or broad service-level access. IRSA roles should follow least privilege — only the specific API actions the workload needs.

## 4. Kubernetes Namespace Security

### PSA Label Missing
* **Description:** A namespace lacks the `pod-security.kubernetes.io/enforce` label.
* **Validation Command:**
    ```bash
    kubectl get namespace <namespace_name> -o jsonpath='{.metadata.labels}' | python3 -m json.tool
    ```
* **What to Look For:** Absence of the `pod-security.kubernetes.io/enforce` label.

### PSA Label Too Permissive
* **Description:** A namespace has a PSA `enforce` label set to a less secure level than expected (e.g., `privileged` when `restricted` is desired).
* **Validation Command:**
    ```bash
    kubectl get namespace <namespace_name> -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}'
    ```
* **What to Look For:** The value is `privileged` or `baseline` when `restricted` is the target standard.

### Namespace Lacks ResourceQuota
* **Validation Command:**
    ```bash
    kubectl get resourcequota -n <namespace_name>
    ```
* **What to Look For:** "No resources found" or an empty list.

### Namespace Lacks LimitRange
* **Validation Command:**
    ```bash
    kubectl get limitrange -n <namespace_name>
    ```
* **What to Look For:** "No resources found" or an empty list.

## 5. Kubernetes Pod & Container Security

> **Tip:** For all pod/container findings, retrieve the full pod spec with:
> ```bash
> kubectl get pod <pod_name> -n <namespace_name> -o yaml
> ```
> For workload-level findings (Deployment, DaemonSet, etc.), inspect the controller's pod template:
> ```bash
> kubectl get deployment <name> -n <namespace_name> -o yaml
> ```

### Pod Using Host Network
* **What to Look For:** `spec.hostNetwork: true`

### Pod Using Host PID Namespace
* **What to Look For:** `spec.hostPID: true`

### Pod Using Host IPC Namespace
* **What to Look For:** `spec.hostIPC: true`

### Pod Using HostPath Volume
* **What to Look For:** In `spec.volumes`, an entry with a `hostPath` field. Note the `path` — paths like `/`, `/etc`, `/var/run/docker.sock`, or `/proc` are especially sensitive.

### Privileged Container
* **What to Look For:** In the container's `securityContext`: `privileged: true`

### Dangerous Capabilities Added
* **Description:** A container adds dangerous Linux capabilities like `SYS_ADMIN`, `NET_ADMIN`, or `SYS_PTRACE`. `SYS_ADMIN` is effectively equivalent to privileged mode.
* **What to Look For:** In the container's `securityContext.capabilities.add`, look for entries like `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `NET_RAW`, `DAC_OVERRIDE`, `SETUID`, `SETGID`.

### Capabilities Not Dropped
* **Description:** A container does not drop all capabilities (`capabilities.drop` does not include `ALL`).
* **What to Look For:** In `securityContext.capabilities.drop`, confirm `ALL` is not listed. Best practice is `drop: [ALL]` and selectively add back only what's needed.

### Container Running As Root
* **What to Look For:** `securityContext.runAsUser: 0` at container or pod level.

### Container Allowed to Run As Root
* **What to Look For:** `securityContext.runAsNonRoot: false` at container or pod level.

### Container May Run As Root
* **What to Look For:** Neither `runAsNonRoot: true` nor a non-zero `runAsUser` is set. The container will run as whatever user the image defines (often root).

### Container Allows Privilege Escalation
* **What to Look For:** `allowPrivilegeEscalation` is `true` or absent (defaults to `true`).

### Seccomp Profile Not Set
* **Description:** No seccomp profile is configured. The container may or may not get the runtime default depending on the CRI configuration.
* **What to Look For:** `securityContext.seccompProfile` is absent at both container and pod level.

### Seccomp Profile Unconfined
* **Description:** The seccomp profile is explicitly set to `Unconfined`, disabling syscall filtering entirely.
* **What to Look For:** `securityContext.seccompProfile.type: Unconfined`

### Container Root Filesystem Writable
* **What to Look For:** `readOnlyRootFilesystem` is `false` or absent (defaults to `false`).

### Container Missing Resource Limits
* **What to Look For:** In `resources.limits`, `cpu` or `memory` (or both) are missing.

### Image Uses Latest Tag
* **What to Look For:** The `image` field ends with `:latest` or has no tag specified.

### Image From Potentially Unapproved Registry
* **What to Look For:** The registry portion of the `image` field is not in your organization's approved list.

### Pod IRSA Role Potentially Overly Permissive
* **What to Look For:** In `metadata.annotations`, find `eks.amazonaws.com/role-arn`. Then review the role's policies using the AWS CLI (see [IRSA Role Has Overly Broad Policy](#irsa-role-has-overly-broad-policy)).

## 6. Kubernetes Service Accounts

### Service Account Using IRSA
* **Description:** Informational — a ServiceAccount has an IRSA role annotation.
* **Validation Command:**
    ```bash
    kubectl get serviceaccount <sa_name> -n <namespace_name> -o jsonpath='{.metadata.annotations.eks\.amazonaws\.com/role-arn}'
    ```
* **What to Look For:** The ARN of the associated IAM role. Review the role's policies for least privilege.

### Service Account IRSA Role Potentially Overly Permissive
* **Validation:** Same as [IRSA Role Has Overly Broad Policy](#irsa-role-has-overly-broad-policy).

### Service Account Token Automount Enabled
* **Validation Command:**
    ```bash
    kubectl get serviceaccount <sa_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** `automountServiceAccountToken` is `true` or absent (defaults to `true`).

### Default Service Account Allows Token Automount
* **Validation Command:**
    ```bash
    kubectl get serviceaccount default -n <namespace_name> -o yaml
    ```
* **What to Look For:** `automountServiceAccountToken` is `true` or absent.

## 7. Kubernetes RBAC

### ClusterRoleBinding Grants High Privileges
* **Validation Command:**
    ```bash
    kubectl get clusterrolebinding <binding_name> -o yaml
    ```
* **What to Look For:** `roleRef.name` is `cluster-admin` (or similar high-privilege role) and the `subjects` list shows who has this access.

### ClusterRoleBinding to Sensitive Subject
* **Validation Command:**
    ```bash
    kubectl get clusterrolebinding <binding_name> -o yaml
    ```
* **What to Look For:** `subjects` include `Group:system:unauthenticated`, `Group:system:authenticated`, or `ServiceAccount:default` in sensitive namespaces.

### ClusterRoleBinding Involves Default Service Account
* **Description:** A ClusterRoleBinding grants cluster-wide permissions to a `default` service account, meaning any pod without an explicit SA inherits those permissions.
* **Validation Command:**
    ```bash
    kubectl get clusterrolebinding <binding_name> -o yaml
    ```
* **What to Look For:** In `subjects`, an entry with `kind: ServiceAccount` and `name: default`.

### RoleBinding Grants Cluster Admin
* **Validation Command:**
    ```bash
    kubectl get rolebinding <binding_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** `roleRef.kind: ClusterRole` and `roleRef.name: cluster-admin`.

### RoleBinding Grants High Privileges in Namespace
* **Validation Command:**
    ```bash
    kubectl get rolebinding <binding_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** `roleRef.name` is `admin`, `edit`, or a custom role with broad permissions.

### RoleBinding Involves Default Service Account
* **Validation Command:**
    ```bash
    kubectl get rolebinding <binding_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `subjects`, `kind: ServiceAccount` with `name: default`.

### Role Contains Risky Permissions
* **Validation Command (for ClusterRole):**
    ```bash
    kubectl get clusterrole <role_name> -o yaml
    ```
* **Validation Command (for Role):**
    ```bash
    kubectl get role <role_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In the `rules` array, look for:
    - `verbs: ["*"]` or `resources: ["*"]` or `apiGroups: ["*"]` (wildcard permissions)
    - Sensitive verbs: `escalate`, `bind`, `impersonate`, `create`/`delete`/`patch` on sensitive resources
    - Sensitive resources: `secrets`, `pods/exec`, `serviceaccounts`, `clusterroles`, `clusterrolebindings`, `nodes`

## 8. Kubernetes Network Policies

### Namespace Lacks Network Policy
* **Validation Command:**
    ```bash
    kubectl get networkpolicy -n <namespace_name>
    ```
* **What to Look For:** "No resources found" — all pod-to-pod traffic is allowed by default.

### Network Policy Allows All Ingress Sources
* **Validation Command:**
    ```bash
    kubectl get networkpolicy <policy_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.ingress[]`, a rule where `from` is absent or empty `[]`.

### Network Policy Allows Ingress From All Pods
* **What to Look For:** In `spec.ingress[].from[]`, an entry with `podSelector: {}`.

### Network Policy Allows Ingress From All Namespaces
* **What to Look For:** In `spec.ingress[].from[]`, an entry with `namespaceSelector: {}`.

### Network Policy Allows Ingress From Any IP
* **What to Look For:** In `spec.ingress[].from[]`, an entry with `ipBlock.cidr: "0.0.0.0/0"`.

### Network Policy Allows All Egress Destinations
* **Description:** An egress rule allows traffic to all destinations — no `to` clause defined.
* **Validation Command:**
    ```bash
    kubectl get networkpolicy <policy_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.egress[]`, a rule where `to` is absent or empty `[]`. Unrestricted egress can facilitate data exfiltration.

## 9. Kubernetes Network Exposure

### Service Exposed via LoadBalancer
* **Validation Command:**
    ```bash
    kubectl get service <service_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** `spec.type: LoadBalancer`. Note `status.loadBalancer.ingress[].hostname` for the external endpoint.

### Ingress Uses Default Backend
* **Validation Command:**
    ```bash
    kubectl get ingress <ingress_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** `spec.defaultBackend` is defined and `spec.rules` is absent or empty.

### Ingress Rule Uses Wildcard Host
* **What to Look For:** In `spec.rules[]`, an entry where `host: "*"`.

### Ingress Rule Lacks TLS Configuration
* **What to Look For:** A host in `spec.rules[].host` is not covered by any entry in `spec.tls[].hosts`.

## 10. Kubernetes Secrets & ConfigMaps

### Secret Contains Sensitive-Looking Keys
* **Description:** A Secret contains data keys with names suggesting credentials (passwords, tokens, API keys).
* **Validation Command:**
    ```bash
    kubectl get secret <secret_name> -n <namespace_name> -o jsonpath='{.data}' | python3 -m json.tool
    ```
* **What to Look For:** Key names matching patterns like `password`, `secret`, `token`, `apikey`, `api_token`. The values are base64-encoded — decode with `echo <value> | base64 -d` to verify content (only in authorized testing contexts).

### Potential Sensitive Data in ConfigMap Keys
* **Validation Command:**
    ```bash
    kubectl get configmap <configmap_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** Key names under `data` matching patterns like `password`, `secret`, `token`, `apikey`. ConfigMaps store data in plaintext and often have weaker RBAC than Secrets.

## 11. High-Risk Combinations & Attack Chains

EKS Scout v2 detects multi-finding attack chains where individual findings combine to create elevated risk. These are reported in the HTML report and JSON output.

### Validating Same-Workload Combinations

When the report identifies a high-risk combination on a workload, validate that **both findings genuinely co-exist on the same workload**:

```bash
# Get the full pod spec for the affected workload
kubectl get deployment <workload_name> -n <namespace> -o yaml
```

**Common combinations to verify:**

| Combination | What to check |
|---|---|
| Privileged + HostPath | `securityContext.privileged: true` AND a `hostPath` volume exists |
| Privileged + Host Network | `securityContext.privileged: true` AND `spec.hostNetwork: true` |
| SYS_ADMIN + Host IPC | `capabilities.add` includes `SYS_ADMIN` AND `spec.hostIPC: true` |
| Root + Host Network | `runAsUser: 0` (or no non-root enforcement) AND `spec.hostNetwork: true` |
| Host IPC + Host PID | `spec.hostIPC: true` AND `spec.hostPID: true` |
| Host Network + HostPath | `spec.hostNetwork: true` AND a `hostPath` volume exists |

### Validating Cross-Scope Attack Chains

Cross-scope combinations involve an infrastructure-level finding + a workload-level finding. Validate both sides independently:

**IMDS Credential Theft (IMDSv2 + Host Network / Privileged):**
```bash
# Confirm IMDSv1 is accessible on nodes
aws ec2 describe-launch-template-versions --launch-template-id <id> --versions <ver> \
  --query "LaunchTemplateVersions[0].LaunchTemplateData.MetadataOptions"

# Confirm the pod has host network or privileged mode
kubectl get pod <pod_name> -n <namespace> -o jsonpath='{.spec.hostNetwork}'
```

**Overprivileged Node Role + Escape Vector:**
```bash
# Confirm the node role has broad policies
aws iam list-attached-role-policies --role-name <node_role_name>

# Confirm the pod has an escape vector (privileged, hostPath, host network)
kubectl get pod <pod_name> -n <namespace> -o yaml | grep -E "privileged|hostPath|hostNetwork"
```

**Public API + Cluster Admin:**
```bash
# Confirm API is publicly accessible
aws eks describe-cluster --name <cluster> --region <region> \
  --query "cluster.resourcesVpcConfig.endpointPublicAccess"

# Confirm cluster-admin binding exists
kubectl get clusterrolebinding <binding_name> -o yaml
```

---
This guide should provide a solid starting point for validating all findings from EKS Scout v2. For the interactive HTML report with attack chain visualizations, open the HTML output file directly in a browser.
