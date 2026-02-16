# EKS Scout - AWS EKS Passive Security Scanner

```
 ______       ___   ___      ______                     ______       ______       ______       __  __       _________
/_____/\     /___/\/__/\    /_____/\                   /_____/\     /_____/\     /_____/\     /_/\/_/\     /________/\
\::::_\/_    \::.\ \\ \ \   \::::_\/_       _______    \::::_\/_    \:::__\/     \:::_ \ \    \:\ \:\ \    \__.::.__\/
 \:\/___/\    \:: \/_) \ \   \:\/___/\     /______/\    \:\/___/\    \:\ \  __    \:\ \ \ \    \:\ \:\ \      \::\ \
  \::___\/_    \:. __  ( (    \_::._\:\    \__::::\/     \_::._\:\    \:\ \/_/\    \:\ \ \ \    \:\ \:\ \      \::\ \
   \:\____/\    \: \ )  \ \     /____\:\                   /____\:\    \:\_\ \ \    \:\_\ \ \    \:\_\:\ \      \::\ \
    \_____\/     \__\/\__\/     \_____\/                   \_____\/     \_____\/     \_____\/     \_____\/       \__\/
```

**by Ben Stevens** | **Version:** 2.0

EKS Scout is a passive (read-only) security scanner for AWS EKS clusters. It uses `kubectl` and `aws` CLI to gather configuration data and identify security misconfigurations, vulnerabilities, and deviations from best practices.

Designed for security consultants, auditors, and internal security teams who need to perform efficient EKS security assessments with read-only access.

## Features

- **Passive scanning** — Only read operations (`get`, `list`, `describe`). No changes to your cluster.
- **Workload-level reporting** — Findings are grouped by Deployment/DaemonSet/StatefulSet, not individual pod replicas, eliminating duplicate noise.
- **High-risk combination detection** — Identifies workloads where multiple findings create attack chains (e.g., privileged + hostPath = container escape).
- **Cross-scope attack chain detection** — Maps infrastructure-to-workload attack paths (e.g., SCARLETEEL: host network + IMDSv1 = AWS credential theft).
- **Interactive HTML report** — Self-contained HTML report with attack chain visualizations, severity dashboards, filtering, and CSV/JSON export.
- **Configurable suppression** — Reduce false positives via YAML config rules or Kubernetes annotations.
- **Plextrac-compatible CSV output** — Ready for import into Plextrac WriteupsDB.
- **Zero dependencies** — Uses only the Python standard library (PyYAML optional for config files).

## Installation

```bash
# Clone and install
git clone https://github.com/amberg/eks-scout.git
cd eks-scout
pip install -e .

# With YAML config file support
pip install -e ".[yaml]"
```

## Prerequisites

- **Python 3.8+**
- **kubectl** configured with cluster access
- **AWS CLI** with valid credentials

### Required Permissions

**Kubernetes RBAC** — Equivalent to the built-in `view` ClusterRole:
- `get` and `list` on: namespaces, pods, serviceaccounts, roles, rolebindings, clusterroles, clusterrolebindings, networkpolicies, services, ingresses, secrets, configmaps, resourcequotas, limitranges

**AWS IAM** — Core (required):
- `eks:DescribeCluster`, `eks:ListNodegroups`, `eks:DescribeNodegroup`, `sts:GetCallerIdentity`

**AWS IAM** — Optional (scanner degrades gracefully if missing):
- `ec2:DescribeSecurityGroups`, `ec2:DescribeLaunchTemplateVersions`
- `iam:ListAttachedRolePolicies`, `iam:GetRolePolicy`, `iam:ListRolePolicies`

## Quick Start

```bash
# Run a scan
eks-scout scan --cluster-name prod-cluster --region us-east-1

# With AWS profile and kubectl context
eks-scout scan --cluster-name dev-cluster --region eu-west-1 --profile dev-account --context dev-eks

# HTML report (default)
eks-scout scan --cluster-name prod-cluster --region us-east-1 -f html -o report.html

# JSON output
eks-scout scan --cluster-name staging --region us-west-2 -f json -o findings.json

# Generate a config file, then scan with it
eks-scout init
eks-scout scan --cluster-name prod --region us-east-1 --config eks-scout.yaml

# Include suppressed findings in output
eks-scout scan --cluster-name prod --region us-east-1 --config eks-scout.yaml --show-suppressed

# Debug logging
eks-scout scan --cluster-name test --region us-west-2 --debug
```

The backward-compatible entry point also works:
```bash
python main.py --cluster-name prod-cluster --region us-east-1
```

## Configuration

Generate a default config file with `eks-scout init`. The config file supports YAML or JSON format.

### Check Enable/Disable

```yaml
checks:
  "*": true              # Enable all checks by default
  "k8s.pods": false      # Disable specific checks
  "aws.nodegroups": true
```

### Severity Overrides

```yaml
severity_overrides:
  "k8s.pods.latest-tag": "Medium"
  "k8s.pods.may-run-as-root": "Informational"
```

### Settings

Override default thresholds and lists:

```yaml
settings:
  psa_expected_level: "restricted"

  allowed_registries:
    - "amazonaws.com"
    - "docker.io"
    - "gcr.io"

  sensitive_hostpaths:
    - "/"
    - "/etc"
    - "/var/run/docker.sock"

  sensitive_key_patterns:
    - "password"
    - "secret"
    - "token"

  system_namespaces:
    - "kube-system"
    - "kube-public"
    - "kube-node-lease"
```

### Suppressions

Reduce false positives by suppressing known-good findings. Rules can match by type, namespace, name (regex), or labels:

```yaml
suppressions:
  # Suppress all findings in kube-system
  - namespace: "kube-system"
    reason: "System namespace - expected configuration"

  # Suppress a specific finding type globally
  - type: "Container May Run As Root"
    reason: "Accepted risk for legacy workloads"

  # Suppress by namespace + finding type
  - namespace: "monitoring"
    type: "Service Exposed via LoadBalancer"
    reason: "Intentional external exposure for Grafana"

  # Suppress by resource name pattern (regex)
  - name: "datadog-.*"
    reason: "Datadog agent requires host access"

  # Suppress by label
  - labels:
      eks-scout.io/ignore: "true"
    reason: "Explicitly marked for exclusion"
```

### Annotation-Based Suppression

Add annotations to Kubernetes resources to suppress findings directly:

```yaml
# Suppress all findings for this resource
metadata:
  annotations:
    eks-scout.io/ignore: "true"

# Suppress specific finding types
metadata:
  annotations:
    eks-scout.io/ignore: "Privileged Container,Pod Using Host Network"
```

## Checks Performed

| Category | Checks |
|----------|--------|
| **EKS Cluster** | API server endpoint access, control plane logging, secrets encryption, cluster IAM role |
| **EKS Nodegroups** | SSH access, node IAM role, IMDSv2 enforcement |
| **Namespaces** | PSA labels, ResourceQuota, LimitRange |
| **Pod Security** | Host namespaces, hostPath volumes, privileged containers, root execution, privilege escalation, writable filesystem, resource limits, image provenance, IRSA roles |
| **Service Accounts** | IRSA role association, token automounting |
| **RBAC** | cluster-admin bindings, sensitive subject bindings, risky permissions (wildcards, secrets access) |
| **Network Policies** | Missing policies per namespace, overly broad ingress |
| **Network Exposure** | LoadBalancer services, Ingress TLS, wildcard hosts |
| **Secrets & ConfigMaps** | Sensitive secret types, sensitive key patterns in ConfigMaps |

## High-Risk Combination Detection

EKS Scout automatically detects workloads where multiple findings combine to create elevated risk (20 same-workload combos). For example:

- **Privileged Container + HostPath Volume** (Critical) — Direct path for container escape and host compromise.
- **SYS_ADMIN Capability + Host IPC** (Critical) — Kernel-level manipulation of host shared memory.
- **Root Container + Host Network** (High) — Node network stack manipulation and Network Policy bypass.
- **Host IPC + Host PID** (High) — See all processes and manipulate their shared memory.
- **Root Container + Overpermissive IRSA Role** (High) — Application compromise leads directly to AWS resource abuse.

## Cross-Scope Attack Chain Detection

Beyond same-workload combos, EKS Scout detects 8 cross-scope attack chains where infrastructure-level weaknesses combine with pod-level findings to create cloud pivot paths:

| Attack Chain | Severity | Description |
|---|---|---|
| **IMDS Credential Theft via Host Network** | Critical | Host network + IMDSv1 = steal node IAM creds (SCARLETEEL pattern) |
| **IMDS Credential Theft via Privileged Container** | Critical | Privileged pod + IMDSv1 = cloud credential theft |
| **Overprivileged Node Role + Container Escape** | Critical | Privileged container escapes to a node with broad AWS permissions |
| **Unrestricted SSH + Overprivileged Node Role** | Critical | SSH brute force to node with broad IAM role |
| **Overprivileged Node Role + Host Filesystem** | High | Read node IAM creds from disk via hostPath |
| **Overprivileged Node Role + Host Network** | High | IMDS access + broad node role = AWS pivot |
| **Public API + Cluster Admin Privileges** | High | Internet-exposed API + cluster-admin RBAC = full control |
| **Unencrypted Secrets with Sensitive Data** | Medium | Secrets in plaintext etcd + sensitive keys detected |

These are reported alongside same-workload combos in the HTML report with full attack chain visualizations.

## HTML Report

The HTML report (`-f html`) is a self-contained, interactive single-file report that includes:

- **Severity dashboard** — Total findings, critical/high counts, and attack chain count at a glance.
- **Severity donut chart** and **category bar chart** — Visual breakdown of findings.
- **Interactive findings table** — Sortable, filterable by severity/namespace/asset type/category, with full-text search. Click any row to expand details.
- **Attack chain visualizations** — Each high-risk combination and cross-scope attack chain renders as a visual kill-chain flow: Initial Access → Foothold → Escalation → Breakout → Attacker Goal.
- **CSV/JSON export** — Download filtered findings as CSV or copy as JSON directly from the report.

No external dependencies — the report works offline in any modern browser.

See `eks_findings_plextrac.html` for an example report generated against a test lab.

## Output Formats

- **CSV** (default) — Plextrac-compatible with columns: Finding Name, Severity, Status, Description, Recommendation, Vulnerability References, Affected Components, Tags.
- **HTML** — Interactive single-file report with dashboards, attack chain visualizations, filtering, and export. See [HTML Report](#html-report) above.
- **JSON** — Structured output including findings, summary statistics, and high-risk combinations.

## Plextrac Integration

The CSV output maps directly to Plextrac WriteupsDB:

| CSV Column | Plextrac Field |
|------------|---------------|
| Finding Name | Title |
| Severity | Severity |
| Description | Description |
| Recommendation | Recommendation |
| Vulnerability References | References |
| Affected Components | Location / Affected Asset |
| Tags | Tags |

## Disclaimer

- **Use responsibly.** Ensure you have authorization to scan the target environment.
- **Read-only limitations.** Cannot verify runtime security controls or detect application-level flaws.
- **Verify findings.** Always validate findings within the context of your specific environment.
- **No guarantees.** This tool is provided "as is" without warranty of any kind.

Use EKS Scout as one part of a comprehensive security assessment process.
