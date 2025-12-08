# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

EKS Scout is a passive security scanner for AWS EKS clusters. It operates in read-only mode using `kubectl` and `aws cli` to identify security misconfigurations. The tool outputs findings in CSV format designed for Plextrac WriteupsDB import, with optional JSON output.

## Running the Scanner

### Main Scanner

```bash
# Basic usage
python main.py --cluster-name <cluster-name> --region <region>

# With specific AWS profile and kubectl context
python main.py --cluster-name prod-cluster --region us-east-1 --profile dev-account --context dev-eks-context

# JSON output with debug logging
python main.py --cluster-name staging --region us-west-2 -o findings.json -f json --debug
```

**Required Arguments:**
- `--cluster-name`: EKS cluster name
- `--region`: AWS region (e.g., us-west-2)

**Optional Arguments:**
- `--profile`: AWS CLI profile
- `--context`: kubectl context
- `-o, --output-file`: Output filename (default: eks_findings_plextrac.csv)
- `-f, --output-format`: csv or json (default: csv)
- `--debug`: Enable verbose logging

### Supplemental Tools

**Roll-up Script** - Consolidates duplicate findings from replicated resources:
```bash
python supplemental/rollup-findings.py -i <input_csv> -o <output_csv>
```

**Combo Analyzer** - Generates narrative report for dangerous finding combinations:
```bash
python supplemental/combo-analyzer.py -i <input_csv> -o <output_markdown>
```

## Architecture

### Core Structure

**main.py** contains all scanner logic in a single file (~1120 lines):

1. **Command Execution Layer** (`run_cmd`): Handles subprocess execution with AWS profile and kubectl context injection
2. **Data Fetching Layer**: Separate functions for AWS EKS resources and Kubernetes resources
3. **Analysis Layer**: Specialized analysis functions for different security domains
4. **Reporting Layer**: CSV and JSON export functions

### Key Design Patterns

**Findings Data Structure**: All findings share a common structure defined in `add_finding()`:
```python
{
    'severity': SEVERITY_*,
    'type': 'Finding Name',
    'namespace': 'namespace or (cluster)',
    'name': 'resource-name',
    'asset_type': 'Pod|Service|EKS Cluster|etc',
    'details': 'Description text',
    'recommendation': 'Remediation guidance',
    'reference': 'CIS benchmark or best practice reference'
}
```

**Context/Profile Injection**: The `run_cmd()` function automatically injects `--context` for kubectl and `--profile` for aws commands based on detection of command prefixes.

**Resource Fetching**: `get_k8s_resources()` supports:
- Single or comma-separated resource types
- Namespace-specific or all-namespaces queries
- Returns list for single type or dict keyed by Kind for multiple types

### Security Analysis Functions

Each analysis function follows the pattern: `analyze_<domain>(all_findings, resources, ...)`:

- **analyze_eks_cluster_config**: API endpoint access, control plane logging, secrets encryption
- **analyze_eks_nodegroups**: SSH access, IAM roles, IMDSv2 enforcement
- **analyze_namespaces**: PSA labels, ResourceQuotas, LimitRanges
- **analyze_pods**: Host namespaces, hostPath, privileged containers, root users, resource limits, IRSA
- **analyze_serviceaccounts**: IRSA roles, token automounting
- **analyze_rbac**: Cluster-admin bindings, risky permissions, wildcard rules
- **analyze_network_policies**: Missing policies, overly broad allow rules
- **analyze_network_exposure**: LoadBalancer services, Ingress TLS configuration
- **analyze_secrets_configmaps**: Sensitive data patterns, secret types

### Severity Levels

Constants defined at top of main.py:
- SEVERITY_CRITICAL
- SEVERITY_HIGH
- SEVERITY_MEDIUM
- SEVERITY_LOW
- SEVERITY_INFO

### AWS Permissions Model

The scanner gracefully degrades when optional permissions are missing (using `suppress_error=True` in `run_cmd()`). Core permissions are required; enhanced checks (EC2, IAM policy analysis) are optional.

## Development Patterns

### Adding New Checks

1. Create or extend an `analyze_*()` function
2. Fetch required resources via `get_k8s_resources()` or AWS-specific functions
3. Use `add_finding()` to register issues
4. Call the analysis function from `main()`

### Error Handling

- Use `suppress_error=True` for optional AWS API calls
- `parse_json()` includes error handling for malformed JSON
- All kubectl resource fetches log warnings on failure and continue

### Testing Changes

No automated test suite exists. Manual testing workflow:
1. Run scanner against test EKS cluster with `--debug`
2. Review findings CSV/JSON for accuracy
3. Test with missing permissions to verify graceful degradation
4. Run roll-up script on output to ensure compatibility

## Plextrac Integration

CSV columns map directly to Plextrac WriteupsDB fields:
- Finding Name → Title
- Severity → Severity
- Description → Description
- Recommendation → Recommendation
- Vulnerability References → References
- Affected Components → Location/Affected Asset
- Tags → Tags (includes "EKS", "Kubernetes", "Security", asset type)

## Common Customizations

**Adjusting PSA Expected Level**: Change `expected_level` variable in `analyze_namespaces()` (line ~245)

**Modifying Allowed Registries**: Update `allowed_registries` list in `analyze_pods()` (line ~407)

**Adding Sensitive HostPaths**: Extend `sensitive_hostpaths` list in `analyze_pods()` (line ~261)

**Configuring RBAC Sensitivity**: Modify `sensitive_verbs`, `sensitive_resources`, `highly_privileged_roles` in `analyze_rbac()` (lines ~462-464)
