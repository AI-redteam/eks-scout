# EKS Scout — Supplemental Reporting Tools

This directory contains tools and reference documents that help consultants turn EKS Scout CSV output into professional client deliverables.

## Contents

| File | Purpose |
|------|---------|
| `csv-to-report.py` | Generate a structured Markdown report from CSV findings |
| `client-report-methodology.md` | Drop-in methodology section describing every assessment area |
| `Finding-Validation-Guide.md` | Manual validation commands for every finding type EKS Scout produces |

---

## csv-to-report.py

Reads EKS Scout v2 CSV output and produces a structured Markdown report suitable for inclusion in penetration test or security review deliverables.

### What it generates

- **Executive Summary** — severity breakdown, namespace and category statistics
- **Scope of Assessment** — table of all assessment categories with finding counts, linked to detail sections
- **Findings by Category** — each category grouped with a description of what was assessed, individual finding types with affected-resource tables (namespace, workload, severity, recommendation)
- **Appendix** — full list of assessment categories including those with zero findings (demonstrates coverage)

### Usage

```bash
python csv-to-report.py -i <input_csv> -o <output_md> [--cluster <name>]
```

| Argument | Required | Description |
|----------|----------|-------------|
| `-i`, `--input` | Yes | Path to the EKS Scout CSV findings file |
| `-o`, `--output` | Yes | Path for the output Markdown report |
| `--cluster` | No | Cluster name to display in the report header |

### Example

```bash
# Generate a report from the example findings
python supplemental/csv-to-report.py \
  -i eks_findings_plextrac.csv \
  -o client-report-findings.md \
  --cluster "prod-us-east-1"
```

The output Markdown can be converted to PDF, DOCX, or HTML using tools like `pandoc`, or pasted directly into your reporting platform.

### Prerequisites

- Python 3.7+
- No external dependencies (stdlib only: `csv`, `collections`, `argparse`, `pathlib`, `textwrap`)

---

## client-report-methodology.md

A ready-to-use methodology section that describes every assessment area covered by EKS Scout. Drop it into the methodology section of a client report with minimal editing.

### Coverage

The methodology covers 12 assessment areas:

1. EKS Cluster-Level Configuration (API endpoint, logging, secrets encryption)
2. Nodegroup & Worker Node Security (SSH, node IAM roles, IMDSv2)
3. IAM Roles for Service Accounts (IRSA trust policies, attached policies)
4. Namespace Security & Governance (PSA, resource quotas, limit ranges)
5. Pod & Container Security Hardening (privileges, capabilities, seccomp, host namespaces, images)
6. Service Account Configuration (IRSA annotations, token automounting)
7. RBAC Posture (cluster-admin bindings, wildcard roles, sensitive subjects)
8. Network Segmentation & Policies (default stance, permissive ingress/egress)
9. Network Exposure of Services (LoadBalancers, Ingress TLS, wildcard hosts)
10. Configuration & Secret Management (ConfigMap data scrutiny, secret key analysis)
11. High-Risk Combination Detection (20 same-workload attack chains)
12. Cross-Scope Attack Chain Detection (8 infrastructure-to-workload chains)

---

## Finding-Validation-Guide.md

A manual validation checklist for every finding type EKS Scout can produce. Use it to:

- **Verify findings** — run the listed `kubectl` / `aws` commands to confirm each finding before including it in a report
- **Understand context** — each finding includes what it means, why it matters, and what to look for
- **Train new team members** — the guide doubles as a learning resource for EKS security assessments

### Coverage

The guide covers 11 sections with validation steps for every finding type:

1. Cluster Configuration (public API endpoint, control plane logging, secrets encryption)
2. Nodegroup Security (SSH access, node IAM roles, IMDSv2)
3. IRSA Configuration (trust policy conditions, role permissions)
4. Namespace Governance (PSA labels, resource quotas, limit ranges)
5. Pod & Container Security (host namespaces, hostPath, privileged, capabilities, seccomp, root, privilege escalation, read-only filesystem, resource limits, image tags)
6. Service Account Security (token automounting)
7. RBAC (cluster-admin bindings, wildcard roles, sensitive subjects, default SA bindings)
8. Network Policies (missing policies, permissive ingress/egress)
9. Service Exposure (LoadBalancers, Ingress without TLS, wildcard hosts)
10. Secrets & ConfigMaps (sensitive keys in ConfigMaps, sensitive keys in Secrets)
11. High-Risk Combinations & Attack Chains (same-workload combos, cross-scope chains)

---

## Typical Workflow

```
1.  Run EKS Scout against the target cluster
       python -m eks_scout.scanner --cluster my-cluster

2.  Generate the client report body
       python supplemental/csv-to-report.py -i findings.csv -o report.md --cluster my-cluster

3.  Validate findings before finalizing the report
       Open supplemental/Finding-Validation-Guide.md and run the commands for each finding type

4.  Assemble the final deliverable
       - Copy client-report-methodology.md into the methodology section
       - Copy the generated report.md into the findings section
       - Add executive summary, scope, and recommendations as needed
```
