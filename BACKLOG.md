# EKS Scout v2 Backlog

## Must-Fix for v2

- [x] **1. Wire up severity overrides** — Legacy `add_finding()` never passes `check_id`, so `severity_overrides` config is non-functional. Need to propagate check IDs through all check modules.
- [x] **2. Add Linux capabilities check** — `config.py` defines `sensitive_capabilities` but no check reads it. `SYS_ADMIN` capability is equivalent to `privileged: true` but produces zero findings. Also check for missing `drop: ["ALL"]`.
- [x] **3. Add egress network policy analysis** — Network policy check only examines ingress. No detection of missing egress policies, overly broad `to` rules, or `0.0.0.0/0` egress.
- [x] **4. Flag NodePort services** — Network exposure check only flags `LoadBalancer`. `NodePort` exposes pods on every node IP.
- [x] **5. Add `--fail-on` CLI exit code** — Scanner always exits 0. Need `--fail-on critical|high|medium|low` for CI/CD pipeline gating.

## Should-Do for v2

- [ ] **6. Seccomp profile check (CIS 5.7.2)** — No check for `securityContext.seccompProfile`. The `restricted` PSA level requires `RuntimeDefault` or `Localhost`.
- [ ] **7. EKS version currency check** — Cluster version is INFO only. End-of-life K8s versions should be HIGH. Add configurable `min_kubernetes_version`.
- [ ] **8. Fix image tag detection** — `registry:5000/image` (port in registry) passes `:` check with no tag. Digest images (`@sha256:...`) are falsely flagged.
- [ ] **9. Internal vs external LoadBalancer** — Differentiate `service.beta.kubernetes.io/aws-load-balancer-internal` from internet-facing. Lower severity for internal LBs.
- [ ] **10. CLI flags** — `--min-severity`, `--version`, `--namespace` / `--exclude-namespace` for scan scoping.
- [ ] **11. `runAsGroup: 0` check** — Pods check ignores `runAsGroup`. Running as root group allows access to root-group-owned files.
- [ ] **12. RBAC sensitive resources** — Add `nodes/proxy`, `mutatingwebhookconfigurations`, `validatingwebhookconfigurations`, `persistentvolumes`, `pods/log` to sensitive resources list.

## Post-Release Backlog

- [ ] Actual IMDSv2 check via `describe-launch-template-versions` (requires EC2 permissions)
- [ ] Fargate profile support (`list-fargate-profiles` / `describe-fargate-profile`)
- [ ] EKS add-on version checks (`list-addons` / `describe-addon`)
- [ ] AppArmor annotation checks
- [ ] HTML report format for client-facing deliverables
- [ ] SARIF output for GitHub Advanced Security / CI platforms
- [ ] Diff/delta mode for comparing scans over time
- [ ] Unit test suite
- [ ] `--list-checks` / `--dry-run` mode
- [ ] Resource count summary in JSON output (pods scanned, namespaces, etc.)
- [ ] Progress indicator for large clusters
- [ ] PSA `privileged` level flagged at HIGH (currently same severity as unknown values)
- [ ] Secrets check: apply key-pattern matching to Opaque secrets, not just ConfigMaps
- [ ] CIS reference audit (verify numbers match CIS Amazon EKS Benchmark, not generic K8s benchmark)
