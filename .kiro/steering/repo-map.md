---
inclusion: always
---
# Repo map — AWS Kiro in FSI Best Practices

MAS-aligned Kiro for financial services (banking reference implementation): docs + CDK + Skills/hooks (workload region `ap-southeast-1`; Kiro profile region `us-east-1` or `eu-central-1`).

- **Full doc map & onboarding:** `AGENTS.md` (agents) and the "Start Here" section of `README.md` (humans).
- **Admin policy (client-enforced):** `managed-settings/` (`managed-settings.json`, `permissions.yaml` template, MCP registry example).
- **Governance model and console settings:** `kiro-docs/agent-runtime-governance.md` (Layer 4); console/registry layer and model approval matrix: `kiro-docs/security-governance-features.md`; MDM deployment across OSes: `kiro-docs/mdm-endpoint-enforcement.md`; Windows with Microsoft Intune: `kiro-docs/intune-deployment.md` (example scripts in `mdm/examples/`: a policy-step script for devices in Constrained Language Mode and a check-first Kiro IDE install wrapper; not part of the reference deployment).
- **Reference agent + hooks (defense in depth):** `agent-hooks/`. **Red-team validation:** `security-tests/chaos/` + report `kiro-docs/chaos-pentest-evidence.md`. **Integration test (sandbox AWS account):** `security-tests/aws-integration/` + results `kiro-docs/aws-integration-test-evidence.md`. **Windows 11 client validation kit (W2, issue #43; run on a Windows 11 26H2 VM on 2026-11-19/20; Round 2 with Kiro IDE 1.5.11 on 2026-11-21 and Round 3 (re-test with a named control per test) on 2026-11-27, results in `kiro-docs/mdm-test-evidence.md`; the issue stays open):** `security-tests/windows-client/`.
- **Rules:** never commit secrets/PII; nothing under `.kiro/specs|hooks|settings/`; hooks live in top-level `agent-hooks/`; validate with `./validate-repo.sh` + `bash agent-hooks/tests/run-tests.sh`; update `README.md`, `CHANGELOG.md` and every related doc in the same pull request.
