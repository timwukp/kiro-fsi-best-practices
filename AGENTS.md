# AGENTS.md — Repository guide for AI agents

> Auto-loaded by Kiro's default agent (alongside `README.md`, `.kiro/skills/`, `.kiro/steering/`).
> Human entry point: the **Start Here** section in [`README.md`](README.md). Keep this file terse.

## What this repo is
MAS-aligned best practices for deploying **AWS Kiro** in Singapore **financial services (FSI)** SDLC, with a **banking** reference implementation. Repository: `timwukp/kiro-fsi-best-practices` (renamed from `kiro-banking-best-practices`; file names and CDK physical names keep "banking" and must not be renamed). Contents: documentation, AWS **CDK** (TypeScript) infrastructure, Kiro **managed settings**, and Kiro **Skills + hooks**. Workload region: `ap-southeast-1`; Kiro profile region: `us-east-1` or `eu-central-1` (Kiro has no Singapore profile region).

## Task → file
| If you need to… | Read / use |
|-----------------|------------|
| Deploy the admin policy (deny/ask rules, sign-in restriction), user permissions template, MCP registry example | `managed-settings/README.md` ← start here |
| Permission model reference (capabilities, precedence, hardcoded invariants, workspace trust, hooks, agents) | `kiro-docs/permissions-and-managed-settings.md` |
| Layer 4 governance model (admin policy → console settings → workspace trust → permissions → hooks → audit) | `kiro-docs/agent-runtime-governance.md` |
| Kiro console governance (models, MCP registry, web tools, API keys, Cloud Sessions) + model approval matrix | `kiro-docs/security-governance-features.md` |
| Defense-in-depth hooks and the reference agent | `agent-hooks/README.md`, `agent-hooks/hooks/banking-guards.json` |
| Deploy managed files with MDM (all OSes) | `kiro-docs/mdm-endpoint-enforcement.md`, `mdm/` |
| Windows with Microsoft Intune (system-wide installer, Win32 app + staging, Remediations wrappers, `UpdateMode`, per-user hooks) | `kiro-docs/intune-deployment.md`, `mdm/lockdown-windows.ps1`, `mdm/intune/`; `mdm/examples/` (example scripts: a policy-step script for devices in Constrained Language Mode and a check-first Kiro IDE install wrapper; not part of the reference deployment) |
| MCP governance (registry, pinned versions, config files) | `Kiro-Banking-Best-Practices-Part2.md` Section 5, `kiro-docs/mcp-security.md` |
| Auth, network & VDI (Sections 1–4) | `Kiro-Agentic-SDLC-Banking-Best-Practices.md` |
| MCP, SDLC, PDPA, FEAT (Sections 5–14) | `Kiro-Banking-Best-Practices-Part2.md` |
| Build a MAS-aligned Kiro Skill | `Banking-Skills-Development-Guide.md` |
| Red-team / validate the controls (chaos test) | `security-tests/chaos/run-chaos.sh`, `kiro-docs/chaos-pentest-evidence.md` |
| Integration test in a sandbox AWS account (EC2 runners, real CDK deploy, teardown) | `security-tests/aws-integration/README.md`, `kiro-docs/aws-integration-test-evidence.md` |
| Validate Kiro on a Windows 11 client (W2 kit, issue #43: installer, policy enforcement, global hooks, steering, Intune contexts). Run on a Windows 11 26H2 VM on 2026-11-19 and 2026-11-20 (Kiro IDE 1.4.236, Kiro CLI 3.5.0); Round 2 on 2026-11-21 and Round 3 on 2026-11-27 (Kiro IDE 1.5.11, Intune emulated; results in `kiro-docs/mdm-test-evidence.md`; Round 3 names a control per test and lists invalid tests as open); the issue stays open; its automatable part also runs as the opt-in integration-test stage `client` (WC) | `security-tests/windows-client/README.md`, `security-tests/windows-client/W2-manual-checklist.md` |
| Deploy infrastructure | `cdk/` (see `cdk/README.md`) |
| MAS TRM mapping | `README.md` → "Compliance Framework" |

## Hard rules when working in this repo
- **Never commit secrets/PII** (real keys, NRIC, tokens, account IDs). Use placeholders: `example.com`, `AKIA…EXAMPLE`, `123456789012`.
- **Do not track** anything under `.kiro/specs/`, `.kiro/hooks/`, or `.kiro/settings/` (CI rejects it). `.kiro/skills/` and `.kiro/steering/` **are** committed.
- Agent **hooks live in top-level `agent-hooks/`**, not `.kiro/hooks/`; admin policy files live in `managed-settings/`.
- **Admin rules (`managed-settings*.json`) use only `deny` or `ask`** and only the documented fields; an `allow` rule or unknown field makes Kiro reject the whole file and deny all tool calls. Make every rule change in **both** policy files (they differ only in rule 1), keep patterns free of backslashes, start shell patterns with the command name, and update the rule table in `managed-settings/README.md` and `managed-settings/tests/shell-vectors.tsv`.
- **Kiro claims:** cite the official kiro.dev page with a verification date; where pages conflict, follow the newer one and note the conflict. Do not call a control "tamper-proof" or "fail-closed" unless Kiro documents it as such.
- **Changes go through a pull request** from a feature branch; never push to `main`. CI (`.github/workflows/validate.yml`) must pass. Run the commands below first.
- **Docs move with the change:** in the same pull request, update `README.md`, `CHANGELOG.md` and every doc that describes the changed behaviour, command, count or status. That includes `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md` (CI description), component READMEs, the `kiro-docs/README.md` index and the evidence pages. Search for the old wording (`grep -rn`) before you finish. If a follow-up is needed, open a new pull request.
- Default to **least privilege**.

## Commands (run from the repo root; CI runs the same)
| Check | Command | Expect |
|-------|---------|--------|
| Repo validator (read-only: required files, secrets/PII, links) | `./validate-repo.sh` | `RESULT: PASSED` (0 errors) |
| CDK tests / lint / synth | `cd cdk && npm test`; `npm run lint`; `npx cdk synth --context env=dev` | 91 tests pass; lint clean; synth OK (cdk.json builds with `tsc`) |
| Agent hooks (bash + jq) | `bash agent-hooks/tests/run-tests.sh` | `PASS=98 FAIL=0` |
| PII skill patterns (grep -E; perl for PCRE) | `bash .kiro/skills/pii-detection/tests/patterns.test.sh` | `PASS=346 FAIL=0` |
| MDM dry run (non-root, no system changes) | `bash mdm/tests/test-lockdown.sh` | `FAIL=0` |
| Windows MDM + Intune wrappers (Windows only; CI job `validate-windows`) | `powershell -ExecutionPolicy Bypass -File mdm\tests\test-lockdown-windows.ps1` | `FAIL=0` |
| PowerShell hook guards (Windows only; CI job `validate-windows`) | `powershell -ExecutionPolicy Bypass -File agent-hooks\tests\run-tests.ps1` | `FAIL=0` |
| Hook manifest | `(cd agent-hooks && shasum -a 256 -c SHA256SUMS)` | all `OK` |
| Admin policy effects | `jq -e '[.rules[].effect] \| all(. == "deny" or . == "ask")' managed-settings/managed-settings*.json` | `true` |
| Admin policy structure, README rule table and shell vectors | `bash managed-settings/tests/test-policy.sh` | `FAIL=0` |

## Hard rules for `cdk/`
- **cdk-nag** `AwsSolutionsChecks` is enabled by default and every stack must pass it; a suppression needs a written reason.
- **KMS:** customer-managed keys with key rotation enabled and `RemovalPolicy.RETAIN`.
- **Network:** the default egress mode is `none` (no public subnets, NAT gateways or internet gateways); `nat-dns-firewall` stays opt-in.
- **Regions:** workload region `ap-southeast-1`; Kiro profile region `us-east-1` or `eu-central-1` (`cdk/config/kiro-endpoints.ts`).
- **AWS Config rules:** when you add or remove a rule in `compliance-stack.ts`, update the `ComplianceRuleCount` CfnOutput and the count in `test/stacks.test.ts` in the same change.
- **Run `cd cdk && npm test`** (and `npm run lint`) after every CDK change.
- **Lockfile:** regenerate `cdk/package-lock.json` with npm 10 (the npm bundled with Node.js 22, which CI uses), e.g. `npx -y npm@10 install --package-lock-only`; an npm 11 lockfile can fail `npm ci` in CI.
- **Never rename** physical resource names, stack IDs, construct IDs of deployed resources or CfnOutput export names: renames replace or orphan retained resources and break cross-stack references.
- Map infrastructure to the MAS TRM sections it supports, and keep those cross-references in the docs.

## Enforced vs defense-in-depth vs guidance
- **Enforced by Kiro (client-side):** admin `deny`/`ask` rules and the sign-in restriction in `managed-settings.json` (an invalid file blocks all tool calls but drops the sign-in restriction); Kiro console settings (model allow list, MCP governance + registry, web tools, API keys, Cloud Sessions); workspace trust; Kiro hardcoded invariants (the agent can never write `~/.kiro/settings/` or `.kiro/settings/`, and always asks before writing `.git/**` or `.kiro` agents/hooks/workflows/powers). A user with local admin rights can bypass client-side controls; the authoritative boundaries are server-side (branch protection, IAM, egress allowlist). Measured limits (Kiro CLI 3.5.0, 2026-11-19/20): `--trust-all-tools` approves commands under an admin `ask` rule in headless runs (a `deny` holds), and on Windows shell rules match case-sensitively, so a casing the policy does not list runs. In Kiro IDE 1.5.11 (Windows 11 VM, 2026-11-21, one run in each of two modes) the all-capitals spelling was not refused by the deny rule in Supervised mode (Kiro asked the user), and in "Approve for me" Kiro reported that it ran the command, which is consistent with the rule not matching it; limits in `managed-settings/README.md`. Round 3 (same lab VM, 2026-11-27, one run per test with a named control, no approval button clicked) measured it from a trace file: for `Invoke-WebRequest` the listed spelling did not run and gave no prompt in all three modes, and the all-capitals spelling gave an approval prompt in Supervised and in "Accept file changes" and ran with no prompt in "Approve for me" (T-CASE-04a); a second cmdlet, `Invoke-Expression`, gave the same outcome in Supervised and in "Approve for me" (T-CASE-05a) and was not tested in "Accept file changes". What stopped the listed spelling is not a check. Treat shell deny rules there as a guardrail, not a boundary, and control egress with a network control.
- **Defense-in-depth:** user `permissions.yaml`, agent `permissions`, hooks (block only with exit code 2; measured in Kiro IDE 1.5.11 with a lab test guard on 2026-11-27: exit code 2 blocked, and exit code 1, a guard that ran 45 seconds with a timeout value of 10, and a missing guard file did not block, T-HOOK-01a, 02a, 02b, 03a, 03b, 04a), OS-level protection of the managed files by MDM.
- **Guidance (advisory only):** `.kiro/steering/*`, `.kiro/skills/*`, this file.
