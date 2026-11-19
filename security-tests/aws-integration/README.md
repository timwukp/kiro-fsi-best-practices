# AWS integration test (isolated sandbox)

End-to-end validation of this repository in a **sandbox AWS account**. It runs what unit tests, `cdk synth` and dry runs cannot prove: a real CDK deployment, the root and admin MDM lockdowns, the full chaos harness, the `nat-dns-firewall` egress mode and the Kiro CLI on a hardened host.

> **Sandbox accounts only.** The CDK deploy creates account-level resources in the workload region: a CloudTrail trail, AWS Config rules, and optionally GuardDuty, Security Hub, an Access Analyzer and a Config recorder. The orchestrator detects existing account singletons and does not touch them.

## What it creates (all tagged `Project=kiro-fsi-test`, region `ap-southeast-1` by default)

| Resource | Security posture |
|---|---|
| `harness.yaml`: isolated VPC `10.250.0.0/24`, Linux (AL2023) and Windows Server 2022 runners, results bucket | **No inbound rules, no SSH keys.** Access only through AWS Systems Manager. IMDSv2 required, encrypted gp3, `InstanceInitiatedShutdownBehavior=terminate` plus an on-instance failsafe shutdown timer (8 h default). Bucket uses SSE-KMS, blocks public access, enforces TLS and expires objects after 7 days. |
| Runner IAM role | `AmazonSSMManagedInstanceCore`, plus read/write on the results bucket and `ssm:GetParameter` on `/kiro-fsi-test/*`. **No deploy permissions:** the CDK deploy runs from the operator's machine. |
| The repo's 5 CDK stacks (`env=dev`) | Synthesized offline with `cdk synth` (real AZs injected into the context for the run only, never committed), deployed with the AWS CLI through the CDK bootstrap bucket and CloudFormation execution role, verified, then deleted. RETAIN resources are cleaned up afterwards (KMS keys go to a 7-day pending deletion). |
| `probe.yaml`: egress probe in the CDK WorkSpaces subnet | Same posture as the runners; used to test the DNS Firewall allowlist and Kiro CLI sign-in paths. |

## Test matrix

| ID | Where | Checks |
|---|---|---|
| L1 | Linux runner | CI parity on GNU/Linux: `npm ci`, `npm audit`, tsc, lint, jest, `cdk synth` variants, hook tests, PII patterns, admin policy tests, `validate-repo.sh`, `SHA256SUMS`, `bash -n`, MDM dry runs |
| L2 | Linux runner (root) | Root-mode MDM suite, plus a real `lockdown-linux.sh`. Checks immutability, that a non-root user cannot modify or delete the policy, hook hashes, drift detection (`--check` exit 3), restore, and that the audit log can be appended to but not truncated. |
| L3 | Linux runner (root) | Full chaos harness, rounds 1 and 2. Requires 0 BYPASSED and 0 sanity failures. |
| W1 | Windows runner (SYSTEM) | `test-lockdown-windows.ps1` in default and admin mode, under Windows PowerShell 5.1 and PowerShell 7. A real `lockdown-windows.ps1` must produce UTF-8 without a BOM, the Users DENY ACE, and correct drift and restore behaviour. |
| W3 | Windows runner (SYSTEM) | PowerShell hook guards (`agent-hooks/tests/run-tests.ps1`) under Windows PowerShell 5.1 and PowerShell 7. Unit tests with crafted hook events; no Kiro client invokes the guards |
| W4 | Windows runner (SYSTEM) | Intune flow on the real paths, with the Intune execution contexts simulated (no Intune tenant): the Win32 install command (`-StageSources -DeployHooks -InstallUser -DisableUpdates`) started from **32-bit** PowerShell; `UpdateMode` in the 64-bit registry view; a plain 32-bit write to `HKLM\SOFTWARE\Policies` visible in the 64-bit view; the Users DENY ACE on the staged sources and the PowerShell guards; the Default-profile hook file; the Remediations detection, remediation and Win32 detection wrappers from 64-bit **and** 32-bit hosts, before and after an administrator tamper; uninstall (`-RemoveSources`) removes only the staged sources |
| WC | Windows runner (SYSTEM); **opt-in** stage `client`, never part of `all` | Label: **Windows Server 2022, outside Kiro's listed operating systems (Windows 10/11): installer mechanics only, no signed-in Kiro client.** [`windows-client-suite.ps1`](windows-client-suite.ps1) reads Kiro's update manifest, downloads the current Kiro IDE system-wide installer (the URL must be on `prod.download.desktop.kiro.dev`; with a 20-minute limit) and records its version, size and SHA-256 (`WC.manifest`, `WC.download`). It then runs the automatable part of the W2 kit ([`security-tests/windows-client/`](../windows-client/README.md)) under Windows PowerShell 5.1 with `-InstallerPath -InstallPolicy -Wrappers -TamperTest`, and adds `-Install` and `-ExpectedSignerSubject` only when the Authenticode status of the installer is `Valid` and its signer subject starts with the CN, OU and O of the subject measured for release 1.4.236 (`WC.signature-gate` PASS; the pin is in the suite). Otherwise `WC.signature-gate` is FAIL and the installer is not run, but the kit still runs: it records W2.2, deploys the policy and runs the wrapper and tamper checks. What the kit checks: silent install exit code, Uninstall registry entry and its registry view, install folder, signer, `UpdateMode` in both registry views, the policy file, and the Intune wrappers as 64-bit and 32-bit SYSTEM before and after a tamper. The kit's `CHECK W2.*` lines are passed through unchanged and counted in the `PHASE WC` line; `WC.kit` says whether the kit ran to its end with an exit code that matches its FAIL lines. The suite then repeats the kit's read-only part (`-InstallerPath`, and the same `-ExpectedSignerSubject` when the gate passed: W2.2 and the inventory) under PowerShell 7 (installed by the `windows` stage) and fails `WC.kit-pwsh7` if a check ends differently from the Windows PowerShell 5.1 run; those lines carry the prefix `PWSH7` and are not counted. Last, it lists the top-level names of the install folder (`WC.install-folder-entries`) and records the uninstall command (`WC.uninstall-command:<hklm64|hklm32>`). The uninstall command runs only with `IT_WC_UNINSTALL=1` (`WC.uninstall:<view>`, `WC.uninstall-leftovers:<view>`). With `IT_WC_STOP_KIRO=1` the suite first stops Kiro processes that run from the install folder (`WC.stop-kiro:<when>`, INFO). Not covered: everything that needs a Kiro window or a logged-on standard user (the manual parts of W2.1 and W2.3 to W2.5, all of W2.6 to W2.9, and context `user` of W2.10) |
| C1 | operator machine | Real deployment of the synthesized CDK app (all 5 stacks). Checks: KMS rotation, VPC endpoints, NACL association, WorkSpaces SG egress, flow logs with CMK, CloudTrail delivery to S3 and CloudWatch Logs, audit bucket Object Lock / versioning / public-access block / SSE-KMS / noncurrent expiration, **alarm actions delivered to the KMS-encrypted SNS topic** (each alarm is forced OK → ALARM, so an alarm that real activity already triggered is still tested), 19 Config rules evaluating without errors (a rule that has not started passes only if it is explicitly scoped and the account holds 0 resources of its scoped types), backup schedule |
| C2 | probe | `egress.mode = nat-dns-firewall`: allowlisted Kiro hosts resolve and answer over HTTPS; non-allowlisted hosts are blocked |
| K1 | probe | Kiro CLI installs through the allowlist; managed settings, hooks and the agent are deployed by MDM |
| K2 | probe | Only if a Kiro API key is stored at `/kiro-fsi-test/kiro-api-key` (SSM SecureString). `kiro-cli chat --no-interactive --trust-all-tools` must have a force-push blocked (remote ref unchanged), an NRIC write blocked, a benign command succeed, and hook audit records written. With Kiro CLI 3.4.0+ (V3 harness named explicitly), each with a positive control: a `PermissionRequest` hook that answers `allow` still cannot answer the admin `ask` rule on `git push*`, and a Pre Tool Use `updatedInput` rewrite to `git push --force` is still denied by the admin policy. |

**Not covered by any phase:** Kiro itself running on Windows. The Windows runner is Windows Server 2022, nothing runs as a logged-on standard user, and no Intune tenant is involved. No Kiro IDE or CLI is installed on it, except by the opt-in WC phase, which installs the IDE and never signs in. (The kit's default switches include `/MERGETASKS=!runcode`, so WC does not start Kiro; without that switch the installer starts Kiro when it ends, as SYSTEM in session 0.) The Windows 11 client validation (W2, issue #43) is not a phase of this test: a person runs it on a Windows 11 test device with the kit in [`security-tests/windows-client/`](../windows-client/README.md) (`Invoke-W2Checks.ps1`, the hook probe and the manual checklist). **That run has not been done yet**, so whether Kiro on Windows enforces the policy, loads global hooks and loads global steering is still untested.

## Run

Prerequisites:
- AWS CLI v2 and credentials for the sandbox account;
- `jq`;
- Node.js 20+ with `cdk/node_modules` installed.

```bash
export IT_REGION=ap-southeast-1   # an inherited AWS_REGION is ignored
bash security-tests/aws-integration/run-integration.sh preflight up bundle
bash security-tests/aws-integration/run-integration.sh linux windows
bash security-tests/aws-integration/run-integration.sh client   # opt-in (WC): Kiro IDE installer + W2 kit on the Windows runner;
#             run it after the windows stage, which installs the PowerShell 7 that WC.kit-pwsh7 needs
# WC options: IT_WC_UNINSTALL=1 (also run the uninstaller), IT_WC_STOP_KIRO=1 (stop Kiro processes first),
#             IT_WC_INSTALLER_ARGS='/VERYSILENT /SP- /SUPPRESSMSGBOXES /NORESTART /LOG=C:\kiro-test\w2\kiro-install-runcode.log'
#             (replaces ALL default switches, including /LOG; this example leaves out /MERGETASKS=!runcode,
#             so the installer starts Kiro when it ends)
bash security-tests/aws-integration/run-integration.sh deploy verify egress
# after fixing anything: bundle + re-run the failing stage
# re-verifying long-lived stacks: IT_VERIFY_WAIT=30 skips most of the 6-minute first-delivery wait
bash security-tests/aws-integration/run-integration.sh down leftovers
```

State and raw logs go to `$IT_WORKDIR` (default `$TMPDIR/kiro-fsi-it`) and are **never committed**. When summarising results, the orchestrator masks account IDs, instance and resource IDs, and IP addresses. Tear down with `down` even after a failed run; `leftovers` must report `LEFTOVERS total=0`. KMS keys pending deletion are listed as `EXPECTED`. Resources that the Resource Groups Tagging API still lists but that their own service reports as deleted are listed as `STALE`. A name-prefix scan also covers untagged and retained resources.

The test-only DNS Firewall additions (SSM, the results bucket and the AL2023 package mirrors, passed with `-c egressAllowedDomains=`) exist only to drive the probe. A production allowlist does not need them.

> **Why not `cdk deploy`?** In the test environment the CDK CLI's Node.js HTTP connections were repeatedly dropped (`aborted` / `Deserialization error`) by an intermediate egress proxy, while the Python AWS CLI was unaffected. The assembly contains no Lambda or Docker assets, so deploying the synthesized templates with CloudFormation is equivalent. `cdk deploy --all` remains the normal deployment path for users.

Results from the last run: [`kiro-docs/aws-integration-test-evidence.md`](../../kiro-docs/aws-integration-test-evidence.md).
