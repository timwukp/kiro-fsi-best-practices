# AWS Integration Test — Evidence

Results of the isolated integration test in [`security-tests/aws-integration/`](../security-tests/aws-integration/README.md), run in a **sandbox AWS account** (`ap-southeast-1`) on disposable EC2 runners and torn down afterwards. This page records two runs:

| Run | Scope | Section |
|-----|-------|---------|
| **2026-11-19** (v1.10) | Linux and Windows runners only: the Windows / Microsoft Intune change for issue #42 (MDM script, Intune wrappers, PowerShell hook guards, admin policy tests) and CI parity on Linux | [Run of 2026-11-19](#run-of-2026-11-19-v110-windows-and-intune) |
| **2026-10-10** (v1.9.1) | Full test: runners, a real deployment of all 5 CDK stacks, the DNS Firewall egress mode and the Kiro CLI behind the allowlist | [Run of 2026-10-10](#run-of-2026-10-10-v191-full-test) |

> **Sanitized.** Account IDs, ARNs, instance, VPC, subnet and key IDs, IP addresses, bucket names and SSM command IDs are removed. The CHECK/PHASE lines below are verbatim apart from that. Raw logs stayed in the test's results bucket (7-day expiry, deleted at teardown) and on the operator's machine, and are not committed. No Kiro API key or other secret was used in, or written to, any log. The two SHA-256 values in the `W4.detect-drift` CHECK line are the hash of this repository's public policy file (`managed-settings/managed-settings.banking.json`) and the hash of the copy the suite tampered with (the same file with one space and a line ending appended); neither is derived from account data.

## Coverage: what was and was not tested

"Tested" means executed in one of the two runs on this page. Everything else in this repository that describes Kiro's behaviour rests on the official Kiro documentation (cited with the date checked) or is marked *verify*.

| What | Linux (Amazon Linux 2023) | Windows Server 2022 | Windows 10/11 client | macOS |
|------|---------------------------|---------------------|----------------------|-------|
| MDM lockdown script on the real system paths, as root / SYSTEM | Tested (L2) | Tested (W1) | Not tested | Not tested (dry-run tests only, run on a developer Mac) |
| Intune wrappers: detection, remediation, Win32 detection, started as SYSTEM from 64-bit and 32-bit PowerShell | — | Tested (W4); the contexts are simulated, no Intune tenant | Not tested | — |
| The same as a logged-on standard user | — | Not tested | Not tested | — |
| A real MDM tenant (Intune, Jamf, Kandji) | Not tested | Not tested | Not tested | Not tested |
| Hook guards, fed crafted hook events (unit tests) | Tested: bash guards (L1) | Tested: PowerShell guards (W3) | Not tested | Bash tests run on a developer Mac |
| Hook guards invoked by a Kiro client | Not tested (K2 skipped) | Not tested | Not tested | Not tested |
| Kiro CLI installed and locked down by the MDM script | Tested on 2026-10-10 (K1, CLI 2.29.0) | Not tested | Not tested | Not tested |
| Kiro IDE installed; the system-wide installer | — | Not tested | Not tested | Not tested |
| Kiro enforcing `managed-settings.json` (rules, sign-in restriction) | Not tested (K2 skipped: no Kiro API key) | Not tested | Not tested | Not tested |
| Admin policy rules: structure and expected effect per command | Tested as a **simulation** of Kiro's documented matching (`managed-settings/tests/test-policy.sh`, L1.policy); it does not drive a Kiro client | Not run on Windows: the simulation ran on Linux only (the same policy file is deployed to every OS) | — | — |
| CDK deployment, DNS Firewall egress, alarms, Config rules | Tested on 2026-10-10 (C1, C2) | — | — | — |

The Windows 11 client validation (Kiro IDE and CLI installed, policy enforcement, global hooks, steering, a logged-on user) is tracked in issue #43. "W2" is reserved for it and is not used on this page.

## Run of 2026-11-19 (v1.10): Windows and Intune

All required checks pass on the final code of this change (base `main` at ed23e48 plus the change for issue #42). The Windows and Linux suites were re-run on the final bundle after the last fix.

| ID | Suite | Where | Result |
|----|-------|-------|--------|
| W1 | Windows MDM: `test-lockdown-windows.ps1` and a real `lockdown-windows.ps1` | Windows runner (SYSTEM) | **14/14 PASS**: suite 102/102 (default) and 136/136 (admin) under Windows PowerShell 5.1 and PowerShell 7 |
| W3 | PowerShell hook guards | Windows runner (SYSTEM) | **5/5 PASS**: 384/384 cases (1 documented known gap) under Windows PowerShell 5.1 and PowerShell 7; one guard call takes about 1 second |
| W4 | Intune flow on the real paths | Windows runner (SYSTEM) | **30/30 PASS** |
| L1 | CI parity on GNU/Linux | Linux runner | **18/18 PASS**, including the admin policy tests (`L1.policy`) |
| L2 | Root MDM: real `lockdown-linux.sh` | Linux runner (root) | **16/16 PASS** |
| L3 | Full chaos harness, rounds 1 and 2 | Linux runner (root) | **2/2 PASS**: 0 BYPASSED, 0 sanity failures |
| C1, C2, K1, K2 | CDK deployment, egress, Kiro CLI | — | **Not run** in this change. C1, C2, K1: no CDK or egress code changed; see the 2026-10-10 run. K2: its code changed (new `PermissionRequest` and `updatedInput` cases), but it needs a Kiro API key and has never been run; see [Not covered in this run](#not-covered-in-this-run) |
| T1 | Teardown and leftover scan | sandbox account | See [Teardown (2026-11-19)](#teardown-2026-11-19) |

### Method

- **Harness.** [`harness.yaml`](../security-tests/aws-integration/harness.yaml) creates a dedicated VPC, a security group with no inbound rules, one Linux and one Windows runner reached only through AWS Systems Manager (no SSH keys), IMDSv2, encrypted volumes, terminate-on-shutdown with an 8-hour failsafe, and a short-lived results bucket.
- **Bundle.** `run-integration.sh bundle` packs the working tree (tracked and untracked files that are not ignored) and uploads it to the results bucket. Each runner downloads and unpacks it, so the runners test exactly the tree on the operator's machine.
- **Execution.** `run-integration.sh windows linux` sends one SSM command for the Windows suite (W1, W3 and W4 together, reported in one `PHASE` line) and one per Linux phase (`setup`, which installs the packages and Node.js and passed 2/2, then L1, L2 and L3). Command output goes to the results bucket and is copied back; the orchestrator prints every `CHECK ... FAIL|SKIP` line and each `PHASE` line.
- **Windows runner (as SYSTEM).** [`windows-suite.ps1`](../security-tests/aws-integration/windows-suite.ps1) runs:
  - **W1:** `mdm/tests/test-lockdown-windows.ps1` in default and admin mode under both PowerShell versions (temporary prefix, never the real `C:\ProgramData`), then a real `lockdown-windows.ps1` on `C:\ProgramData\Kiro` with a tamper, `-Check` and restore.
  - **W3:** `agent-hooks/tests/run-tests.ps1` under both PowerShell versions (each guard is started as its own process and fed a hook event on STDIN), and the latency of one call of each guard.
  - **W4:** the Intune flow on the real paths. The Win32 install command (`-StageSources -DeployHooks -InstallUser -DisableUpdates`) is started from 32-bit PowerShell, as Microsoft documents for `powershell.exe` in an install command. The two detection wrappers are then run from 64-bit and 32-bit PowerShell with STDOUT and STDERR captured separately, before and after an administrator-style tamper (the Users DENY ACE and the content of the policy file, the Default profile's hook file, `UpdateMode`). The remediation wrapper is run from 64-bit PowerShell on that tamper and from 32-bit PowerShell on a second tamper of the policy file only, followed by the uninstall command.
- **Linux runner.** [`linux-suite.sh`](../security-tests/aws-integration/linux-suite.sh) runs L1 (what CI runs, plus all four synth variants), L2 (a real `lockdown-linux.sh` as root with a non-root test user) and L3 (the chaos harness, rounds 1 and 2).
- **Pass criterion.** Every `CHECK` must be `PASS`, and every embedded suite must report `FAIL=0`. No `CHECK` was skipped (`skip=0` in every `PHASE` line). Inside the embedded suites one case was skipped: the macOS-only honesty check of `mdm/tests/test-lockdown-macos.sh`, which reports `PASS=30 FAIL=0 SKIP=1` when run on Linux (`L1.mdm-macos-dry-run`).
- **State between runs.** The runners were not reset between the nine runs. In the final run `C:\ProgramData\Kiro` and the policy already existed from the previous run (the deployment logged the policy as unchanged; the write by this script version is shown by the restore after the tamper), and on Linux the test user and the hook scripts were reused. A first deployment of the final code on clean real paths was exercised only under the temporary prefix of the embedded suites.

### Environment

| Item | Value |
|------|-------|
| Account | The same sandbox account as on 2026-10-10, `ap-southeast-1`. Only the harness stack was created; no CDK stack was deployed |
| Windows runner | Windows Server 2022 (latest AWS-provided English Full Base image), t3.medium, Windows PowerShell 5.1 and PowerShell 7.6.10. **No Kiro IDE or Kiro CLI installed** |
| Linux runner | Amazon Linux 2023 x86_64, t3.medium, Node.js v22.23.5 |
| Identity | Commands ran as SYSTEM (Windows) and root (Linux) through SSM |

### Process: runs, failures and fixes

Nine runs were made on the same harness (start times in UTC; approximate for runs 1 to 4, whose orchestrator logs were not kept). A run that failed was fixed at the root cause and repeated.

| Run | Time | Code under test | Result |
|-----|------|-----------------|--------|
| 1 | 02:56 | Intune wrappers, `-StageSources`, `-DisableUpdates`, `-InstallUser`, first PowerShell guards | Windows 36 pass, **2 fail**: the hook test runner did not parse (finding 1) |
| 2 | 03:03 | Fix for finding 1 | Windows 38/38; hook guards 135/135 |
| 3 | 03:17 | Windows rules added to the admin policy | Windows 38/38; L1 17/17; L2 15 pass, **1 fail** (finding 2); L3 2/2 |
| 4 | 03:34 | Fix for finding 2; admin policy tests added to L1 | All pass |
| 5 | 03:50 | `auth_portal_url` validation; phases renamed to W3/W4; 32-bit checks for remediation and Win32 detection | All pass; Windows 43/43 |
| 6 | 04:18 | Fixes from the first code review (finding 4) | Windows 44 pass, **2 fail**: one test under Windows PowerShell 5.1 (finding 3); hook guards 249/249 |
| 7 | 04:31 | Fix for finding 3 | All pass; Windows 46/46 |
| 8 | 04:59 | Fixes from the second code review to the MDM script (finding 5) | Windows 46/46 |
| 9 | 05:15 | **Final code:** second-review fixes to the hook guards, guard latency check | **All pass:** Windows 49/49; L1 18/18; L2 16/16; L3 2/2 |

| # | Finding | How it was found | Fix |
|---|---------|------------------|-----|
| 1 | `agent-hooks/tests/run-tests.ps1` did not parse: `"$g: ..."` inside a double-quoted string is read by PowerShell as a drive-qualified variable | Run 1 (the script was written without a PowerShell host) | `"${g}: ..."`; all `.ps1` files were searched for the same pattern |
| 2 | `L2.hooks-verified` compared `/opt/kiro/hooks` with the whole `SHA256SUMS`, which now also lists the Windows guards and hook file that Linux does not deploy | Run 3 | The check verifies the top-level `*.sh` entries, which is what Linux deploys. The deployment itself was correct |
| 3 | A test compared the refusal message as one string; Windows PowerShell 5.1 wraps captured STDERR text at the console width | Run 6 | The test compares without white space. The script's behaviour (exit 1) was correct |
| 4 | First code review of the change: 47 confirmed defects that the tests did not show. The most serious: a file a standard user created under `C:\ProgramData\Kiro` before the first deployment was kept in place, so a handle opened earlier stayed usable after the ACL was set, and the staged script is later run as SYSTEM; the Win32 detection could not see a newer policy package; `git` called by a quoted path with a space, and commands inside `( )`, `{ }` or `$( )`, were not inspected by the PowerShell guards; several admin policy patterns matched routine commands | Review of the diff by independent reviewers, each finding checked by a second reviewer who tried to refute it | Fixed, or documented as a limitation where a script cannot fix it. Files are written as new files and renamed into place; folders owned or controlled by a non-administrator are moved aside; `$ExpectedPolicySha256` in the wrappers; guards and policy patterns corrected; tests added for each |
| 5 | Second review, of the fixes: a folder re-created by a user in the instant after it was moved aside was adopted; deleting the old file before the rename could leave a device without the policy; escaped quotes desynchronised the guards' quote scanner; three guard regular expressions were quadratic, with no size or time bound | Review of the fixes | Folders are created under a random name, locked and renamed into place; files are prepared in an administrators-only work folder and the old file is put back if the rename fails; the guards evaluate the escaped-quote readings and stop themselves with exit 2 on oversized input or after 2.5 seconds |
| 6 | The lockdown scripts treated `auth_portal_url` (Kiro CLI 3.5.0+) as an unknown settings key, so `--strict` / `-Strict` refused a valid policy | Check of the issue's follow-up items against Kiro's sign-in page | Known key, validated; tests on all three operating systems |

**Changes after the final run.** Three edits were made after run 9 and were not re-run on the runners, which had been torn down: two rows of `agent-hooks/tests/fixtures/windows-cases.tsv` now use a placeholder user name in a `C:\Users\...` path (the name was replaced for publication; the rows still expect the same result), header comments in `mdm/lockdown-linux.sh` and `mdm/lockdown-macos.sh` were updated, and documentation was corrected. The local Linux and macOS dry-run tests were repeated afterwards; the changed fixture rows are run by the `validate-windows` CI job on the pull request.

**Limits of this evidence.** Findings 4 and 5 were found by reading the code, not by an attack on a device: no test holds a handle on a pre-created file or races the folder creation. The tests added for them show the new behaviour (an untrusted folder is moved aside, a file with a foreign owner is replaced, no temporary folder is left behind), not the absence of every such path. The per-user hook files remain a documented residual risk (SYSTEM writes into user-controlled folders).

### W1 — Windows MDM (Windows runner, SYSTEM)

```
CHECK W1.ps51-default PASS RESULT: PASS=102 FAIL=0 SKIP=0
CHECK W1.ps51-admin PASS RESULT: PASS=136 FAIL=0 SKIP=0
CHECK W1.pwsh7-installed PASS 7.6.10
CHECK W1.pwsh7-default PASS RESULT: PASS=102 FAIL=0 SKIP=0
CHECK W1.pwsh7-admin PASS RESULT: PASS=136 FAIL=0 SKIP=0
CHECK W1.lockdown PASS
CHECK W1.policy-present PASS
CHECK W1.no-bom PASS
CHECK W1.json PASS
CHECK W1.content PASS
CHECK W1.users-deny-ace PASS
CHECK W1.check-clean PASS
CHECK W1.check-detects-drift PASS rc=3
CHECK W1.check-after-restore PASS
```

`C:\ProgramData\Kiro\managed-settings.json` is written as UTF-8 without a BOM, is valid JSON, matches the source policy (34 rules), and carries a DENY ACE for `BUILTIN\Users`. `-Check` detects drift (exit 3), and a re-run restores the file. The embedded suite (136 checks in admin mode) also covers the Intune wrapper exit-code mapping against stubs that exit 0, 1, 2, 3 and 5, the expected-policy hash, `-DisableUpdates`, `-InstallUser` with broken profiles and a junction, a directory at a file path, a folder owned by `BUILTIN\Users` (moved aside) and a file with a foreign owner (replaced).

### W3 — PowerShell hook guards (Windows runner, SYSTEM)

```
CHECK W3.hooks-ps51 PASS RESULT: PASS=384 FAIL=0 KNOWN_GAP=1
CHECK W3.hooks-pwsh7 PASS RESULT: PASS=384 FAIL=0 KNOWN_GAP=1
CHECK W3.guard-latency:pii-guard.ps1 PASS worst of 3 runs: 1042 ms (hook timeout 5000 ms)
CHECK W3.guard-latency:git-guard.ps1 PASS worst of 3 runs: 1023 ms (hook timeout 5000 ms)
CHECK W3.guard-latency:destructive-fs-guard.ps1 PASS worst of 3 runs: 1030 ms (hook timeout 5000 ms)
```

384 cases per PowerShell version: every row of the shared fixtures (`git-fs-cases.tsv`, `pii-cases.tsv`), the Windows fixtures (`windows-cases.tsv`), cases built in the runner (line continuations, typographic characters, oversized input) and the fail-closed cases (empty input, invalid JSON, a JSON array, a non-object `tool_input`). The known gap is a deletion target held in a variable. These are unit tests with crafted events: no Kiro client called the guards. One guard call, including the start of `powershell.exe`, took about 1 second on this instance; the hook timeout in the shipped hook file is 5 seconds.

### W4 — Intune flow on the real paths (Windows runner, SYSTEM)

```
CHECK W4.win32-install-32bit-host PASS
CHECK W4.updatemode-64bit-view PASS REG_SZ none
CHECK W4.wow64-policies-shared PASS a 32-bit write to HKLM\SOFTWARE\Policies is visible in the 64-bit view
CHECK W4.staged-acl:mdm\lockdown-windows.ps1 PASS
CHECK W4.staged-acl:managed-settings\managed-settings.banking.json PASS
CHECK W4.staged-acl:agent-hooks\SHA256SUMS PASS
CHECK W4.staged-acl:agent-hooks\windows\pii-guard.ps1 PASS
CHECK W4.hook:pii-guard.ps1 PASS
CHECK W4.hook:git-guard.ps1 PASS
CHECK W4.hook:destructive-fs-guard.ps1 PASS
CHECK W4.default-profile-hook-file PASS
CHECK W4.detect-compliant PASS COMPLIANT: the deployed Kiro controls match the staged sources
CHECK W4.detect-from-32bit-host PASS Sysnative path
CHECK W4.win32-detected PASS
CHECK W4.win32-detected-from-32bit-host PASS
CHECK W4.detect-drift PASS NON-COMPLIANT: drift in 4 item(s); first: C:\ProgramData\Kiro\managed-settings.json content differs (sha256 7993a9e08b6ea58bc36270fcf0ac85d0ca68a8a0c0d722bc832fed764d8c109d, expected f930b7c2e9d191f9475cb8f1fe5edf967ab14be1b5e6dbd1565d149d2300b03d)
CHECK W4.detect-drift-names:policy PASS
CHECK W4.detect-drift-names:user-hook-file PASS
CHECK W4.detect-drift-names:updatemode PASS
CHECK W4.win32-not-detected PASS
CHECK W4.detect-drift-from-32bit-host PASS
CHECK W4.win32-not-detected-from-32bit-host PASS
CHECK W4.remediate PASS REMEDIATED: lockdown-windows.ps1 restored the Kiro controls (3 change(s))
CHECK W4.detect-after-remediate PASS
CHECK W4.updatemode-restored PASS
CHECK W4.remediate-from-32bit-host PASS REMEDIATED: lockdown-windows.ps1 restored the Kiro controls (1 change(s))
CHECK W4.detect-after-32bit-remediate PASS
CHECK W4.uninstall-removes-staged PASS
CHECK W4.uninstall-keeps-policy PASS
CHECK W4.detect-after-uninstall PASS
PHASE W1,W3,W4 RESULT pass=49 fail=0 skip=0
```

- The install command works when started from 32-bit PowerShell, and `UpdateMode` is in the 64-bit registry view.
- A value written to `HKLM\SOFTWARE\Policies` by a 32-bit process is visible in the 64-bit view (Microsoft lists the key as shared under WOW64).
- The staged sources and the deployed guards carry the Users DENY ACE; the Default profile received the hook file.
- Remediations detection: exit 0 with `COMPLIANT` when compliant; exit 1 with a one-line `NON-COMPLIANT` summary after the tamper, from 64-bit and 32-bit PowerShell; the full log names each of the three tampered items.
- Win32 detection: exit 0 with output on STDOUT and nothing on STDERR when compliant; no output and a non-zero exit code after the tamper, from both hosts.
- The remediation restores all tampered controls from 64-bit PowerShell (3 changes) and the policy file from 32-bit PowerShell (1 change); the uninstall command removes only the staged sources and keeps the policy.

### L1 — CI parity on GNU/Linux (Linux runner)

```
CHECK L1.npm-ci PASS
CHECK L1.npm-audit PASS
CHECK L1.tsc PASS
CHECK L1.lint PASS
CHECK L1.jest PASS
CHECK L1.synth[env=dev] PASS
CHECK L1.synth[env=prod] PASS
CHECK L1.synth[env=dev egress=nat-dns-firewall] PASS
CHECK L1.synth[env=dev createConfigRecorder=true] PASS
CHECK L1.hooks PASS
CHECK L1.pii-patterns PASS
CHECK L1.validate-repo PASS
CHECK L1.sha256sums PASS
CHECK L1.policy PASS
CHECK L1.mdm-dry-run PASS
CHECK L1.mdm-macos-dry-run PASS
CHECK L1.bash-n PASS
CHECK L1.json PASS
PHASE L1 RESULT pass=18 fail=0 skip=0
```

### L2 — root MDM lockdown (Linux runner, root)

```
CHECK L2.root-suite PASS
CHECK L2.user PASS reusing kirotest from an earlier run of this suite
CHECK L2.lockdown PASS
CHECK L2.policy-present PASS
CHECK L2.policy-owner-mode PASS root:644
CHECK L2.policy-immutable PASS
CHECK L2.policy-content PASS
CHECK L2.user-cannot-modify PASS
CHECK L2.user-cannot-delete PASS
CHECK L2.hooks-verified PASS
CHECK L2.check-clean PASS rc=0
CHECK L2.check-detects-drift PASS rc=3
CHECK L2.reapply PASS
CHECK L2.check-after-restore PASS rc=0
CHECK L2.audit-append PASS
CHECK L2.audit-no-truncate PASS
PHASE L2 RESULT pass=16 fail=0 skip=0
```

### L3 — chaos harness (Linux runner, root)

```
CHECK L3.run-chaos.sh PASS total=37 BLOCKED=28 DETECTED=1 GAP=8 BYPASSED=0 sanity-failures=0
CHECK L3.run-chaos-hardened.sh PASS total=32 BLOCKED=27 DETECTED=1 GAP=4 BYPASSED=0 sanity-failures=0
PHASE L3 RESULT pass=2 fail=0 skip=0
```

### Not covered in this run

- **Kiro itself on Windows.** No Kiro IDE or CLI was installed on the Windows runner. Not exercised: Kiro reading `C:\ProgramData\Kiro\managed-settings.json`, the new Windows rules as matched by a Kiro client (case handling, aliases, path forms), global hooks loaded by the IDE or the CLI, the shell that runs a hook command, the system-wide installer, `UpdateMode` as seen in Help > About, and `AuthPortalUrl`.
- **Windows 10/11.** The runner is Windows Server 2022. Kiro lists Windows 10/11 for the IDE and Windows 11 for the CLI.
- **A logged-on standard user and a real Intune tenant.** The Intune execution contexts were simulated as SYSTEM from 64-bit and 32-bit PowerShell. The Intune Management Extension's own process, its re-evaluation schedule and supersedence were not exercised.
- **macOS.** `lockdown-macos.sh` changed in this change (`auth_portal_url`). Only its dry-run tests ran (`L1.mdm-macos-dry-run` on the Linux runner, and on a developer Mac); there was no run as root on macOS.
- **K2 (Kiro end-to-end).** Still not run: it needs a Kiro API key. The new K2 cases (`PermissionRequest` against an admin `ask` rule, `updatedInput` against an admin `deny` rule) are code that has not been executed.
- **The new CI job `validate-windows`.** It runs for the first time on the pull request for this change.
- **C1, C2, K1.** Not repeated; the 2026-10-10 results below are for the code of that date.

### Teardown (2026-11-19)

`run-integration.sh down leftovers`, run after the final test run (05:36 to 05:39 UTC):

```
retained resources recorded: 0
harness deleted (instances terminated)
STALE ec2:instance (deleted; tagging API not yet updated)        (x2)
LEFTOVERS total=0
```

- Only the harness stack existed in this run: no CDK stack was deployed, so there were no retained resources and no KMS keys to schedule for deletion.
- The two `STALE` entries are the terminated runners, which the Resource Groups Tagging API still listed.
- Checked again with separate AWS CLI calls after the scan: the harness stack no longer exists; 0 instances tagged `Project=kiro-fsi-test` in a state other than terminated; 0 buckets, 0 stacks and 0 SSM parameters with the test prefixes.
- The harness ran for about three hours (02:36 to 05:39 UTC). The account resources that existed before the test were not modified.

## Run of 2026-10-10 (v1.9.1): full test

The sections below are the record of the full run of 2026-10-10 (base `main` at 3c181c8 plus the fixes listed there). They were not changed by the 2026-11-19 run. Where a suite ran in both, the newer result is above.

### Result

All required checks pass on the final code of this change (base `main` at 3c181c8 plus the fixes listed below). Every suite was re-run on the final bundle after the last fix.

| ID | Suite | Where | Result |
|----|-------|-------|--------|
| L1 | CI parity on GNU/Linux | Linux runner | **17/17 PASS**: Jest 91/91, hooks 98/98, PII patterns 346/346, 4 synth variants, `npm audit --audit-level=high` |
| L2 | Root MDM: real `lockdown-linux.sh` | Linux runner (root) | **16/16 PASS** |
| L3 | Full chaos harness, rounds 1 and 2 | Linux runner (root) | **2/2 PASS**: 0 BYPASSED, 0 sanity failures |
| W1 | Windows MDM: real `lockdown-windows.ps1` | Windows runner (SYSTEM) | **14/14 PASS**: suite 24/24 (default) and 36/36 (admin) under Windows PowerShell 5.1 and PowerShell 7 |
| C1 | Real deployment of all 5 CDK stacks (`env=dev`) | sandbox account | **36/36 PASS** |
| C2 | `egress.mode = nat-dns-firewall`: DNS Firewall allowlist | egress probe | **13/13 PASS** |
| K1 | Kiro CLI on a hardened host behind the allowlist | egress probe | **3/3 PASS** (Kiro CLI 2.29.0) |
| K2 | Kiro end-to-end prompts | egress probe | **SKIP**: no Kiro API key was provided (see [Not covered](#not-covered)) |
| T1 | Teardown and leftover scan | sandbox account | **PASS**: `LEFTOVERS total=0`; 5 KMS keys pending deletion (expected) |

### Environment

| Item | Value |
|------|-------|
| Account | Sandbox account, `ap-southeast-1`. GuardDuty, Security Hub, an AWS Config recorder and the CDK bootstrap already existed, so the deployment used `-c enableGuardDuty=false -c enableSecurityHub=false` and the existing recorder. None of the existing account resources were modified. |
| Harness | [`harness.yaml`](../security-tests/aws-integration/harness.yaml): dedicated VPC `10.250.0.0/24`, security group with **no inbound rules**, access through AWS Systems Manager only (no SSH keys), IMDSv2 required, encrypted gp3, terminate-on-shutdown plus an 8-hour on-instance failsafe. The runner role has `AmazonSSMManagedInstanceCore` and access to the results bucket only, with no deploy permissions. |
| Linux runner | Amazon Linux 2023 x86_64, t3.medium, Node.js v22.23.3 (verified against `SHASUMS256.txt`) |
| Windows runner | Windows Server 2022, t3.medium, Windows PowerShell 5.1 and PowerShell 7.6.6 |
| Egress probe | Amazon Linux 2023, t3.small, in the CDK NetworkStack's WorkSpaces subnet (`nat-dns-firewall`), no public IP |
| CDK toolchain | aws-cdk-lib 2.273.0, CDK CLI 2.1145.0, cdk-nag 2.38.2, TypeScript 5.9.3, Jest 30.5.2, ESLint 9.39.5, lockfile generated with npm 10 |
| Kiro | Kiro CLI 2.29.0, installed with `curl -fsSL https://cli.kiro.dev/install \| bash` through the DNS Firewall |

The CDK app was synthesized with `cdk synth`, with the real Availability Zones injected into the context for the run only (never committed). The synthesized templates were then deployed with the AWS CLI through the CDK bootstrap bucket and CloudFormation execution role. The assembly has no Lambda or Docker assets, so this is equivalent to `cdk deploy`. The CDK CLI was not used for the deploy because its connections were dropped by the operator's egress proxy (see the harness README).

### Findings and fixes

The first runs failed in several places. Each failure was traced to its root cause and fixed, and the suite was re-run until it passed.

| # | Finding | Fix (in this change) |
|---|---------|----------------------|
| 1 | `npm audit --audit-level=high` on the lockfile at 3c181c8: **1 critical and 36 high** advisories. CI did not catch them, because the audit step had `continue-on-error: true`. | Upgraded to aws-cdk-lib 2.273, cdk-nag 2.38, CDK CLI 2.1145, Jest 30, TypeScript 5.9 and ESLint 9 (flat config `eslint.config.mjs` replaces `.eslintrc.json`), then ran `npm audit fix`. Result: 0 critical and 0 high (20 moderate, reviewed). The CI audit step is now a **blocking** gate. |
| 2 | A lockfile written by npm 11 failed `npm ci` under npm 10, the version bundled with Node.js 22 that CI uses: "Missing: @emnapi/core from lock file". | Lockfile regenerated with npm 10; works with `npm ci` under npm 10.9 and 11.6. Rule added to `AGENTS.md`. |
| 3 | Synth printed CDK deprecation warnings: `Stack.addDependency`, `CfnResource.addDependency`, and the planned change of the default cross-stack reference strength. | `addStackDependency` / `addResourceDependency`. `cdk.json` pins `@aws-cdk/core:defaultCrossStackReferences` to `strong`, which keeps today's CloudFormation exports, so deployed stacks and export names are unchanged. |
| 4 | Testing `nat-dns-firewall` needs extra DNS Firewall entries for the probe itself (SSM, S3, OS package mirrors), and there was no way to add them for one run. | New `-c egressAllowedDomains=a,b` context option. It is validated (exact hostnames or `*.`-wildcards; a bare `*` is rejected), merged into `egress.allowedDomains`, and covered by 4 unit tests. |
| 5 | The PDPA RDS Config rules never started evaluating in an account without RDS, so they were indistinguishable from a broken rule. | Both rules are now explicitly scoped to `AWS::RDS::DBInstance` (unit test added). The verifier accepts a rule that hasn't started only if it reports no error and the account holds 0 resources of the scoped types. |
| 6 | The chaos harness's hash-chained evidence records showed the **previous step's command** for steps run through `$(dev …)`. The command substitution ran `dev()` in a subshell, so its `LAST_CMD` was lost. The verdicts were unaffected (they use the captured output). | New `devo()` helper captures the output in the current shell. The 6 call sites in `run-chaos.sh` and `run-chaos-hardened.sh` use it, and the records now show the command that actually ran. |
| 7 | Two alarms (`unauthorized-api`, `iam-policy-change`) were **already in ALARM** from real activity when the delivery check started, so `set-alarm-state ALARM` caused no transition and no action. | The verifier now forces each alarm OK → ALARM before checking. |

Test-tooling fixes (no effect on the product):
- macOS `tar` added AppleDouble `._*` entries, which the hook-manifest and Windows checks correctly rejected as unsafe file names. Fixed with `COPYFILE_DISABLE=1` plus a guard.
- Credentials and IMDS are hidden during the L1 synth for CI parity; otherwise the CDK CLI replaces the dummy account with the instance role's account.
- Re-runs of an SSM label no longer mix earlier outputs into the summary log.
- Teardown: retained-bucket cleanup and the leftover scan (see [Teardown](#teardown)).

**Detective controls fired on real activity.** During the test, the *unauthorized API calls* alarm (16 access-denied events in 5 minutes) and the *IAM policy changes* alarm went to ALARM on genuine events. The access-denied events came from workloads that already existed in the sandbox account. The policy change was the deployment itself: the CloudFormation execution role attached a managed policy to a role created by the stacks. In both cases the KMS-encrypted SNS topic received the notifications ("Successfully executed action"). None of the access-denied events came from the deployed stacks.

### L1 — CI parity on GNU/Linux (Linux runner)

```
CHECK L1.npm-ci PASS
CHECK L1.npm-audit PASS
CHECK L1.tsc PASS
CHECK L1.lint PASS
CHECK L1.jest PASS
CHECK L1.synth[env=dev] PASS
CHECK L1.synth[env=prod] PASS
CHECK L1.synth[env=dev egress=nat-dns-firewall] PASS
CHECK L1.synth[env=dev createConfigRecorder=true] PASS
CHECK L1.hooks PASS
CHECK L1.pii-patterns PASS
CHECK L1.validate-repo PASS
CHECK L1.sha256sums PASS
CHECK L1.mdm-dry-run PASS
CHECK L1.mdm-macos-dry-run PASS
CHECK L1.bash-n PASS
CHECK L1.json PASS
PHASE L1 RESULT pass=17 fail=0 skip=0
```

Details from the same run: `Tests: 91 passed, 91 total`; hooks `PASS=98 FAIL=0 KNOWN_GAP=0`; PII patterns `PASS=346 FAIL=0 SKIP=0`; `validate-repo.sh` `RESULT: PASSED`; MDM dry runs `PASS=45 FAIL=0` (Linux) and `PASS=28 FAIL=0 SKIP=1` (macOS script on Linux); `npm audit`: 20 moderate, 0 high, 0 critical.

### L2 — root MDM lockdown (Linux runner, root)

A real `mdm/lockdown-linux.sh --hooks` for a test user that the suite created (the final run reused it):

```
CHECK L2.root-suite PASS
CHECK L2.user PASS
CHECK L2.lockdown PASS
CHECK L2.policy-present PASS
CHECK L2.policy-owner-mode PASS root:644
CHECK L2.policy-immutable PASS
CHECK L2.policy-content PASS
CHECK L2.user-cannot-modify PASS
CHECK L2.user-cannot-delete PASS
CHECK L2.hooks-verified PASS
CHECK L2.check-clean PASS rc=0
CHECK L2.check-detects-drift PASS rc=3
CHECK L2.reapply PASS
CHECK L2.check-after-restore PASS rc=0
CHECK L2.audit-append PASS
CHECK L2.audit-no-truncate PASS
PHASE L2 RESULT pass=16 fail=0 skip=0
```

`/etc/kiro/managed-settings.json` is identical to `managed-settings/managed-settings.banking.json`, owned by root, mode 644, and immutable (`chattr +i`). The non-root user can neither modify nor delete it. The deployed hooks match `agent-hooks/SHA256SUMS`. `--check` exits 0 on a clean host and 3 after a one-byte change, and a re-run restores the file. The user can append to the hook audit log but cannot truncate it (`chattr +a`).

### L3 — chaos harness (Linux runner, root, `CHAOS_ALLOW_SYSTEM_CHANGES=1`)

```
CHECK L3.run-chaos.sh PASS total=37 BLOCKED=28 DETECTED=1 GAP=8 BYPASSED=0 sanity-failures=0
CHECK L3.run-chaos-hardened.sh PASS total=32 BLOCKED=27 DETECTED=1 GAP=4 BYPASSED=0 sanity-failures=0
PHASE L3 RESULT pass=2 fail=0 skip=0
```

Every GAP is a documented endpoint limitation, and its `expected` value in the harness is `GAP`. Each is covered by another tier (server-side branch protection, egress control, IAM), as described in [`chaos-pentest-evidence.md`](chaos-pentest-evidence.md):
- **Round 1:** deleting or renaming user-owned files (A8, A9); git by absolute path or a private copy of git bypassing a PATH guard (C1, C2); redirecting the audit log through an environment variable (C3); base64-encoded commands and PII (D4, D6); copying readable data to a local sink (E3).
- **Round 2:** the remaining four, D4, D6, C3 and C1. An approved system binary still runs, so force-push must be stopped server-side.

The harness created its own test account, refused to reuse an existing one, and deleted only the account it created.

### W1 — Windows MDM (Windows runner, SYSTEM)

```
CHECK W1.ps51-default PASS RESULT: PASS=24 FAIL=0 SKIP=0
CHECK W1.ps51-admin PASS RESULT: PASS=36 FAIL=0 SKIP=0
CHECK W1.pwsh7-installed PASS 7.6.6
CHECK W1.pwsh7-default PASS RESULT: PASS=24 FAIL=0 SKIP=0
CHECK W1.pwsh7-admin PASS RESULT: PASS=36 FAIL=0 SKIP=0
CHECK W1.lockdown PASS
CHECK W1.policy-present PASS
CHECK W1.no-bom PASS
CHECK W1.json PASS
CHECK W1.content PASS
CHECK W1.users-deny-ace PASS
CHECK W1.check-clean PASS
CHECK W1.check-detects-drift PASS rc=3
CHECK W1.check-after-restore PASS
PHASE W1 RESULT pass=14 fail=0 skip=0
```

`C:\ProgramData\Kiro\managed-settings.json` is written as UTF-8 without a BOM, is valid JSON, matches the source policy, and carries a DENY ACE for `BUILTIN\Users`. `-Check` detects drift (exit 3), and a re-run restores the file.

### C1 — real deployment (`env=dev`, default egress `none`)

```
CHECK C1.stack[KiroBanking-Encryption-dev] PASS CREATE_COMPLETE
CHECK C1.stack[KiroBanking-Network-dev] PASS CREATE_COMPLETE
CHECK C1.stack[KiroBanking-Monitoring-dev] PASS CREATE_COMPLETE
CHECK C1.stack[KiroBanking-Compliance-dev] PASS UPDATE_COMPLETE
CHECK C1.stack[KiroBanking-Backup-dev] PASS CREATE_COMPLETE
CHECK C1.kms-rotation[KiroBanking-Encryption-dev] PASS        (x3)
CHECK C1.kms-rotation[KiroBanking-Network-dev] PASS
CHECK C1.kms-rotation[KiroBanking-Backup-dev] PASS
CHECK C1.vpc-endpoints-available PASS 5 available
CHECK C1.nacl-associated PASS Endpoints subnets
CHECK C1.workspaces-sg-no-allow-all-egress PASS nat-gateways=0
CHECK C1.flow-log-active PASS ACTIVE/SUCCESS
CHECK C1.flow-log-cmk PASS
CHECK C1.cloudtrail-logging PASS
CHECK C1.cloudtrail-no-LatestDeliveryError PASS
CHECK C1.cloudtrail-no-LatestCloudWatchLogsDeliveryError PASS
CHECK C1.cloudtrail-no-LatestDigestDeliveryError PASS
CHECK C1.cloudtrail-delivered-s3 PASS
CHECK C1.cloudtrail-delivered-cwl PASS
CHECK C1.audit-object-lock PASS GOVERNANCE 30
CHECK C1.audit-versioning PASS
CHECK C1.audit-public-access-block PASS
CHECK C1.audit-sse-kms PASS
CHECK C1.audit-noncurrent-expiration PASS
CHECK C1.alarm-action-delivered[kiro-banking-cloudtrail-change-dev] PASS prior-state=OK
CHECK C1.alarm-action-delivered[kiro-banking-iam-policy-change-dev] PASS prior-state=OK
CHECK C1.alarm-action-delivered[kiro-banking-kms-key-disable-or-deletion-dev] PASS prior-state=OK
CHECK C1.alarm-action-delivered[kiro-banking-no-mfa-signin-dev] PASS prior-state=OK
CHECK C1.alarm-action-delivered[kiro-banking-root-account-usage-dev] PASS prior-state=OK
CHECK C1.alarm-action-delivered[kiro-banking-sg-change-dev] PASS prior-state=OK
CHECK C1.alarm-action-delivered[kiro-banking-unauthorized-api-dev] PASS prior-state=ALARM
CHECK C1.config-rules-19 PASS
CHECK C1.config-rules-evaluate PASS not-applicable(0 in-scope resources): pdpa-rds-encryption-dev pdpa-rds-no-public-dev
CHECK C1.backup-schedule PASS cron(0 18 * * ? *)
PHASE C1 RESULT pass=36 fail=0 skip=0
```

This proves:
- **Alarm delivery:** all 7 alarms deliver to the SNS topic encrypted with the AuditKey, so the key policy and topic policy allow CloudWatch alarms to publish.
- **CloudTrail:** delivers to the Object Lock audit bucket and to CloudWatch Logs without errors.
- **Flow logs:** active and encrypted with their dedicated CMK.
- **Network:** the endpoint NACL is attached to the Endpoints subnets, and the WorkSpaces security group has no allow-all egress rule.
- **Config:** 17 of the 19 Config rules evaluate without errors. The 2 RDS rules have nothing in scope.

`KiroBanking-Compliance-dev` shows `UPDATE_COMPLETE` because the RDS rule scopes (finding 5) were deployed as an in-place update. The stack was not re-created.

### C2 — `nat-dns-firewall` egress (probe in the WorkSpaces subnet)

The deployed Network stack was updated in place to `-c egress=nat-dns-firewall`. CloudFormation added the `Public` subnets, the NAT gateway, the DNS Firewall rule group and association, and the WorkSpaces default routes; it replaced no existing subnet or endpoint. The test-only allowlist additions (`-c egressAllowedDomains=`) were the regional SSM hosts, the regional S3 host and the results bucket, and the AL2023 package mirrors. A production allowlist does not need them.

```
CHECK C2.resolves[app.kiro.dev] PASS
CHECK C2.resolves[prod.us-east-1.auth.desktop.kiro.dev] PASS
CHECK C2.resolves[runtime.us-east-1.kiro.dev] PASS
CHECK C2.resolves[cli.kiro.dev] PASS
CHECK C2.resolves[q.us-east-1.amazonaws.com] PASS
CHECK C2.resolves[oidc.ap-southeast-1.amazonaws.com] PASS
CHECK C2.blocked[example.com] PASS
CHECK C2.blocked[www.google.com] PASS
CHECK C2.blocked[github.com] PASS
CHECK C2.blocked[pastebin.com] PASS
CHECK C2.https[https://app.kiro.dev] PASS http=200
CHECK C2.https[https://prod.us-east-1.auth.desktop.kiro.dev] PASS http=404
CHECK C2.https-blocked PASS
PHASE probe RESULT pass=13 fail=0 skip=0
```

`github.com` is blocked because the optional extension and Powers/MCP hosts are excluded by default (`KIRO_OPTIONAL_HOSTS`). An HTTP 404 from the auth host still proves the TLS connection succeeded.

### K1 — Kiro CLI behind the allowlist (probe)

```
CHECK K1.install PASS kiro-cli 2.29.0
CHECK K1.lockdown PASS
CHECK K1.agent-installed PASS valid JSON, identical to agent-hooks/banking-secure.agent.json
CHECK K2.e2e SKIP no /kiro-fsi-test/kiro-api-key parameter (end-to-end prompts need a Kiro API key)
PHASE kiro RESULT pass=3 fail=0 skip=1
```

The official installer and its download host (`prod.download.cli.kiro.dev`) worked using only the hosts that `kiroEgressDomains()` allowlists. This confirms that the CLI host list in `cdk/config/kiro-endpoints.ts` is sufficient for installation.

### Not covered

- **K2 (Kiro end-to-end) was skipped.** It needs a Kiro API key (Pro tiers; headless mode uses `KIRO_API_KEY`) stored as the SSM SecureString `/kiro-fsi-test/kiro-api-key`. Without it, the following were not exercised: admin deny rules overriding `--trust-all-tools`, the pii-guard hook blocking an agent-driven write of an NRIC, and hook audit records written by a live session. The hooks themselves are covered by L1 (98 tests), L3 and K1. To run K2, store the key and re-run the `egress` stage.
- **macOS** was not tested (out of scope for this run; EC2 Mac has a 24-hour minimum allocation).
- **Account singletons:** GuardDuty, Security Hub and the Config recorder already existed, so the stacks' creation paths for them (`enableGuardDuty`, `enableSecurityHub`, `createConfigRecorder=true`) were synthesized and checked by cdk-nag (L1) but not deployed.
- **DNS Firewall scope:** it filters DNS only. A connection made directly to an IP address is not blocked (documented in `cdk/README.md`).
- The test asserts that the Config rules **evaluate**. It does not assert their compliance results, which reflect account-level settings of the sandbox account.

### Teardown

`run-integration.sh down leftovers`, run after this change's PR was opened (2026-10-10):

```
probe deleted
retained resources recorded: 10
deleted KiroBanking-Backup-dev
deleted KiroBanking-Compliance-dev
deleted KiroBanking-Monitoring-dev
deleted KiroBanking-Network-dev
deleted KiroBanking-Encryption-dev
KMS key scheduled for deletion (7 days)                      (x5)
deleted log group (retained)                                 (x2)
deleted bucket (retained)                                    (audit-log bucket, Object Lock GOVERNANCE)
deleted backup vault (retained)
harness deleted (instances terminated)
```

The first pass left one retained bucket behind. The cleanup passed `--bypass-governance-retention` to every bucket, and S3 rejects that flag on a bucket without Object Lock (the access-log bucket). `empty_bucket` now passes the flag only when Object Lock is enabled, and fails on per-object errors instead of looping. The bucket was then deleted with the fixed code.

Final leftover scan:

```
STALE ec2:instance (deleted; tagging API not yet updated)        (x3)
STALE ec2:natgateway (deleted; tagging API not yet updated)
STALE ec2:vpc-endpoint (deleted; tagging API not yet updated)    (x5)
STALE ec2:vpc-flow-log (deleted; tagging API not yet updated)
EXPECTED kms:key PendingDeletion                                 (x5)
LEFTOVERS total=0
```

- The Resource Groups Tagging API keeps listing deleted resources for a while. `leftovers` now checks every tagged ARN against its own service and reports it as `STALE` only when that service says it is gone (terminated, deleted or not found).
- A name-prefix scan (`kiro-banking`, `KiroBanking`, `kiro-fsi-test`) found nothing. It covers S3 buckets, log groups, KMS aliases, backup vaults and plans, SNS topics, alarms, Config rules, trails, Access Analyzer, EventBridge rules, DNS Firewall rule groups and domain lists, IAM roles and SSM parameters.
- No test instances are pending, running, stopping or stopped.
- The 5 customer-managed KMS keys are in `PendingDeletion` (7-day window, ending 2026-10-17). AWS deletes them automatically.
- The account resources that existed before the test are unchanged: the GuardDuty detector, Security Hub, the Config recorder (still recording), the CDK bootstrap stack, and the account's multi-region CloudTrail trail (still logging). The CDK bootstrap was not created by the test, so it was not removed.

## Reproduce

```bash
export IT_REGION=ap-southeast-1
bash security-tests/aws-integration/run-integration.sh preflight up bundle
bash security-tests/aws-integration/run-integration.sh linux windows
bash security-tests/aws-integration/run-integration.sh deploy verify egress
bash security-tests/aws-integration/run-integration.sh down leftovers
```

See [`security-tests/aws-integration/README.md`](../security-tests/aws-integration/README.md) for prerequisites, the safety controls and the test matrix.
