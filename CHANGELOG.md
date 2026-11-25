# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

Windows client validation for issue #43. Refs #43 (issue stays open). The W2 kit was run on 2026-11-19 and 2026-11-20, and the Kiro CLI suite on 2026-11-20, on a Windows 11 Enterprise 26H2 (Evaluation, build 26300.9457) Hyper-V VM on an EC2 host with nested virtualization, with Kiro IDE 1.4.236 (system-wide build) and Kiro CLI 3.5.0; Kiro CLI was also run on Windows Server 2022 (2026-11-19). Intune itself was emulated (no tenant: SYSTEM, 64-bit and 32-bit hosts), the edition is Evaluation, and each case had one model run. This change adds the kit, the test tooling, the results and four product findings (F1 to F4), which are published in full and reported to Kiro on GitHub (kirodotdev/Kiro). Still open in issue #43: a real Intune tenant, the per-user build installed by a user, a profile created later in Kiro IDE, ARM64, and the F1 case check in Kiro IDE.

### Results (Windows 11 26H2 VM, 2026-11-19 and 2026-11-20; dated per item)
- **Kiro IDE 1.4.236, system-wide build, standard user at the console:**
  - Install (W2.1, 2026-11-19, elevated administrator, the kit's default switches with `/MERGETASKS=!runcode`): exit 0, Kiro not started, Uninstall entry `{ECDD7648-5B69-4BDC-9D21-C3452CE76CD2}_is1` in the 64-bit HKLM view, `C:\Program Files\Kiro`, machine PATH, all-users shortcut: the Windows Server 2022 measurements hold. The Intune wrappers (W2.10) as 64-bit and 32-bit SYSTEM, with tamper and remediation: 14 pass, 0 fail, 1 skip (2026-11-19, repeated on 2026-11-20). The per-user build run as SYSTEM (Windows Server 2022, 2026-11-19) installs into SYSTEM's profile, registers under `HKU\S-1-5-18` only and is not detected.
  - The admin policy is enforced: `git push --force`, `Invoke-WebRequest`, `irm`, lowercase `invoke-webrequest` and a nested `powershell -Command` were refused with the source "administration" (`git push --force` and `Invoke-WebRequest` on 2026-11-19, the others on 2026-11-20); an admin `ask` prompted, and the rejection held (2026-11-20).
  - An Entra ID only policy (`exclude ["external_idp"]`) left one sign-in option, "Your organization". The repository policy (`idc` only) signed in with IAM Identity Center (both 2026-11-19).
  - `UpdateMode=none` removes "Check for Updates"; Help > About shows no text about it (2026-11-20).
  - An invalid policy file (valid JSON with a UTF-8 BOM): tools fail closed, sign-in fails open (all four methods offered; 2026-11-20).
  - Global hooks: Kiro IDE lists and runs the PreToolUse hooks in `%USERPROFILE%\.kiro\hooks` (not documented by Kiro for the IDE), starts them through `cmd.exe`, exit code 2 blocks, and `pii-guard.ps1` blocked a write of a test NRIC. Global steering from `%USERPROFILE%\.kiro\steering` loaded (2026-11-20). The standard user could rename the hook file in the profile (2026-11-19).
- **Kiro CLI 3.5.0, headless, a standard user created after the deployment (phase WK):** Windows Server 2022 (2026-11-19): 31 pass, 0 fail, with F1 and F2 observed in both runs. Windows 11 (2026-11-20), run 1 (clean image): the MSI exits 0, but `kiro-cli.exe` exits 0xC0000135 as SYSTEM and as the user. Runs 2 and 3 with the Visual C++ 2015-2022 Redistributable x64 14.44.35211.0: run 3 31 pass, 0 fail, 7 info; an invalid policy (malformed JSON, or a UTF-8 BOM) refuses every tool call.
- **F1: shell rules match case-sensitively; PowerShell does not.** `INVOKE-WEBREQUEST` in capitals ran past a deny rule that lists `Invoke-WebRequest*` and `invoke-webrequest*` (Windows Server 2022, both runs; Windows 11, runs 2 and 3), and on Windows 11 also with the hook guards on. With the guards on, `REMOVE-ITEM .git -RECURSE -FORCE` was blocked by `destructive-fs-guard.ps1`, which ignores case. On Windows, shell deny rules are a guardrail, not a boundary; egress needs a network control.
- **F2: `--trust-all-tools` approves commands under an admin `ask` rule.** `Remove-Item <file> -Force` (rule 21, `ask`) ran in a headless run with the flag and nobody was asked (both platforms); without the flag it was refused. Rule 21 changed to `deny`: the canonical spelling was refused (Windows Server 2022 follow-up run, Windows 11 run 3), but `REMOVE-ITEM <file> -FORCE` in capitals ran (Windows 11 run 3): F1 defeats this mitigation. Kiro's two documentation pages disagree; the measured behaviour follows the permissions page.
- **F3: Kiro CLI needs the Visual C++ 2015-2022 Redistributable x64** (`MSVCP140.dll`, `MSVCP140_1.dll`, `VCRUNTIME140.dll`, `VCRUNTIME140_1.dll`), which a clean Windows 11 does not have and the MSI does not install. Existing issue kirodotdev/Kiro#9752 (opened for 2.9.0) still reproduces with 3.5.0.
- **F4: the Kiro CLI MSI run as SYSTEM without `INSTALLFOLDER`** installs into `C:\Windows\system32\config\systemprofile\AppData\Local\Kiro-Cli\`, while the HKLM 64-bit Uninstall entry `{539162FB-DCCC-4E50-8AA5-423F78632CA8}` makes a registry detection rule report it as installed. With `INSTALLFOLDER="C:\Program Files\Kiro-Cli"` it installs machine-wide, but PATH is set only for the installing account.
- A search of kirodotdev/Kiro (1,117 issues screened, 112 read) found F3 as an existing issue; F1, F2 and F4 are new.

### Added
- **`security-tests/windows-client/` (W2 kit, issue #43):** a defensive validation kit that a person runs on a Windows 11 **test device** with Kiro installed.
  - `Invoke-W2Checks.ps1` (Windows PowerShell 5.1 and PowerShell 7) records the installer signature and hash (W2.2), a silent system-wide install and its Uninstall entry, registry view, install folder, PATH and Start Menu entries (W2.1), a per-user build next to the system-wide one (W2.3), `UpdateMode` in both registry views (W2.4), the deployed policy file (W2.5) and the Intune wrappers as 64-bit SYSTEM, 32-bit SYSTEM and the logged-on user, with an optional tamper test (W2.10). With no action switch it only reads. Output: `CHECK <id> PASS|FAIL|SKIP|INFO`, `NOTE` and `ACTION` lines and a `PHASE W2 RESULT` line, with SIDs, user, computer and domain names masked (a `-NoSanitize` run writes to a separate file, `w2-results-UNSANITIZED.txt`). `-ExpectedSignerSubject` ignores double quotes, because the subject of the Kiro installer contains them and they do not survive every command line.
  - `hook-probe.ps1` and the switches `-InstallProbes`, `-ReadProbes` and `-RemoveProbes` record whether Kiro IDE and Kiro CLI V3 load global hooks, which process chain runs a hook command and whether exit code 2 blocks (W2.7, W2.8), and place a steering marker (W2.9). The probe logs no tool input.
  - `W2-manual-checklist.md` holds the steps that need a signed-in Kiro window (W2.1, W2.3 to W2.9), with a result block for each. The policy tests run with the hook guards switched off, so a refusal can be attributed to the admin policy, and every command the agent is asked to run is harmless if a control fails.
  - `README.md` describes the test environment, what each switch changes and how to undo it, the run order, the output format, and where confirmed values go in the documentation. The kit must not be used on a device that already carries an organisation's Kiro policy.
- **Integration test: opt-in stage `client` (phase WC),** never part of `all` (`security-tests/aws-integration/windows-client-suite.ps1`, `run-integration.sh client`). It downloads the current Kiro IDE system-wide installer (the URL must be on `prod.download.desktop.kiro.dev`) to the disposable Windows Server 2022 runner and runs the automatable part of the W2 kit as SYSTEM; the installer is run only when its Authenticode status is `Valid` and its signer subject starts with the CN, OU and O of the subject measured for release 1.4.236. It then repeats the kit's read-only part under PowerShell 7. The uninstall command runs only with `IT_WC_UNINSTALL=1`. Windows Server 2022 is outside Kiro's listed operating systems and no Kiro window is opened or signed in, so WC shows installer mechanics only and does not replace the Windows 11 run.

- **Installer mechanics measured (WC, 2026-11-19, Kiro IDE 1.4.236 x64 system-wide installer, Windows Server 2022):** Inno Setup; signer subject starting `CN="Amazon.com, Inc.", OU=AWS Kiro` (the full string is in the runbook); install folder `C:\Program Files\Kiro`; Uninstall entry in the 64-bit registry view; the silent switches work (exit code 0). Two findings that change the Intune guidance: **a silent install starts Kiro when it finishes** (as SYSTEM under Intune) unless `/MERGETASKS=!runcode` is given, and **install and uninstall both end with exit code 1 while Kiro is running** (measured with Kiro running in session 0; a Kiro that a logged-on user has open was not tested). `kiro-docs/intune-deployment.md` section 1 now gives the measured install and uninstall commands, a table of what the installer does, and two troubleshooting rows; `mdm-endpoint-enforcement.md` and Part 1 Section 4.2.3 point to it. Results and all runs: `kiro-docs/aws-integration-test-evidence.md`, section WC. Confirmed on Windows 11 26H2 for an install by an elevated administrator (2026-11-19, see Results); still to confirm on Windows 10 and ARM64.
- The WC stage accepts `IT_WC_UNINSTALL=1`, `IT_WC_STOP_KIRO=1` and `IT_WC_INSTALLER_ARGS`.
- Repeating the `windows` stage on a new runner gave a first deployment of the 1.10 code on clean real paths: W1, W3 and W4 passed 49/49.
- **Integration test: new opt-in stages,** never part of `all` (`security-tests/aws-integration/run-integration.sh`):
  - `kirowin`: phase WK on the Windows Server 2022 runner. `IT_WK_UNINSTALL=1` uninstalls Kiro CLI at the end.
  - `kiro`: K1/K2 on the Linux runner (open egress), without deploying the CDK stacks.
  - `win11host`: launches the Windows 11 lab host into the harness subnet (EC2 `m8i.2xlarge` by default, `IT_W11_TYPE`; nested virtualization, Windows Server 2025, Hyper-V; no inbound rules; failsafe shutdown after `IT_W11_FAILSAFE_MINUTES`, default 1440). Local account passwords are generated into SSM SecureStrings `/kiro-fsi-test/win11-*` and never printed; `down` terminates the host and deletes them.
  - `win11:<phase>`: runs a phase of `win11-lab.ps1` on that host: `host`, `iso`, `vm`, `status`, `kit-baseline`, `kit-install`, `kit-policy` and `wk`. `IT_W11_WK_VCREDIST=1` makes `wk` install the Visual C++ 2015-2022 Redistributable x64 first (signature checked); `IT_W11_WK_RECHECK=1` adds the re-check block `WK.re.*`.
- **`security-tests/aws-integration/win11-lab.ps1`:** builds and drives the Windows 11 lab as SYSTEM through SSM: the Hyper-V role and a failsafe scheduled task that survives restarts; the Windows 11 Enterprise 26H2 Evaluation ISO checked against Microsoft's published SHA-256; an internal switch with NAT and a Generation 2 VM with virtual TPM and Secure Boot, a local administrator and a standard user, and a checkpoint `clean`; the W2 kit in the VM through PowerShell Direct; and phase WK in the VM through a one-time scheduled task, with the API key handed in as a file that only SYSTEM and Administrators can read.
- **`security-tests/aws-integration/windows-kiro-cli-suite.ps1` (phase WK):** installs Kiro CLI from Kiro's manifest (SHA-256 and Authenticode signer checked) as SYSTEM, with and without `INSTALLFOLDER`, deploys the policy, creates a standard user after the deployment and drives `kiro-cli chat --v3 --no-interactive` as that user: admin denials, the case check `WK.policy-case`, the admin `ask` checks `WK.policy-ask-*` with and without `--trust-all-tools`, invalid policy files, global hooks, exit code 2, a guard from issue #42, global steering. `WK.re.*` measures the mitigations (guards on; rule 21 as `deny`). The suite removes the Users DENY entry only for its own test writes of the policy, and the deployment script puts it back (run 2 failed two checks because that entry also applies to SYSTEM).
- **`security-tests/aws-integration/architecture.md`:** the integration-test environment drawn from the code: network, servers, identities, data paths, external endpoints and the Windows 11 lab host.

### Changed
- **`--trust-all-tools` and admin `ask` (F2):** the documentation said that `--trust-all-tools` and `/tools trust-all` cannot weaken an admin rule. Corrected: an admin `deny` holds (measured), but in headless runs `--trust-all-tools` approves commands under an admin `ask` rule (measured, Kiro CLI 3.5.0; Kiro's governance page and permissions page disagree). Use `deny` for anything that must never run unattended, and keep `--trust-all-tools` out of pipeline and agent configurations.
- **Shell deny rules on Windows (F1):** where they are presented as controls, the documentation now states the limit: matching is case-sensitive, a casing the policy does not list runs, deny is a guardrail and not a boundary, egress needs a network control, and the case-insensitive guard hooks back up only what they cover.
- Part 1: Section 4.1.1 (operating system) states what was measured on Windows 11 and the Visual C++ prerequisite of Kiro CLI; Section 4.2.1 adds the F1 and F2 caveat; Section 4.2.3 states the per-user build run as SYSTEM as measured (Windows Server 2022) instead of *(verify)*. `agent-hooks/README.md` records the global hooks measured in Kiro IDE and Kiro CLI on Windows. The integration-test README documents the new stages and their environment variables.
- "W2", reserved in 1.10 for the Windows 11 client validation, is now the kit above. `README.md` (validation scope, Start Here, documentation table), `AGENTS.md`, `QUICK-REFERENCE.md`, `CONTRIBUTING.md`, `SECURITY.md`, `kiro-docs/README.md`, `.kiro/steering/repo-map.md`, the integration-test README, the Intune runbook (the "What was tested" note, the pilot checklist and the open questions) and the coverage section of `kiro-docs/aws-integration-test-evidence.md` point to the kit and now state the results of the Windows 11 run of 2026-11-19 and 2026-11-20 and what stays open in issue #43.

**Round 2 (Windows 11, Kiro IDE 1.5.11, 2026-11-21). Refs #43 (issue stays open).** A second test round on the Windows 11 Enterprise 26H2 (Evaluation) lab VM with Kiro IDE 1.5.11 (system-wide build). Intune was emulated (a SYSTEM scheduled task from a 32-bit or 64-bit `cmd.exe`; not a real Intune tenant); the Kiro window tests are an interactive session of a standard user. One run per result unless a count is given; not reviewed by a second person. This change is documentation plus one example script; no existing script changes. The full table (R2-01 to R2-95), the method, the limits of each row and "Not tested" are in [`kiro-docs/mdm-test-evidence.md`](kiro-docs/mdm-test-evidence.md#round-2-windows-11-kiro-ide-1511-2026-11-21).

### Results (Round 2: Windows 11 Enterprise 26H2 VM, 2026-11-21, Kiro IDE 1.5.11; one run each unless stated)
- **Installer (R2-01 to R2-07, R2-30 to R2-36, R2-87):** silent install and uninstall of the system-wide build as SYSTEM exit 0; it registers only in the 64-bit view of HKLM, and the per-user build only in the installing user's HKCU. Without `/LOG=` no installer log was found; `/LOG=` into a folder that does not exist ended with exit 1 and installed nothing. Without `/MERGETASKS=!runcode` a first install started Kiro as SYSTEM, and an install while that Kiro ran ended with exit 1 (seen 3 times). The installer appears to reuse the stored `runcode` choice (R2-36, R2-87; likely explanation, not shown directly).
- **Policy file (R2-10 to R2-16, R2-20 to R2-23):** `lockdown-windows.ps1` updated and rolled back a changed policy over the locked file, from 64-bit and 32-bit SYSTEM hosts (Entra ID policy variant, a one-line change). A plain `Copy-Item -Force` over the locked file failed also as SYSTEM, and without error handling the script still exited 0.
- **Wrappers and drift (R2-24 to R2-28, R2-40 to R2-50, R2-88):** the Win32 detection script as shipped (`$Options = @()`) reported a correct Entra ID deploy as not detected; configured, the wrappers detected and repaired the drift cases tried. A missing staged script needs a full deploy. A standard user could not overwrite or delete the policy file. A new local user's profile got the hook file (console sign-in, local account).
- **Constrained Language Mode (R2-60 to R2-66, R2-80 to R2-86; one lab App Control policy):** the unsigned reference script ended with exit 1 and changed nothing in the items checked. Signed, it failed when started with `-File` and deployed when started with the call operator (separate runs; the cause is not understood). The two signed detection wrappers as shipped reported a correct deploy as not compliant; the remediation wrapper was not run as shipped. An unsigned guard hook ended with exit 1. The example script without .NET calls deployed and updated the policy file unsigned.
- **Kiro IDE 1.5.11 window tests (R2-70 to R2-76, R2-90 to R2-95):** an in-place upgrade from 1.4.236 kept the policy file, its lock, the hooks and `UpdateMode`. Global hooks ran and blocked; the admin deny rule refused `Invoke-WebRequest`; a policy file with a UTF-8 BOM gave "Permissions: Failed" and the one tool call seen was reported as denied. The mode menu has Supervised, "Accept file changes" and "Approve for me", and no "Autopilot".
- **Letter case in Kiro IDE (R2-74, R2-94): a weakness in how the policy is enforced, seen once per mode.** In Supervised mode `INVOKE-WEBREQUEST` in capitals was not refused by the deny rule and Kiro asked the user (Deny chosen). In "Approve for me" no prompt appeared and Kiro reported that the command ran; this rests on Kiro's own sentence, the command string and its output were not visible, so it is consistent with the deny rule not matching that spelling, not a direct observation of it. One cmdlet, one casing, one rule. This fits F1 (Kiro CLI 3.5.0).
- **Not tested:** a real Intune tenant; other App Control or AppLocker policies, allow rules, signed hooks; in Kiro IDE 1.5.11 the sign-in restriction, a UTF-16 policy file, "Accept file changes" and an answered admin `ask` prompt; Kiro CLI; Entra ID accounts.

### Added (Round 2)
- **`kiro-docs/mdm-test-evidence.md`:** the section "Round 2: Windows 11, Kiro IDE 1.5.11 (2026-11-21)" with the environment and method, one row per test ID with its limit, and "Not tested".
- **`mdm/examples/`:** `Deploy-KiroPolicy-CLM.ps1`, an example script for the policy step with no .NET calls, for devices in Constrained Language Mode, and a `README.md` with what was measured and its limits. It is not part of the reference deployment and not covered by the test suites.

### Changed (Round 2)
- **`kiro-docs/intune-deployment.md`:** the Round 2 installer, deploy, update, rollback, detection and drift results; `/MERGETASKS=!runcode` and `/LOG=` with an existing folder in every install command; the wrappers' `$Options` line must be set; a new section for devices with App Control script enforcement, with the known limitation of the wrappers there.
- **`managed-settings/README.md`, `kiro-docs/permissions-and-managed-settings.md`:** what was measured with Kiro IDE 1.5.11 (policy enforcement, letter case, the mode menu, the approval prompt, a BOM policy file), with the limits of each row.
- **`agent-hooks/README.md`:** global hooks and steering as seen in Kiro IDE 1.5.11, and the guard result under Constrained Language Mode (re-test the hooks on such devices before relying on them).
- **`managed-settings/README.md`:** a precaution for the mode "Approve for me" in Kiro IDE (test it on a pilot device before you allow it on managed devices; it rests on one run, R2-94).
- **`SECURITY.md`, `README.md`, `AGENTS.md`, `kiro-docs/agent-runtime-governance.md`:** the F1 letter-case check in Kiro IDE is no longer listed as not run; they state the one run per mode with Kiro IDE 1.5.11 and point to the limits.
- **`README.md`, `AGENTS.md`, `QUICK-REFERENCE.md`, `CONTRIBUTING.md`, `kiro-docs/README.md`, `.kiro/steering/repo-map.md`:** the Round 2 run and the new folder `mdm/examples/` are listed.
- No existing script in `mdm/`, `mdm/intune/`, `agent-hooks/` or `security-tests/` changes, and the version number is not changed.

---

## [1.10] - 2026-11-19

Windows and Microsoft Intune deployment (issue #42), refreshed against the Kiro and Microsoft Intune documentation on 2026-11-19.

### Fixed
- **Intune detection did not work as documented.** `mdm-endpoint-enforcement.md` named `lockdown-windows.ps1 -Check` as the Intune detection script. Remediations treat only exit 1 as an issue, Win32 app detection needs exit 0 plus STDOUT and no STDERR, neither accepts script arguments, and the script needs its sources on the device. A device with drift (exit 3) or without the policy source (exit 2) was therefore reported as healthy and never repaired. Now:
  - `lockdown-windows.ps1 -StageSources` (Win32 app install) copies the script, the validated policy and the verified hook files to `C:\ProgramData\Kiro\deploy\` with the policy's ACL; `-RemoveSources` is the uninstall command.
  - The wrappers accept `$ExpectedPolicySha256`: without it they can only compare a device with its own staged copy, so a device holding an older package would be reported as installed and never receive a new policy version. Their logs are appended instead of overwritten.
  - New wrappers in `mdm/intune/`: `Detect-KiroPolicy.ps1` (Remediations detection: 0 → 0, any other result → 1, one summary line within the 2,048-character limit), `Remediate-KiroPolicy.ps1`, and `Detect-KiroPolicy-Win32.ps1` (Win32 detection: STDOUT and exit 0 only when compliant, never STDERR; the self-repair path without the Remediations licence).
  - The drift-detection step documents each MDM's convention (Intune, Kandji, Jamf extension attributes).
- **Stale version notes:** "there is no CLI 3.x binary" (`managed-settings/README.md`, `security-governance-features.md`, `permissions-and-managed-settings.md`, `agent-runtime-governance.md`). Kiro CLI 3.0.0 (2026-11-03) is a single `kiro-cli` binary with the V3 harness as the default; a headless run that names no harness still starts on V2, so scripts should pass `--v3`. The "latest on 2026-10-08" values are replaced by a changelog link and a minimum-version table (sign-in controls IDE 1.2 / CLI 2.25.0, system-wide installer IDE 1.4.62, Enterprise Management IDE 1.4.154 / CLI 3.1.0, `PermissionRequest` and `updatedInput` IDE 1.4.236 / CLI 3.4.0).
- **Line endings:** a new `.gitattributes` keeps `agent-hooks/`, `mdm/`, `managed-settings/` and `*.sh` LF on every platform. A CRLF checkout (the Git for Windows default) made the `SHA256SUMS` check fail.
- `Test-ReparsePoint` in `lockdown-windows.ps1` now also detects dangling junctions and symbolic links.
- **`lockdown-windows.ps1` no longer trusts files and folders that existed before it ran** (found in the review of this change). A standard user can create `C:\ProgramData\Kiro` and files in it before the first deployment and keep a handle open; re-applying the ACL does not revoke such a handle, and the staged script is later run as SYSTEM. Files are now always prepared as a new file in an administrators-only work folder and renamed over the old one (never written in place, also when the content already matches but the owner or ACL was not set by the script; the old file is put back if the rename fails), folders are created under a random name and renamed into place, and an existing folder that a non-administrator owns or can re-permission is moved aside to `<name>.untrusted-<id>`. A directory at a file path is refused with a clear message; `-RemoveSources` deletes the staged tree without following junctions; one broken user profile no longer stops the other profiles or the machine-level steps.

### Added
- **`kiro-docs/intune-deployment.md`:** Windows runbook covering the per-user vs system-wide installer (IDE 1.4.62+), the policy Win32 app and staging, Remediations, managed updates, per-user hooks and steering, troubleshooting logs, a pilot checklist and the open questions. Two open questions from the issue are answered by current documentation: the Kiro CLI policy on Windows is `update.baseUrl` in `HKLM\SOFTWARE\Policies\Kiro\CLI`, and `HKLM\SOFTWARE\Policies` is a shared key under WOW64.
- **`-DisableUpdates`:** writes `HKLM\SOFTWARE\Policies\Kiro` → `UpdateMode` (REG_SZ) = `none` in the 64-bit registry view; `-Check` reports drift.
- **Windows hooks:** PowerShell ports of the three guards (`agent-hooks/windows/`), the Windows v1 hook file `hooks/banking-guards.windows.json` (exit 2 blocks; `shell` matcher covers `execute_pwsh`), and `-InstallUser`, which installs it into every local profile and `C:\Users\Default` and skips profiles with a junction or symbolic link under `.kiro`. All are listed in `agent-hooks/SHA256SUMS`. Kiro documents global hooks for CLI V3; IDE support and the hook shell on Windows remain pilot items.
- **Windows rules in the admin policy** (`managed-settings.banking.json`, `managed-settings.option-b.json`; 19 → 34 rules). The shell rules were POSIX-shaped only, so on Windows, where the shell tool is PowerShell (`execute_pwsh`), the primary control did not cover PowerShell cmdlets, `cmd.exe` commands or `.exe` / `.cmd` program names. New rules 9–15 (deny), 20–25 (ask), 28 (`fs_read`) and 30 (`fs_write`) mirror each existing group with the same effect and add Windows-only cases (registry start-up entries, Microsoft Defender settings, event logs, firewall, scheduled tasks, services, ACLs, Credential Manager, Startup folders, PowerShell profiles). Patterns start with the command name, contain no backslash, and list canonical and lowercase spellings; `powershell -File` and other routine commands are deliberately not matched. Case sensitivity, alias handling and `~` expansion on Windows are not documented by Kiro and are listed as pilot items in `managed-settings/README.md`. Rules were renumbered in the README table.
- **`managed-settings/tests/test-policy.sh`** (CI: `validate-governance`): both policy files carry the same rules apart from rule 1, only documented fields and deny/ask, no backslashes, shell pattern shape, the README rule table matches the file order, every shell rule is exercised by at least one vector, and over 100 command vectors give the expected effect, including routine commands that must not match.
- **Managed updates, system-wide installer and steering by MDM** in `mdm-endpoint-enforcement.md` and Part 1 Section 4.2.3.
- **Enterprise Management (preview)** in `security-governance-features.md` (Section 2.9) and `agent-runtime-governance.md` (layer 4b).
- **Tests:** `mdm/tests/test-lockdown-windows.ps1` covers the wrapper exit-code mapping (real staged script and stubs exiting 0, 1, 2, 3 and 5), staging, `-DisableUpdates`, `-InstallUser` and `-RemoveSources`. `agent-hooks/tests/run-tests.ps1` runs the PowerShell guards against the shared fixtures plus Windows cases. The integration test gains W3 (PowerShell hooks) and W4 (the Intune flow as SYSTEM on the real paths, with the install, detection, remediation and Win32 detection also started from 32-bit PowerShell); W2 is reserved for the Windows 11 client validation in issue #43, and K2 gains `PermissionRequest` and `updatedInput` checks against the admin policy (run only when a Kiro API key is provided).
- **CI:** a `validate-windows` job on `windows-latest` (PowerShell parse check, `SHA256SUMS` on a Windows checkout, the Windows MDM and hook tests under Windows PowerShell 5.1 and PowerShell 7).

- **Follow-up items from the issue discussion** (all re-checked against the primary sources on 2026-11-19):
  - `auth_portal_url` (Kiro CLI 3.5.0+) was unknown to the three lockdown scripts, so `--strict` / `-Strict` refused a valid policy and the default mode printed a wrong "Kiro ignores it" warning. It is now a known key and validated (https, no credentials, query or fragment, at most 2,048 bytes); length limits are counted in UTF-8 bytes, as Kiro does. The `AuthPortalUrl` OS policy is documented.
  - "Sign-in controls fail open" was too broad: the method restriction fails open, the sign-in portal falls back to the default portal. Corrected in `managed-settings/README.md`, `permissions-and-managed-settings.md` and `security-governance-features.md`.
  - The Intune runbook adds: installer signature and hash baseline before packaging, the redirected Uninstall key and the "32-bit app" setting for registry detection rules, devices that already have the per-user build, SYSTEM copy vs user context for per-user files, an explicit "logged-on credentials = No" for Remediations, and new pilot-checklist items and open questions.
  - Per-user hook files are described as editable by the user (the script sets no owner or ACL), not as "user-owned". The steering example no longer follows a junction at `.kiro`.
  - Part 1 Section 4.1.1 states the WorkSpaces operating system choice: AWS-provided Windows bundles run Windows Server, Windows 10/11 needs BYOL, and Kiro lists Windows 10/11 for the IDE and Windows 11 for the CLI.
- **Validation scope** stated in `README.md`, the Intune runbook and the evidence page: the Windows scripts were run on Windows Server 2022 as SYSTEM; no Kiro client on Windows, no Windows 10/11 client and no Intune tenant were tested.

- **Integration test results (2026-11-19, final code):** W1 Windows MDM 14/14 (suite 102/102 default and 136/136 admin under Windows PowerShell 5.1 and PowerShell 7); W3 PowerShell hook guards 384/384 under both versions, about 1 second per guard call; W4 Intune flow 30/30; L1 18/18; L2 16/16; L3 chaos rounds 1 and 2 with 0 BYPASSED. Windows Server 2022 as SYSTEM, without a Kiro client. `kiro-docs/aws-integration-test-evidence.md` records the method, the nine runs, the findings and a coverage table of what was and was not tested.

### Changed
- Part 1: Section 3.2 names the WorkSpaces streaming protocol DCV (formerly WSP); the Section 4.1.1 bundle row no longer names GraphicsPro; version 1.10.
- Integration test: L1 runs the admin policy tests (`L1.policy`); `L2.hooks-verified` checks the top-level `*.sh` entries of `SHA256SUMS`, which is what Linux deploys.
- `README.md` (Start Here, documentation table, version 1.10), `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md` (CI description), `QUICK-REFERENCE.md`, `kiro-docs/README.md`, `agent-hooks/README.md` and the integration-test README describe the new files, commands and checks.

---

## [1.9.1] - 2026-10-10

Integration test in a sandbox AWS account and the fixes it found. Sanitized results: [`kiro-docs/aws-integration-test-evidence.md`](kiro-docs/aws-integration-test-evidence.md).

### Added
- **`security-tests/aws-integration/`:** an isolated, reproducible integration test. A CloudFormation harness provides disposable Linux (AL2023) and Windows Server 2022 runners: SSM only, no inbound rules or SSH keys, IMDSv2, encrypted volumes, terminate-on-shutdown with a failsafe timer, and a short-lived results bucket. An orchestrator stages a bundle, runs the suites, deploys and verifies the CDK app, tests the `nat-dns-firewall` egress mode with a probe in the WorkSpaces subnet, tears everything down and scans for leftovers.
- **Results (final code):** L1 CI parity on Linux 17/17; L2 root MDM lockdown 16/16; L3 chaos rounds 1 and 2 with 0 BYPASSED; W1 Windows MDM 14/14 under PowerShell 5.1 and 7; C1 real deployment of all 5 stacks 36/36, including alarm delivery to the encrypted SNS topic for all 7 alarms; C2 DNS Firewall allowlist 13/13; K1 Kiro CLI 2.29.0 installed and locked down behind the allowlist 3/3. The Kiro end-to-end prompts (K2) were skipped because no Kiro API key was provided.
- **`-c egressAllowedDomains=a,b`:** extra DNS Firewall allowlist entries for one run (exact hostnames or `*.`-wildcards; a bare `*` is rejected), merged into `egress.allowedDomains`.

### Fixed
- **Dependencies:** the lockfile had 1 critical and 36 high `npm audit` advisories. Upgraded to aws-cdk-lib 2.273, cdk-nag 2.38, CDK CLI 2.1145, Jest 30, TypeScript 5.9, ESLint 9 (flat config `eslint.config.mjs` replaces `.eslintrc.json`) and typescript-eslint 8, giving 0 critical and 0 high. The CI audit step is now blocking (`continue-on-error` removed).
- **Lockfile:** regenerated with npm 10, the npm bundled with Node.js 22 that CI uses; an npm 11 lockfile failed `npm ci` there.
- **CDK deprecations:** `addStackDependency` / `addResourceDependency`. The cross-stack reference strength is pinned to `strong` in `cdk.json`, so the existing CloudFormation exports are unchanged.
- **AWS Config:** the PDPA RDS rules are explicitly scoped to `AWS::RDS::DBInstance`.
- **Chaos harness:** evidence records for steps run through `$(dev …)` showed the previous step's command, because `dev()` ran in a subshell. The new `devo()` helper keeps the command and exit code; verdicts were not affected.
- **Integration-test teardown:** the retained-bucket cleanup passed `--bypass-governance-retention` to buckets without Object Lock, which S3 rejects, and it now also fails on per-object errors instead of looping. The leftover scan now checks every tagged ARN against its own service (the tagging API lists deleted resources for a while) and adds a name-prefix scan. Final result: `LEFTOVERS total=0`.
- **Docs:**
  - `SECURITY.md` still described the CI audit as "reported, not blocking";
  - `mdm-endpoint-enforcement.md`, `agent-runtime-governance.md` and `mdm-test-evidence.md` said that a CI job for the hook and MDM tests was still to be added, although `validate-governance` already runs them;
  - the `kiro-docs/README.md` index did not list the new evidence page.

### Changed
- `mdm-test-evidence.md` and `chaos-pentest-evidence.md` link to the new results for the current scripts and harness.
- `AGENTS.md`, `CONTRIBUTING.md` and `cdk/README.md`: 91 tests, the npm 10 lockfile rule, the integration test, and `-c egressAllowedDomains=`.
- **Docs move with the change:** a new rule in `AGENTS.md`, `CONTRIBUTING.md` (pre-pull-request checklist) and `.kiro/steering/repo-map.md`. Every pull request updates `README.md`, `CHANGELOG.md` and every related doc.
- README: a Start Here entry for the evidence pages, and version 1.9.1 in the footer. `SECURITY.md` and `CONTRIBUTING.md` describe the manual integration test. `cdk/README.md` notes the sandbox deployment test.

---

## [1.9] - 2026-10-09

Correction release. A review of 1.0–1.8 found inaccurate regulatory citations, data-location and network claims that do not match the official Kiro documentation, Kiro settings and commands that do not exist, hooks that failed open, and CDK defects. This release fixes them and records two changes that were merged after 1.8.

### Fixed
- **MAS TRM citations** remapped to the January 2021 table of contents: audit logging 15 → 12.2, security-by-design 5.2 → 5.4, change management 7.1 → 7.5, key management 10.1 → 10.2, VDI 8.5 / 11.5 → 9.3 / 11.3 / 11.4, secure coding "Section 10" → 6.1, monitoring 12.1 → 12.2
- **Incident notification:** the cancelled Notice 644 "24 hours" step is replaced by MAS Notice FSM-N05: notify MAS within 1 hour of discovery of a relevant incident (para 7) and submit a root-cause and impact report within 14 days (para 8)
- **Outsourcing:** MAS Notice 658 and the Guidelines on Outsourcing (Banks / FIs other than Banks), effective 11 Dec 2024, replace the cancelled 2016/2018 guidelines; TRM 3.4 (third-party services) added
- **AI governance:** the final MAS Guidelines on AI Risk Management (published 7 Oct 2026, effective 7 Oct 2027) replace the 2025 consultation paper
- **PDPA:** significant-scale and significant-harm tests, 3-day PDPC notification, Transfer Limitation Obligation (s26), purpose-based retention, NRIC authentication cessation by 31 Dec 2026
- **Overclaims:** "MAS compliant", "full compliance" and "tested" replaced with "MAS-aligned" wording; institution-specific numbers labelled as example policy
- **Data location:** Kiro has no Singapore profile region. Kiro content is stored and processed in the profile region (`us-east-1` or `eu-central-1`), inference scope is set per model (Geography for Claude models, Global for GPT-5.6 Sol, Terra and Luna), and Kiro use is treated as a cross-border transfer
- **Network:** removed the non-existent `com.amazonaws.ap-southeast-1.q` and `.codewhisperer` endpoints and the unused `bedrock-runtime` endpoints; documented the official Kiro VPC endpoint names (profile region only) and the official firewall allowlist; no longer advises blocking `prod.us-east-1.auth.desktop.kiro.dev` (restrict sign-in methods in `managed-settings.json` instead)
- **Kiro configuration:** removed invented `kiro.*` settings keys, `aws q` commands and `AWS::Q::*` CloudTrail data selectors; replaced with `kiroAgent.agentAutonomy`, permission rules and Kiro console steps
- **Hooks:** command normalisation (`sh -c` wrappers, quoting, compound commands, `git -C` / `-c`); PEM pattern bug fixed (`grep -e`); the audit logger writes valid hash-chained JSONL without raw input
- **CDK:** EndpointNacl associated with the Endpoints subnets; no-MFA sign-in filter limited to successful IAM-user logins; IAM policy-change filter completed to CIS 4.4; lifecycle transitions always before expiration; build without `ts-node` (`tsc` to `build/`); redundant cdk-nag suppressions removed
- **Skills:** wrong code examples fixed (boto3 `put_bucket_encryption`, Secrets Manager client, rate limiter, missing import, account numbers in audit logs, balance race); nested code fences in the Skills Development Guide that rendered Sections 5–7 and 9 as code; corrected claims about how Kiro activates skills
- **Navigation:** the Part 1 table of contents links Sections 5–14 to Part 2, and the trailing "Document continues" placeholder is replaced by a link to Part 2

### Changed
- **Repository renamed** from `kiro-banking-best-practices` to `kiro-fsi-best-practices` to reflect that the MAS TRM Guidelines apply to all MAS-regulated financial institutions. Project titles and audience descriptions now say "FSI"; the banking reference implementation, file names and CDK physical resource names (`kiro-banking-*`) are unchanged. GitHub redirects the old URL.
- **Test fixtures:** the AWS documentation example secret key is now assembled at runtime in the hook and PII-pattern test fixtures, so repository secret scanning does not flag the example credential pair.
- **Kiro 1.x governance model:** runtime controls moved to the admin policy (`managed-settings.json` deny/ask rules and sign-in restriction), user `permissions.yaml`, v1 hook files and workspace trust; the reference agent migrated from `toolsSettings` to `permissions.rules`; MCP lockdown through MCP governance, a version-pinned registry and workspace trust
- **MDM:** `mdm/lockdown-*` deploy `managed-settings.json` to the official per-OS paths with validation (no `allow` rules), hash-verified hook deployment, a drift check and a dry-run mode; limits documented (a local administrator can still change the files)
- **Chaos harness:** safety gates (throwaway VM, no deletion of existing users); round 2 now exercises the shipped hooks, the shipped policy and `mdm/lockdown-linux.sh`
- **CDK:** `kiroProfileRegion` (Kiro interface endpoints are created only when the stack runs in the profile region); flow logs encrypted with a dedicated rotating CMK; WorkSpaces security-group egress explicitly restricted in the default egress mode; flags for account singletons (GuardDuty, Security Hub, Access Analyzer); configurable backup schedule (default 02:00 SGT). No existing resource is replaced; construct IDs, physical names, exports and Config rule names are unchanged. CDK tests 27 → 86
- **Skills and steering:** one tested PII pattern catalogue shared by the skill, its reference and the PDPA checklist; trigger phrases moved into skill descriptions; clear split between `mas-compliance-review` (regulatory and IaC mapping) and `banking-code-review` (application code); unified masking (`S****567D`); steering files have explicit frontmatter (`banking-standards`: always; `fairness`: fileMatch on model, scoring, decisioning and pricing code)
- **Diagrams:** the README architecture and security-layer diagrams are now Mermaid, rendered by GitHub and kept in sync with the text; they show the allowlisted egress, the Kiro service in the profile region and corrected TRM references. The outdated PNGs (Bedrock endpoint, TRM 8.5 / 15 labels) are removed, and `diagrams/generate_diagrams.py` is updated for optional PNG export
- **QUICK-REFERENCE.md:** the 6-week phase table is replaced by the effort and exit-criteria plan; the document map lists `managed-settings/`, `agent-hooks/README.md`, `mdm/` and the governance references
- **CI:** Node.js 22; a new governance job runs the hook regression tests, verifies `agent-hooks/SHA256SUMS`, validates the managed-settings and hook JSON and runs the MDM dry-run tests; the PII pattern tests and `./validate-repo.sh` also run in CI
- **`validate-repo.sh`:** read-only, resolves each link relative to the linking file's directory, broader scope (`managed-settings/`, `mdm/`, `security-tests/`, `diagrams/`)
- **Repo hygiene:** `.gitignore` covers secrets and key material, local tool state, Python caches and coverage output; `SECURITY.md`, `CONTRIBUTING.md` and `AGENTS.md` describe the current checks and the pull-request flow
- **Merged after 1.8, recorded here:** objective implementation plan with effort estimates and exit criteria instead of a fixed 6-week timeline (#29, 2026-06-05); data location described as a customer preference, not a MAS requirement (#31, 2026-06-30)

### Added
- Applicability table of MAS TRM and Cyber Hygiene notices across MAS-regulated sectors (FSM-N03 … FSM-N26); FSM-N05 availability / RTO and FSM-N06 cyber hygiene requirements; note on Consultation Paper P012-2026
- `managed-settings/`: reference admin policies (Option A IAM Identity Center, Option B external IdP), user `permissions.yaml` template, pinned MCP registry example and deployment guide
- `kiro-docs/permissions-and-managed-settings.md`; `agent-hooks/README.md`, the v1 hook file `agent-hooks/hooks/banking-guards.json` and `agent-hooks/SHA256SUMS`
- Opt-in CDK egress mode `nat-dns-firewall` (public /28 subnets, one NAT gateway, Route 53 Resolver DNS Firewall allowlist built from the official Kiro firewall list, block-all default); `-c region=<r>` and `-c egress=<mode>` context overrides; optional AWS Config recorder and delivery channel (`createConfigRecorder`, default `false`)
- CloudWatch alarms for root account usage (CIS 4.3), CloudTrail changes (CIS 4.5) and KMS key disable or scheduled deletion (CIS 4.7)
- Tests: 98 hook regression tests with exact exit codes, MDM dry-run tests (46 Linux, 35 macOS) and 346 PII pattern checks (`.kiro/skills/pii-detection/tests/patterns.test.sh`)

### Security
- Guard hooks fail closed: exit 2 on any error, on empty or invalid input and when `jq` is missing (the 1.8 hooks let these calls through); broader secret and NRIC/FIN coverage (S, T, F, G and M series)
- Admin `deny` / `ask` rules for force pushes, history rewrites, destructive commands, credential reads, `git push` and deploy commands; sign-in restricted to the corporate identity
- CloudWatch alarms now deliver: the audit KMS key grants `cloudwatch.amazonaws.com` and the SNS topic policy allows CloudWatch to publish (both scoped to the account)
- Audit-log bucket: Object Lock default retention (GOVERNANCE) and noncurrent version expiration; KMS key policies for CloudTrail, CloudWatch Logs and WorkSpaces scoped with source and encryption-context conditions
- A real AWS account ID removed from `cdk.context.json`
- Documented the client-side enforcement limit: a local administrator can bypass Kiro client controls, so endpoint controls and server-side boundaries (branch protection, IAM, egress allowlist) stay authoritative

### Corrections to earlier entries

The entries below are kept as written; these statements in them are superseded:
- **1.8:** the MDM lockdown is not "immutable, append-only, self-healing". It deploys the files read-only for standard users, detects drift and restores the files on the next scheduled run; a local administrator can still change them ([`kiro-docs/mdm-endpoint-enforcement.md`](kiro-docs/mdm-endpoint-enforcement.md))
- **1.8:** "round 2 closes 4/6 endpoint gaps" is withdrawn. The round-2 "closed" items were simulated by the harness (a purpose-written audit hook, a bash function imitating `denyByDefault`, a `noexec` home and a root-only file set up by the harness), and the shipped hooks failed open on errors and missed common variants ([`kiro-docs/chaos-pentest-evidence.md`](kiro-docs/chaos-pentest-evidence.md))
- **1.8:** `denyByDefault` is not the primary agent control: agent `toolsSettings`, including `denyByDefault`, is deprecated in Kiro 1.x and has no equivalent. The primary control is the admin policy in `managed-settings.json`
- **1.7:** #13 was never merged; the `AGENTS.md`, steering map and "Start Here" work landed in #14
- **1.3:** ComplianceStack defines 19 AWS Config managed rules (it always did; "18" was a miscount), and there are now 5 stacks (BackupStack was added on 2026-05-17 in #1, which no earlier entry recorded). The "8 PrivateLink endpoints" included `q`, `codewhisperer` and `bedrock-runtime` endpoints in `ap-southeast-1` that do not exist or were unused; 1.9 removes them
- **1.0, 1.3, 1.4:** "MAS-compliant" should read "MAS-aligned"; the 1.4 sources "MAS Outsourcing Guidelines (Jul 2016)" and "AI Risk Management Guidelines (2025 consultation paper)" are superseded by Notice 658 with the Guidelines on Outsourcing (effective 11 Dec 2024) and by the final AI Risk Management Guidelines (7 Oct 2026)

---

## [1.8] - 2026-06-05

### Added
- **MDM / endpoint-managed enforcement** `kiro-docs/mdm-endpoint-enforcement.md` + cross-platform lockdown references `mdm/lockdown-{linux.sh,macos.sh,windows.ps1}` (immutable, append-only, self-healing) with tests; `destructive-fs-guard` hook (#22)
- **Chaos / penetration test** `security-tests/chaos/` (non-privileged human + Kiro agent) + sanitized hash-chained evidence `kiro-docs/chaos-pentest-evidence.md`; round 2 closes 4/6 endpoint gaps with stronger local controls (#25, #26)
- README **Key Features**: Agent Runtime Governance, Endpoint Enforcement (MDM) & Defense-in-Depth, Adversarial Validation (#27)

### Changed
- Relocated OS-level MDM enforcement out of `agent-hooks/` into top-level `mdm/` (layering: MDM is not a Kiro feature) (#24)
- Hardening from chaos findings folded into best practices: declarative `denyByDefault` as the primary agent control; fixed/managed audit path; application allow-listing; server-side as the authoritative boundary

---

## [1.7] - 2026-06-04

### Added
- **Agent Runtime Governance** (Layer 4): `kiro-docs/agent-runtime-governance.md` + `agent-hooks/` reference hooks (`pii-guard`, `git-guard`, hash-chained `audit-logger`) and locked-down `banking-secure.agent.json` (#11, #12)
- Consolidated Kiro Security & Governance features reference `kiro-docs/security-governance-features.md` (#4, #7)
- `AGENTS.md`, steering map (`.kiro/steering/repo-map.md`), README "Start Here" + 15-minute quickstart for first-time Kiro users (#13, #14)

### Changed
- Renamed `README-Kiro-Banking-Best-Practices.md` to `QUICK-REFERENCE.md` (#16)
- Redirected `CLAUDE.md` to `AGENTS.md` — repo targets Kiro (#15)
- Aligned `CONTRIBUTING.md` `.kiro` commit policy: skills + steering committed; specs/hooks/settings ignored (#10)

### Fixed
- CI: `Validate Documentation` (allow tracked `.kiro/steering`; scope secret scan) and `Validate CDK` (lockfile sync + AZ context cache) now pass on `main` (#8, #9)

---

## [1.6] - 2026-03-11

### Added
- Architecture diagrams (PNG), `SECURITY.md`, steering samples, kiro-docs source/freshness tracking

### Changed
- README consolidation

---

## [1.5] - 2026-03-11

### Added
- Option B: Direct IdP federation architecture (Okta / Entra ID, no IAM Identity Center)

### Fixed
- CDK compilation and tests

---

## [1.4] - 2026-02-28

### Added
- **Working Kiro Skills** (`.kiro/skills/`):
  - `mas-compliance-review`: Automated MAS TRM + PDPA + AIRG compliance checking with 6-category review process, fail patterns, and compliance report output
  - `pii-detection`: Singapore-specific PII detection (NRIC, FIN, credit cards, bank accounts) with PDPA-aligned masking and remediation
  - `banking-code-review`: Structured banking code review with 6-section checklist (security, access control, data protection, audit, error handling, AI governance)
  - Reference files: MAS TRM quick reference, PDPA developer checklist
- **GitHub Actions CI/CD** (`.github/workflows/validate.yml`):
  - Documentation validation (required files, no PDFs, no secrets)
  - CDK validation (TypeScript compile, jest tests, cdk synth + CDK Nag)
  - Skill structure validation (SKILL.md exists, frontmatter fields, name matching)
- Updated `.gitignore` to track skills while excluding local Kiro config

### Changed
- Ingested MAS AI Risk Management Guidelines (2025 consultation paper)
- Ingested MAS Outsourcing Guidelines (Jul 2016)
- Ingested ABS Cloud Computing Implementation Guide 2.0
- Enterprise IdP confirmed as Microsoft Entra ID

---

## [1.3] - 2026-02-28

### Added
- **AWS CDK Infrastructure** (`cdk/`): TypeScript CDK modules for MAS-compliant deployment
  - `EncryptionStack`: 3 KMS customer-managed keys (audit, data, workspaces) with rotation
  - `NetworkStack`: VPC + 8 PrivateLink endpoints + security groups + NACLs + flow logs
  - `MonitoringStack`: CloudTrail + S3 log bucket + 4 CloudWatch security alarms + SNS
  - `ComplianceStack`: 18 AWS Config managed rules mapped to MAS TRM + PDPA
- CDK Nag (AwsSolutions) integration for automated security validation
- CDK test suite with assertions for all stacks
- Environment configs (dev/prod) with banking-specific defaults

---

## [1.2] - 2026-02-28

### Added
- **PDPA Compliance**: Personal Data Protection Act (Singapore) coverage with Kiro-specific controls
- **MAS Outsourcing Guidelines**: Third-party risk assessment for Kiro as AWS-managed service
- **MAS FEAT Principles**: AI/ML governance framework for AI-assisted development
- **ABS Guidelines References**: Cloud computing, penetration testing, and red team standards
- **Expanded TRM Mapping**: Deeper cross-references to specific MAS TRM sub-sections
- **CHANGELOG.md**: Version tracking for documentation changes
- **Approved MCP Server Tiers**: Added to README.md (previously only in quick reference)
- **Version History Table**: Added to README.md

### Changed
- **README.md**: Enhanced with MCP server tiers, expanded regulatory references, version history
- **README-Kiro-Banking-Best-Practices.md**: Converted from duplicate overview to concise quick-reference card
- **validate-repo.sh**: Enhanced with 8 validation checks (was 6), including broken links, secrets scanning, TODO detection, large file warnings, markdown structure
- **Part 2 Status**: Corrected from "In Progress" to "Complete"

### Removed
- Duplicate License/Disclaimer text from Kiro-Agentic-SDLC-Banking-Best-Practices.md and Kiro-Banking-Best-Practices-Part2.md (now reference LICENSE file)
- Content duplication between README.md and README-Kiro-Banking-Best-Practices.md

---

## [1.1] - 2026-02-26

### Added
- README.md with project overview, architecture diagrams, and documentation structure
- Updated .gitignore to exclude .vscode config files

---

## [1.0] - 2026-02-25

### Added
- Initial release: AWS Kiro Banking Best Practices for MAS-compliant SDLC
- Kiro-Agentic-SDLC-Banking-Best-Practices.md (Sections 1-4: Architecture, Identity, Network, VDI)
- Kiro-Banking-Best-Practices-Part2.md (Sections 5-10: MCP, SDLC, Data Protection, Compliance, Operations, Incident Response)
- Banking-Skills-Development-Guide.md (Kiro Skills for banking)
- kiro-docs/ technical reference (MCP configuration, security, servers, usage, privacy)
- validate-repo.sh validation script
- MIT License
- CONTRIBUTING.md guidelines
