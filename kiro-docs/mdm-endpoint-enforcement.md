# MDM Endpoint Enforcement

How to deploy Kiro's admin policy (`managed-settings.json`) and the optional guard hooks to every Kiro client (IDE and CLI) on Windows, macOS, Linux and WorkSpaces VDI with an MDM platform, and how to detect drift. This is the deployment side of layer 4a and 4e in [`agent-runtime-governance.md`](agent-runtime-governance.md).

> **Last verified:** 2026-11-19 against the official Kiro documentation (Permission policies: https://kiro.dev/docs/enterprise/governance/permissions/; managed updates: https://kiro.dev/docs/enterprise/managed-updates/; hooks: https://kiro.dev/docs/hooks/; steering: https://kiro.dev/docs/steering/) and the Microsoft Intune documentation (Remediations, Win32 apps). Reference scripts: `mdm/lockdown-linux.sh`, `mdm/lockdown-macos.sh`, `mdm/lockdown-windows.ps1` and the Intune wrappers in `mdm/intune/`. **Windows with Intune:** follow [`intune-deployment.md`](intune-deployment.md).

## What MDM can and cannot guarantee

- **Resists a developer without administrator rights.** The policy file and the hook scripts are owned by root or Administrators, world-readable, and write-protected (Linux `chattr +i`, macOS `chflags schg`, Windows ACL with a deny for Users). A standard user cannot change or delete them.
- **Does not stop an administrator or root.** Kiro enforces the policy in the client, and the official page says it "can be circumvented by users, e.g., via administrative access to their local machine". An administrator can clear the flags or ACLs and edit or delete the file. Developers must therefore not be local administrators.
- **Detects drift instead of preventing it.** Re-run the MDM job on a schedule: it compares SHA-256 hashes with the source and restores anything changed or deleted. Use the `--check` / `-Check` mode (exit 3 on drift) as the detection step and alert on it, mapped to each MDM's convention ([Drift detection](#drift-detection)). Intune does **not** accept exit 3: use the wrappers in `mdm/intune/`.
- **Gives no secrecy.** Kiro and its hooks run as the developer, so the developer can read the hook scripts and the policy. The controls are about integrity, not confidentiality.
- **Covers only managed devices running the Kiro client.** Devices without the file, older clients (for sign-in controls: before IDE 1.2 and CLI 2.25.0) and Kiro Web are not covered. Keep Cloud Sessions off in the Kiro console.

Earlier versions of this page called the controls "tamper-proof" and said they "cannot be removed". That wording was wrong and has been replaced by the statements above.

## What gets deployed

| Item | Linux | macOS | Windows | Owner / lock | Required |
|------|-------|-------|---------|--------------|----------|
| Admin policy `managed-settings.json` | `/etc/kiro/managed-settings.json` | `/Library/Application Support/Kiro/managed-settings.json` | `C:\ProgramData\Kiro\managed-settings.json` (UTF-8 without BOM) | root / Administrators, mode 0644 or Users Read; `chattr +i` / `chflags schg` / ACL deny | **Yes**: the primary control |
| Hook scripts (`--hooks`, `-DeployHooks`) | `/opt/kiro/hooks/` | `/Library/Application Support/Kiro/hooks/` | `C:\ProgramData\Kiro\hooks\`: the PowerShell guards (`agent-hooks/windows/*.ps1`) and the bash scripts | root / Administrators, 0755; same lock; deployed only after `agent-hooks/SHA256SUMS` verifies | Optional (defense in depth) |
| v1 hook file (`--install-user`, `-InstallUser`) | `banking-guards.json` in `~USER/.kiro/hooks/` | `banking-guards.json` in `~USER/.kiro/hooks/` (paths rewritten to the macOS hook directory) | `banking-guards.windows.json` in `.kiro\hooks\` of **every** local profile and `C:\Users\Default` (written by SYSTEM with no owner or ACL change, so it inherits the profile's permissions) | **User-owned** (Windows: editable by the user) | Optional |
| Agent `banking-secure.json` (`--install-user`) | `~USER/.kiro/agents/` | `~USER/.kiro/agents/` (paths rewritten) | Not installed (its hooks match `execute_bash` and reference `/opt/kiro/hooks`) | **User-owned** | Optional |
| Hook audit log (`--audit-user`) | `~USER/.kiro/audit/kiro-hooks.jsonl`, `chattr +a` | Same path, `chflags uappnd` (default) or `sappnd` (`--audit-sappnd`) | Not prepared (no PowerShell audit logger) | User-owned file, append-only flag set by root | Optional, supplementary |
| Staged sources for the Intune wrappers (`-StageSources`) | — | — | `C:\ProgramData\Kiro\deploy\` (repository layout) | Administrators; same ACL as the policy | Windows with Intune |
| `UpdateMode` = `none` (`-DisableUpdates`) | — | — | `HKLM\SOFTWARE\Policies\Kiro` (REG_SZ) | Administrators (registry) | Optional ([Managed updates](#managed-updates)) |

Why the per-user files are user-owned: Kiro loads custom agents only from `~/.kiro/agents` and a trusted workspace's `.kiro/agents`, and global v1 hook files only from `~/.kiro/hooks`. An agent file under `/opt` or `/Library` is ignored. Kiro always asks before the **agent** writes to those directories, but the developer can edit or delete the files. The scripts reinstall them on each run and `--check` reports when they differ, but **the guarantee comes from `managed-settings.json`, not from these files**. Kiro documents global hooks in `~/.kiro/hooks` for **Kiro CLI V3**; whether Kiro IDE loads them needs a pilot test.

Not deployed by these scripts: steering files (guidance only), `mcp.json` (MCP is governed by the console MCP registry, not by locking files), and the user `permissions.yaml` template ([`../managed-settings/permissions.banking.yaml`](../managed-settings/permissions.banking.yaml); MDM may copy it to `~/.kiro/settings/permissions.yaml`, where it remains user-owned).

**Steering by MDM (optional, for consistency):** Kiro allows pushing team steering files to `~/.kiro/steering` "via MDM solutions or Group Policies" ([steering](https://kiro.dev/docs/steering/)). Copy them to every profile and to the default profile (`C:\Users\Default\.kiro\steering\` on Windows, `/etc/skel/.kiro/steering/` on Linux) so new users get them; [`intune-deployment.md`](intune-deployment.md#5-per-user-hooks-and-steering-optional) has a PowerShell example. The files stay user-owned, workspace steering wins on conflict, and custom agents load steering only when it is listed in their `resources` (`banking-secure` lists `file://.kiro/steering/**/*.md`). Kiro Enterprise Management (preview) can deliver steering from the Kiro service instead.

## Global, per-user and local

| Scope | What | Who can change it |
|-------|------|-------------------|
| Machine (MDM, admin-owned) | `managed-settings.json`; hook scripts | Administrators only; drift detected by MDM |
| Organization (Kiro console) | Model list, MCP governance and registry, web tools, API keys, Cloud Sessions, prompt logging | Kiro administrators |
| Per user (MDM-installed, user-owned) | v1 hook file, `banking-secure` agent, hook audit log, optional `permissions.yaml` | The developer (drift reported) |
| Workspace (repository) | Project code, specs, workspace steering, workspace agents and hooks | Repository contributors; workspace agents, steering, MCP configuration and skills load only after the user trusts the workspace |

`availableAgents` governs subagents only: it limits which agents a session may spawn as subagents (with `trustedAgents`, CLI 1.25.0). It does not stop a developer from creating or selecting a workspace or global agent. Agent choice is not an enforcement point; the admin policy applies to every agent.

## Running the scripts

Every script validates **everything first** (policy JSON, `SHA256SUMS`, user hook files, user accounts) and only then installs anything, so a refusal leaves the machine unchanged. All are idempotent, make no network calls, and support a dry run that needs no root.

```bash
# Linux / VDI image (root)
bash mdm/lockdown-linux.sh --dry-run                          # validate and print the plan (no root)
sudo bash mdm/lockdown-linux.sh                               # policy only (Option A file)
sudo bash mdm/lockdown-linux.sh --option-b                    # direct IdP federation policy
sudo bash mdm/lockdown-linux.sh --hooks --install-user alice  # + hooks, alice's v1 hook file, agent and audit log
sudo bash mdm/lockdown-linux.sh --check --hooks --install-user alice   # detection: exit 3 on drift

# macOS (Jamf Pro, Kandji, Intune; runs as root)
sudo bash mdm/lockdown-macos.sh --hooks --install-user alice
```

```powershell
# Windows (Intune Win32 app, SCCM or GPO startup script; SYSTEM or elevated Administrator)
powershell -ExecutionPolicy Bypass -File mdm\lockdown-windows.ps1 -DryRun
powershell -ExecutionPolicy Bypass -File mdm\lockdown-windows.ps1
powershell -ExecutionPolicy Bypass -File mdm\lockdown-windows.ps1 -DeployHooks -InstallUser -DisableUpdates
powershell -ExecutionPolicy Bypass -File mdm\lockdown-windows.ps1 -Check   # exit 3 on drift (SCCM, GPO, scheduled task)

# Intune: the Win32 app also stages the sources; the wrappers in mdm\intune\ run -Check on the device
powershell -ExecutionPolicy Bypass -File mdm\lockdown-windows.ps1 -StageSources -DeployHooks -InstallUser -DisableUpdates
powershell -ExecutionPolicy Bypass -File mdm\lockdown-windows.ps1 -RemoveSources   # Win32 app uninstall
```

Which script is for which Intune feature (details in [`intune-deployment.md`](intune-deployment.md)):

| Script | Intune feature |
|--------|----------------|
| `mdm\lockdown-windows.ps1 -StageSources ...` | Win32 app install command (System context) |
| `mdm\lockdown-windows.ps1 -RemoveSources` | Win32 app uninstall command |
| `mdm\intune\Detect-KiroPolicy-Win32.ps1` | Win32 app custom detection script |
| `mdm\intune\Detect-KiroPolicy.ps1` | Remediations detection script |
| `mdm\intune\Remediate-KiroPolicy.ps1` | Remediations remediation script |

Common options: `--settings FILE` / `-SettingsPath` for another policy file (or `KIRO_MANAGED_SETTINGS_SRC`), `--strict` / `-Strict` to treat warnings such as placeholder values as errors, `--manifest-sha256 HEX` / `-ManifestSha256` to pin the hash of `SHA256SUMS` itself (deliver the pin out of band, for example in the MDM policy). Exit codes: 0 success, 1 usage or environment error, 2 validation refused, 3 drift (check mode).

**Validation before deployment.** The scripts reject a UTF-8 BOM or UTF-16 encoding, malformed JSON, unknown top-level or rule fields, a missing `rules` array, any rule whose effect is not `deny` or `ask` (an `allow` rule would make Kiro reject the whole file and deny every tool call), sign-in rules with more than 16 entries and a non-https `signin_help_url`. Unknown capabilities and placeholder values produce warnings. Hook deployment aborts on any `SHA256SUMS` mismatch, a malformed or unsafe manifest line, a missing manifest, or a user hook file whose command points outside the hook directory or to a script that is not in the manifest.

### Platform notes

- **Linux.** `chattr +i` needs a filesystem that supports it (ext4, XFS); on tmpfs, overlay or NFS the script warns and relies on ownership and mode. The audit log gets `chattr +a`: the developer can append but cannot truncate, overwrite or delete it or clear the flag. The developer still owns `~/.kiro/audit` and can rename it, so the local log is supplementary evidence only.
- **macOS.** `schg` can be cleared by root only at `kern.securelevel` 0; at 1 or higher it needs Recovery or single-user mode, and so does every later MDM update of the file. Use `--no-system-immutable` where that is not acceptable; root ownership and mode 0644 already stop a standard user. The hook directory contains a space, so the rewritten hook commands quote the path; this assumes Kiro passes hook commands to a shell, so verify on a pilot machine or use `--hooks-dest /opt/kiro/hooks`. The default audit flag `uappnd` is a user flag: the owner can clear it with `chflags nouappnd`, so it guards against accidental truncation, not against the developer. `--audit-sappnd` uses the super-user flag instead (the owner cannot clear it; at securelevel 1 or higher neither can root without Recovery mode, which also blocks log rotation).
- **Windows.** The file is written from the bytes of `(New-Object System.Text.UTF8Encoding $false).GetBytes(text)`, so it has no BOM, and its hash is verified after the write. The ACL is rebuilt on every run: owner Administrators, inheritance removed, every other explicit ACE removed (a standard user can pre-create folders under `C:\ProgramData` and plant ACEs), SYSTEM and Administrators Full Control, Users Read (+Execute on the folder), and a deny for Users on Delete, Write, Append and attribute changes. The script refuses a junction or symbolic link at `C:\ProgramData\Kiro`, including a dangling one. It never writes an existing file in place (it prepares a new file in an administrators-only work folder and renames it over the old one), creates folders under a random name before renaming them into place, and moves aside any existing folder that a non-administrator owns or can re-permission, because a handle opened before the lockdown stays usable after an ACL change. Administrators are members of Users, so the deny also blocks an administrator's direct edits until it is removed; the script removes it before each update. `-DeployHooks` deploys the PowerShell guards (`agent-hooks\windows\*.ps1`, no `jq` needed) and the bash scripts (for Git Bash or WSL); `-InstallUser` wires the PowerShell guards with `banking-guards.windows.json` in every profile and skips a profile whose `.kiro` path contains a junction or symbolic link. Kiro does not document which shell runs hook commands on Windows, so the commands are written to work from cmd, PowerShell and Git Bash. `-DisableUpdates` writes `UpdateMode` in the 64-bit registry view. On Windows, `managed-settings.json` remains the primary control.

## Windows: per-user vs system-wide installer

Kiro IDE **1.4.62** added Windows system-wide installers for x64 and ARM64 ([changelog](https://kiro.dev/changelog/ide/1-4-62/)); the managed-updates page lists the Windows variants `-system` (default), `-user` and `-archive`. Use the system-wide installer for MDM, with Intune install behaviour **System**, a file-based detection rule and an uninstall command. Deploying the per-user build in System context is expected to install Kiro into the SYSTEM profile, where users do not see it *(verify)*. The install path, uninstall path and silent switches are not documented by Kiro *(verify on a test device)*; [`intune-deployment.md`](intune-deployment.md#1-kiro-ide-per-user-vs-system-wide-installer) lists the expected values. The IDE troubleshooting sentence "Kiro does not support system-level installation" is the text of the error shown when the **per-user** build runs as Administrator, not a statement about the system-wide installer.

## Managed updates

Kiro IDE and Kiro CLI can each be pointed at a self-hosted update server, or have updates disabled ([managed updates](https://kiro.dev/docs/enterprise/managed-updates/)):

| Setting | Windows | macOS | Linux |
|---------|---------|-------|-------|
| IDE `UpdateMode` = `none` (disables updates; wins over `UpdateUrl`) | REG_SZ in `HKLM\SOFTWARE\Policies\Kiro` (`lockdown-windows.ps1 -DisableUpdates`) | Same managed-policy delivery as `UpdateUrl` | Same managed-policy delivery as `UpdateUrl` |
| IDE `UpdateUrl` (`https://` only) | REG_SZ in `HKLM\SOFTWARE\Policies\Kiro` | `dev.kiro.desktop` managed preferences (MDM profile) | `/etc/kiro/policy.json` |
| CLI `update.baseUrl` | REG_SZ in `HKLM\SOFTWARE\Policies\Kiro\CLI` | Forced value in the `dev.kiro.cli` domain (MDM profile) | Not supported |

The same registry key carries the optional sign-in portal policy for Kiro CLI 3.5.0+: a string value `AuthPortalUrl` under `HKLM\SOFTWARE\Policies\Kiro` (macOS: a forced `AuthPortalUrl` preference in `dev.kiro.desktop`; Linux: `auth_portal_url` in the policy file), which takes precedence over `auth_portal_url` in `managed-settings.json` ([sign-in controls](https://kiro.dev/docs/enterprise/governance/sign-in/)). The lockdown scripts validate `auth_portal_url` (https, no credentials, query or fragment); an invalid portal value does not block sign-in, it sends users to the default portal.

Kiro recommends `UpdateMode=none` on shared machines where Kiro is installed for all users, because standard users cannot apply updates there. Pinning (advertising the version the fleet runs) governs only the automatic update check; users can still install another version by hand. **Kiro's pages conflict here:** managed updates (updated 2026-10-29) suggests blocking `prod.download.desktop.kiro.dev` together with `UpdateUrl`, while the newer [firewall page](https://kiro.dev/docs/privacy-and-security/firewalls/) (updated 2026-11-18) lists the same host for "Auto-updates, Powers registry, and icons". Following the newer page, do not block it fleet-wide; if you must, test the effect on Powers on a pilot device first *(verify)*.

## Drift detection

1. Schedule the deploy run (self-repair) at least daily and at login on VDI.
2. Run the check mode as the MDM detection step and map its result to the MDM's convention:

   | MDM | Convention | Use |
   |-----|------------|-----|
   | Intune Remediations | Only exit **1** means an issue; the script takes no arguments | `mdm/intune/Detect-KiroPolicy.ps1` + `Remediate-KiroPolicy.ps1` ([runbook](intune-deployment.md)) |
   | Intune Win32 app detection | Installed only on exit 0 **and** STDOUT **and** no STDERR | `mdm/intune/Detect-KiroPolicy-Win32.ps1` |
   | Kandji (now Iru) audit script | Exit 0 passes; any other code is a failure and runs the remediation script ([Kandji](https://support.kandji.io/kb/custom-scripts-overview), checked 2026-11-19) | `--check` directly (exit 3 is a failure) |
   | Jamf Pro extension attribute | Reads the value printed as `<result>...</result>` on STDOUT, not the exit code *(verify in your Jamf Pro version)* | A wrapper such as the one below, with a smart group on `Drift` |
   | SCCM configuration item, scheduled task | Your rule | `--check` / `-Check` exit code |

   ```bash
   #!/bin/bash
   # Jamf Pro extension attribute (runs as root): report the lockdown check as a value.
   REPO="/Library/Management/kiro-fsi"   # example: the admin-only copy your Jamf policy installed
   if bash "$REPO/mdm/lockdown-macos.sh" --check --hooks >/dev/null 2>&1; then
     echo "<result>Compliant</result>"
   else
     echo "<result>Drift</result>"
   fi
   ```

   Use the same options as the deployment. The check needs the policy source and `agent-hooks/` next to the script, in a root-owned folder, for the same reason as the Windows staging.
3. Compare the deployed hash with the expected value that `--dry-run` prints (`sha256=...`), for example `shasum -a 256 "/Library/Application Support/Kiro/managed-settings.json"`.
4. Optionally add file-integrity monitoring (auditd, osquery or EDR) on the policy path and alert in the SIEM.

## Protecting the repository and workspace

The workspace stays writable for the developer, so protection is layered: the admin policy denies catastrophic deletion and asks for other recursive deletion, `destructive-fs-guard.sh` blocks destructive commands issued by the agent, and backups (the CDK `BackupStack`, WorkSpaces snapshots, the Git server) make an accidental or malicious deletion recoverable.

## Threat model

| Stops (for a developer without administrator rights) | Does not stop |
|------------------------------------------------------|---------------|
| Changing, replacing or deleting the admin policy and the deployed hook scripts | A local administrator or root user (detected by drift checks, not prevented) |
| The agent changing its own permission or MCP files (Kiro hardcoded deny) | The developer editing the user-owned hook file or agent (reported by `--check`, restored on the next run) |
| Weakening the admin policy with user, workspace, agent or session rules, including `--trust-all-tools` | Commands that evade glob rules and hook patterns (quoting, encoding, scripts); covered by OS, IAM, egress and server-side controls |
| Deploying a policy with an `allow` rule or a tampered hook (refused by the scripts) | Reading the hook scripts and the policy (no secrecy) |
| Truncating the hook audit log (`chattr +a`; `sappnd` on macOS) | Renaming the user-owned audit directory, or redirecting the log with `KIRO_AUDIT_LOG`; Kiro prompt logging is the audit record |

## Testing

- **Dry-run tests (no root, no system changes, safe for CI):** `bash mdm/tests/test-lockdown.sh` and `bash mdm/tests/test-lockdown-macos.sh` validate the shipped policy JSON, `agent-hooks/SHA256SUMS`, the planned actions and the refusal of bad input (allow rules, malformed JSON, BOM, UTF-16, tampered hooks, wrong pins, hook commands outside the hook directory), and assert that nothing was written. `mdm/tests/test-lockdown-windows.ps1` does the same on Windows and also writes into a temporary folder (and an `HKCU` test key) to check the UTF-8-without-BOM output, `-StageSources`, `-DisableUpdates`, `-InstallUser`, `-RemoveSources` and the exit-code mapping of the Intune wrappers. CI runs the Linux dry run (`validate-governance`) and the Windows tests under Windows PowerShell 5.1 and PowerShell 7 (`validate-windows`); run the macOS test on macOS.
- **Root and administrator tests (opt-in, disposable hosts only):** `KIRO_MDM_ROOT_TESTS=1` (Linux, macOS) or `KIRO_MDM_ADMIN_TESTS=1` (Windows). They deploy into a temporary prefix, never the real system paths, use an existing unprivileged account, and never create or delete accounts. The integration test in `security-tests/aws-integration/` runs them on disposable EC2 instances, together with a real lockdown of the system paths and tamper, drift and restore checks.
- **Hook tests:** `bash agent-hooks/tests/run-tests.sh` (bash guards) and `powershell -ExecutionPolicy Bypass -File agent-hooks\tests\run-tests.ps1` (PowerShell guards). CI runs both (`validate-governance`, `validate-windows`) and verifies `agent-hooks/SHA256SUMS`.
- **Adversarial harness:** `security-tests/chaos/` (see [`chaos-pentest-evidence.md`](chaos-pentest-evidence.md)). `--hooks-only` is safe anywhere; the full run needs a throwaway Linux VM and `CHAOS_ALLOW_SYSTEM_CHANGES=1`.

Results for the current scripts (Linux as root and Windows Server 2022 as SYSTEM on disposable EC2 instances, 2026-11-19; no Kiro client on Windows, see the coverage table there): [`aws-integration-test-evidence.md`](aws-integration-test-evidence.md). Historical results: [`mdm-test-evidence.md`](mdm-test-evidence.md). They predate this version of the scripts; read the dated note at the top.

## MAS TRM mapping

| MAS TRM | Covered by |
|---------|------------|
| 9.1 / 9.2 Access control | Administrator-only policy file; developers without local admin rights; sign-in restriction |
| 11.1 Data security | Policy `fs_read` denies and PII hooks deployed to every client |
| 11.2 Network security | Policy network-tool denies; MCP registry in the console |
| 7.5 Change management | Policy changes only through the MDM job; validation before deployment; hash-pinned hooks |
| 12.2 Cyber event monitoring | Drift detection (`--check`, exit 3), file-integrity alerts, append-only hook log shipped to the SIEM |

## References

- [`agent-runtime-governance.md`](agent-runtime-governance.md): the layered model this deployment supports.
- [`../managed-settings/README.md`](../managed-settings/README.md): the policy, rule rationale and manual deployment commands.
- [`permissions-and-managed-settings.md`](permissions-and-managed-settings.md): reference snapshot of the official pages.
- [`intune-deployment.md`](intune-deployment.md): Windows runbook for Microsoft Intune (Win32 apps, Remediations, managed updates, pilot checklist).
- Official: https://kiro.dev/docs/enterprise/governance/permissions/, https://kiro.dev/docs/enterprise/governance/sign-in/, https://kiro.dev/docs/permissions/, https://kiro.dev/docs/custom-agents/, https://kiro.dev/docs/hooks/, https://kiro.dev/docs/hooks/types/, https://kiro.dev/docs/steering/, https://kiro.dev/docs/enterprise/managed-updates/, https://kiro.dev/changelog/ide/1-4-62/
- Microsoft Intune: https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/remediations, https://learn.microsoft.com/en-us/intune/intune-service/apps/apps-win32-add
