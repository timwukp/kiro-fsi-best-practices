# Kiro Managed Settings for Banking (Layer 4a)

Reference administrator policy, user permission template and MCP registry example for running Kiro 1.x (IDE 1.0+, CLI V3 engine) in a MAS-regulated software development environment.

> **Last verified:** 2026-10-08 against the official Kiro documentation (links at the end); the client versions were re-checked on 2026-11-19, and the Windows limits in [Measured limits on Windows](#measured-limits-on-windows-kiro-cli-350-2026-11-20) were measured with Kiro CLI 3.5.0 on 2026-11-19 and 2026-11-20. Kiro changes quickly: re-check the pages and test on a pilot machine before each fleet rollout.

## Contents

| File | Deploy to | Purpose |
|------|-----------|---------|
| [`managed-settings.banking.json`](managed-settings.banking.json) | OS-protected admin path (see [Deployment paths](#deployment-paths)) | **Option A** (sign-in through IAM Identity Center). Admin deny/ask rules plus a sign-in restriction to `idc` |
| [`managed-settings.option-b.json`](managed-settings.option-b.json) | Same path | **Option B** (direct external IdP federation). Same rules; sign-in restricted to `external_idp` |
| [`permissions.banking.yaml`](permissions.banking.yaml) | `~/.kiro/settings/permissions.yaml` (per user) | User-scope convenience template: silent approval for routine read-only, test, lint and synth commands and for writes to `src/`, `test/`, `tests/`, `docs/` |
| [`mcp-registry.example.json`](mcp-registry.example.json) | An HTTPS URL entered in the Kiro console (MCP Registry URL) | MCP allow list in the official registry format, with exact pinned versions |

Deploy only one `managed-settings.*.json` per machine, renamed to `managed-settings.json`. Replace every placeholder first: `d-xxxxxxxxxx`, `it.example.com`, `bank.example.com`, `idp.example.com`, `mcp.internal.example.com`, and the example MCP versions.

## Where this fits in the governance stack

| Layer | Control | Where |
|-------|---------|-------|
| 4a | Admin policy: `managed-settings.json` (deny/ask rules + sign-in restriction) | This folder, deployed by MDM |
| 4b | Organization settings: model allow list, MCP governance and registry, web tools, API keys off, Cloud Sessions off, prompt logging on | Kiro console > Settings |
| 4c | Workspace trust: leave unknown repositories untrusted | Each user's Kiro client |
| 4d | User and agent permissions (convenience, never weaker than 4a because deny wins) | `permissions.banking.yaml`, agent `permissions.rules` in [`../agent-hooks/`](../agent-hooks/) |
| 4e | Hooks: secret/PII scanning, git and destructive-command guards (defense in depth) | [`../agent-hooks/`](../agent-hooks/) |
| 4f | Audit: Kiro prompt logging and user activity reports to S3, CloudTrail for the AWS account | Kiro console, SIEM |

## Requirements and scope

- **Plan:** the administration scope (`managed-settings.json`) is an enterprise feature. Users must sign in with an enterprise identity for the organization settings in layer 4b to apply.
- **Client versions:** permission rules use the capability-based permission system of Kiro IDE 1.0+ and the Kiro CLI **V3 agent harness**. Kiro CLI 3.0.0 (2026-11-03) is a single `kiro-cli` binary with V3 as the default for interactive sessions and for headless runs with `--trust-all-tools`; CLI 2.x ran V3 with `kiro-cli --v3`. "V3" names the harness, not the 3.x version. Sign-in controls need **IDE 1.2+ and CLI 2.25.0+**; older clients ignore them. Recommended minimum for this policy: IDE 1.2 and CLI 2.25.0; all minimum versions are in the table in [`../kiro-docs/permissions-and-managed-settings.md`](../kiro-docs/permissions-and-managed-settings.md#1-applicability), and current versions on the [changelog](https://kiro.dev/changelog/). Use V3 sessions in the CLI: whether V2 sessions (`kiro-cli --v2`, and headless runs that name no harness, which start on V2) honour admin permission rules is not documented, so verify on a pilot machine, name the harness in scripts (`kiro-cli chat --v3 --no-interactive`) or save it (`kiro-cli settings chat.agentEngine v3`).
- **Surfaces:** one file applies to every Kiro surface on the machine; the IDE and the CLI read the same file. It does **not** apply to Kiro Web (Cloud Sessions). Keep Cloud Sessions turned off in the Kiro console.
- **Restart:** permission rules are read when Kiro starts. Restart the IDE and all CLI sessions after every change. Sign-in controls are read when a sign-in starts, so they take effect at the next sign-in.

## Deployment paths

| OS | Path (official) | Write access |
|----|-----------------|--------------|
| macOS | `/Library/Application Support/Kiro/managed-settings.json` | root only |
| Windows | `C:\ProgramData\Kiro\managed-settings.json` | Administrators and SYSTEM only |
| Linux | `/etc/kiro/managed-settings.json` | root only |

Users need read access to the file. They must not have local administrator or root rights, otherwise they can change or delete it (see [Client-side enforcement](#client-side-enforcement)).

**macOS**

```bash
sudo mkdir -p "/Library/Application Support/Kiro"
sudo install -m 0644 -o root -g wheel managed-settings/managed-settings.banking.json \
  "/Library/Application Support/Kiro/managed-settings.json"
```

**Linux**

```bash
sudo install -D -m 0644 -o root -g root managed-settings/managed-settings.banking.json \
  /etc/kiro/managed-settings.json
```

**Windows (elevated PowerShell)**

Kiro requires **UTF-8 without a byte order mark (BOM)**. It rejects UTF-16 files, which Windows PowerShell `Out-File` (and `>` redirection) writes by default, and files that start with a BOM. An invalid file blocks all agent tools (see [Failure behaviour](#failure-behaviour)). Write the file with .NET instead:

```powershell
$dir  = 'C:\ProgramData\Kiro'
$path = Join-Path $dir 'managed-settings.json'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$content = Get-Content -Raw -Encoding UTF8 -Path '.\managed-settings\managed-settings.banking.json'
[System.IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding $false))
# Administrators (S-1-5-32-544) and SYSTEM (S-1-5-18) full control; Users (S-1-5-32-545) read only
icacls $dir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX'
# Verify there is no BOM: the first byte must be 123 ('{'), not 239
[System.IO.File]::ReadAllBytes($path)[0]
```

**At scale:** deploy with MDM (Jamf, Kandji, Intune), Group Policy or SCCM, or bake the file into the WorkSpaces/VDI image. The scripts in [`../mdm/`](../mdm/) (`lockdown-macos.sh`, `lockdown-linux.sh`, `lockdown-windows.ps1`) deploy the policy to these official paths with administrator-only write access (the Option A file by default; see each script's usage text for selecting Option B or another source); see [`../kiro-docs/mdm-endpoint-enforcement.md`](../kiro-docs/mdm-endpoint-enforcement.md). Use the MDM's compliance reporting to detect devices where the file is missing or changed.

## What the bundled policy does

The JSON files cannot carry comments, so every rule is explained here. Rules are listed in file order. Shell patterns follow the official glob rules: `*` matches any sequence of characters (including spaces and `/`), and compound commands (`;`, `&&`, `||`, `|`) are split and checked one by one. Every shell pattern ends with `*`, so it behaves the same whether Kiro matches the whole command or a command prefix. Filesystem patterns: `*` stays in one path component, `**` crosses directories.

| # | Capability / effect | Patterns (summary) | Rationale | MAS TRM |
|---|---------------------|--------------------|-----------|---------|
| 1 | `signin_method` / deny | `match: ["*"]`, `exclude: ["idc"]` (Option B: `["external_idp"]`) | Only the corporate identity is offered; Builder ID, Google and GitHub sign-in are removed, and a denied method is refused before a token is issued. Settings prefill the Identity Center start URL and Region (`ap-southeast-1` here) and show an internal help link. This is a client guardrail, not access control: who may use Kiro is still decided by subscriptions in the IdP and Kiro console | 9.1 |
| 2 | `shell` / deny | `git push *--force*`, `git push -f*`, `git push * -f*`, `git push *+*`, `git push * :*`, `--mirror`, `--delete`, `-d`, `--prune`, `git reset *--hard*`, `git clean -*f*`, `git branch *-D*`, `git filter-branch*`, `git filter-repo*`, `git update-ref -d*`, `git reflog expire*` | Prevents the agent from rewriting or deleting shared history, deleting remote branches, or destroying uncommitted work. Source integrity and an auditable change trail | 6.3, 7.5 |
| 3 | `shell` / deny | `git commit *--no-verify*`, `git commit -n*`, `git push *--no-verify*`, `git config *core.hooksPath*` | Stops the agent from skipping or redirecting pre-commit and pre-push hooks (secret scanning, linting, tests) | 6.1, 6.3 |
| 4 | `shell` / deny | `rm -rf` and `rm -fr` of `/…`, `~…`, `$HOME…`, `..…`, `.git…`, `./.git…`; `mkfs*`; `dd *of=/dev/*` | Blocks catastrophic deletion outside the workspace or of the repository itself, and raw disk writes. Note that recursive force deletion of any absolute path is denied; use relative paths inside the workspace (rule 19 asks for those) | 11.3 |
| 5 | `shell` / deny | `sudo *`, `su *`, `doas *`, `chown *`, `chmod 777 *`, `chmod * 777 *` | No privilege escalation or ownership changes by the agent; no world-writable permissions | 9.2, 11.3 |
| 6 | `shell` / deny | `bash -c *`, `bash -lc *`, `sh -c *`, `zsh -c *`, `/bin/bash -c *`, `/bin/sh -c *`, `/bin/zsh -c *`, `eval *` | The agent already runs commands in a shell. Nested shells and `eval` hide the real command from glob rules and from reviewers | 11.3 |
| 7 | `shell` / deny | `curl *`, `wget *`, `nc *`, `ncat *`, `netcat *`, `telnet *`, `ftp *`, `scp *`, `sftp *` | Raw network transfer tools are the simplest exfiltration path for source code and customer data. Fetching documentation goes through `web_fetch` (rule 33), which prompts | 11.1, 11.2 |
| 8 | `shell` / deny | `aws iam *`, `aws organizations *`, `aws sts assume-role*`, `aws secretsmanager get-secret-value*`, `aws ssm get-parameter*--with-decryption*`, `aws kms decrypt*` | No identity changes, role chaining or secret retrieval by the agent, even when the developer's credentials would allow it | 9.2, 10.2, 11.1 |
| 9 | `shell` / deny | The rule 2 and rule 3 patterns for the `git.exe` token: `git.exe push *--force*`, `git.exe reset *--hard*`, `git.exe commit *--no-verify*`, … | **Windows.** Patterns are matched on the command text, so `git.exe push --force` does not match `git push *--force*`. Same effect as rules 2 and 3 | 6.3, 7.5, 6.1 |
| 10 | `shell` / deny | `powershell` / `pwsh` (and `.exe`) with `-Command` or `-EncodedCommand` anywhere on the line, or with the short forms `-c`, `-e`, `-ec`, `-enc` as the first argument or directly after the usual leading switches (`-NoProfile`, `-nop`, `-NoLogo`, `-NonInteractive`, `-ExecutionPolicy Bypass`, `-ep bypass`, `-WindowStyle Hidden`, `-w hidden`); `Invoke-Expression *`, `iex *`; `cmd /c *`, `cmd /k *` (also after `/d`, `/s`); `wsl *` | **Windows.** Sibling of rule 6: nested interpreters and string evaluation hide the real command from the per-command check, and an encoded command hides it completely. Running a script file (`powershell -File …`, with or without `-ExecutionPolicy Bypass`) is deliberately **not** matched, so MDM, test and hook commands keep working; the exception is a script parameter literally named `-Command` or `-EncodedCommand`. Other abbreviations and switch orders, and a command passed without any switch, are not matched (see the notes below). `iex` is also the Elixir shell, and `wsl` management commands such as `wsl --list` are denied as well | 11.3 |
| 11 | `shell` / deny | `Format-Volume*`, `Clear-Disk*`, `Initialize-Disk*`, `Remove-Partition*`, `diskpart*`, `format *:*`, `cipher /w*`, `vssadmin delete *`, `wbadmin delete *`, `bcdedit *` | **Windows.** Sibling of `mkfs*` / `dd` in rule 4: disk wiping, deletion of shadow copies and backups, and boot configuration changes | 11.3 |
| 12 | `shell` / deny | `runas *`; `Start-Process` / `saps` / `start` with `RunAs` (five common casings); `net localgroup … Administrators … /add`, `Add-LocalGroupMember *dministrators*` (the `*dministrators*` spelling covers both letter cases) | **Windows.** Sibling of rule 5: no elevation and no new local administrators. Listing the group (`net localgroup Administrators`) is not matched. Windows `sudo` is already covered by `sudo *` | 9.2, 11.3 |
| 13 | `shell` / deny | `Invoke-WebRequest*`, `iwr *`, `Invoke-RestMethod*`, `irm *`, `Start-BitsTransfer*`, `bitsadmin *`, `certutil *-urlcache*`, `certutil *-decode*`, `curl.exe *`, `wget.exe *`, `nc.exe *`, `ncat.exe *`, `telnet.exe *`, `ftp.exe *`, `tftp *`, `scp.exe *`, `sftp.exe *` | **Windows.** Sibling of rule 7: the PowerShell download cmdlets, the built-in download tools and the `.exe` names of the rule 7 tools. `certutil -hashfile` stays available. Local health checks go through the test framework or the developer | 11.1, 11.2 |
| 14 | `shell` / deny | The rule 8 patterns for `aws.exe`; AWS Tools for PowerShell: every `<Verb>-IAM*` and `<Verb>-ORG*` cmdlet for 21 verbs (`Get`, `New`, `Remove`, `Update`, `Set`, `Add`, `Write`, `Register`, `Edit`, `Enable`, …), `Get-SECSecretValue*`, `Invoke-KMSDecrypt*`, `Use-STSRole*`, `Get-SSMParameter*-WithDecryption*` | **Windows.** Sibling of rule 8 for the `aws.exe` token and the PowerShell AWS cmdlets (IAM, Organizations, secrets, KMS decrypt, assume-role) | 9.2, 10.2, 11.1 |
| 15 | `shell` / deny | `reg add`, `Set-ItemProperty` and `New-ItemProperty` on `…CurrentVersion…Run…` and on `Winlogon`; `Set-MpPreference` / `Add-MpPreference` that disable real-time protection or script scanning or add an exclusion path; `wevtutil cl *`, `Clear-EventLog*`, `Remove-EventLog*`; `netsh advfirewall set *state off*`, `Set-NetFirewallProfile *-Enabled False*` | **Windows only** (no POSIX sibling, and no file path for rule 30 to catch): start-up persistence in the registry, weakening Microsoft Defender, clearing event logs and turning the firewall off. The `CurrentVersion…Run` pattern also matches other value names under `CurrentVersion` that contain `Run` | 11.3, 12.2 |
| 16 | `shell` / ask | `git push*`, `git remote add*`, `git remote set-url*`, `gh *`, `ssh *` | Anything that leaves the workstation or changes where code is pushed needs a human decision. Branch protection on the Git server remains the authoritative control | 6.3, 9.3 |
| 17 | `shell` / ask | `npm publish*`, `npm unpublish*`, `yarn publish*`, `pnpm publish*`, `twine upload*`, `docker push*`, `mvn deploy*`, `cdk deploy*`, `cdk destroy*`, `npx cdk deploy*`, `npx cdk destroy*`, `terraform apply*`, `terraform destroy*` | Releases and infrastructure changes go through change management; the agent can prepare them but a human approves each one. In headless runs `ask` becomes `deny`, except in a run started with `--trust-all-tools`, which approves admin `ask` rules ([measured](#measured-limits-on-windows-kiro-cli-350-2026-11-20)) | 7.5, 7.6, 6.3 |
| 18 | `shell` / ask | `aws * create-*`, `aws * delete-*`, `aws * put-*`, `aws * update-*`, `aws * terminate-*`, `aws s3 cp*`, `aws s3 mv*`, `aws s3 rm*`, `aws s3 rb*`, `aws s3 sync*` | AWS write operations and S3 transfers (a data-movement path) prompt. Read-only AWS CLI calls are not covered by this rule and fall back to Kiro's default (ask) unless a user rule allows them | 7.5, 9.2, 11.1 |
| 19 | `shell` / ask | `rm -r*`, `rm -R*`, `rm -f*`, `rm *--recursive*`, `xargs *`, `find * -exec*`, `find * -delete*`, `python -c *`, `python3 -c *`, `node -e *`, `perl -e *`, `ruby -e *` | Bulk deletion and inline interpreter code are legitimate but can hide destructive or network actions; a human sees the full command first | 11.3, 6.3 |
| 20 | `shell` / ask | `git.exe push*`, `git.exe remote add*`, `git.exe remote set-url*`, `gh.exe *`, `ssh.exe *` | **Windows.** Sibling of rule 16 for the `.exe` names | 6.3, 9.3 |
| 21 | `shell` / ask | `Remove-Item` / `ri` / `rm` / `del` / `erase` / `rd` / `rmdir` with `-Recurse` or `-Force`; `del /s*`, `del /q*`, `del /f*`, `erase /s*`, `rd /s*`, `rmdir /s*`, also with the switch after the path (`rd build /s`); `forfiles *`; `python.exe -c *`, `py -c *`, `node.exe -e *`, `perl.exe -e *`, `ruby.exe -e *` | **Windows.** Sibling of rule 19. Recursive deletion of build output is routine, so it asks; the admin policy does not deny by drive path (agents use absolute paths for ordinary clean-up). Abbreviated switches (`-r`, `-fo`) are not matched. The `destructive-fs-guard.ps1` hook blocks drive roots, system folders, the profile and `.git`. A headless run with `--trust-all-tools` ran `Remove-Item <file> -Force` under this rule without a prompt ([measured](#measured-limits-on-windows-kiro-cli-350-2026-11-20)) | 11.3, 6.3 |
| 22 | `shell` / ask | The rule 17 patterns for `npm.cmd`, `yarn.cmd`, `pnpm.cmd`, `npx.cmd`, `cdk.cmd`, `mvn.cmd`, `docker.exe`, `twine.exe`, `terraform.exe`; `nuget push*`, `dotnet nuget push*`, `Publish-Module*`, `Publish-Script*`, `Publish-PSResource*` | **Windows.** Sibling of rule 17 for the Windows launcher names, plus NuGet and the PowerShell Gallery. `dotnet publish` (a local build step) is not matched | 7.5, 7.6, 6.3 |
| 23 | `shell` / ask | The rule 18 patterns for `aws.exe`; `Write-S3Object*`, `Copy-S3Object*`, `Remove-S3Object*`, `Remove-S3Bucket*` | **Windows.** Sibling of rule 18 for `aws.exe` and the PowerShell S3 cmdlets | 7.5, 9.2, 11.1 |
| 24 | `shell` / ask | `schtasks /create*`, `/change*`, `/delete*`; `Register-ScheduledTask*`, `Set-ScheduledTask*`, `Unregister-ScheduledTask*`; `sc.exe` / `sc` `create`, `config`, `delete`, `stop`; `net stop *`; `New-Service*`, `Set-Service*`, `Stop-Service*`, `Remove-Service*`; `reg add *`, `reg delete *`, `reg import *`; `icacls * /grant*` and its other changing switches; `takeown *`; `Set-Acl*` | **Windows only.** Scheduled tasks, services, registry writes and ACL or ownership changes are sometimes legitimate (installers, local services), so they need a human decision. Read-only forms (`reg query`, `sc.exe query`, `icacls <path>`) are not matched | 9.2, 11.3, 7.5 |
| 25 | `shell` / ask | `Get-Content` / `gc` / `type` / `cat` of `*.aws*credentials*`, `*id_rsa*`, `*id_ed25519*`, `*.pem*`, `*.pfx*`; `cmdkey /list*`, `cmdkey /add*`, `cmdkey /generic*`, `vaultcmd /list*`, `certutil *-store*` | **Windows** (the `cat` patterns also apply on macOS and Linux). The shell route around rules 27 and 28: reading credential files with a command, and listing the Windows Credential Manager or certificate stores. | 10.2, 11.1 |
| 26 | `fs_read` / deny | `**/.env`, `**/.env.*` (excluding `.env.example`, `.env.sample`, `.env.template`) | Environment files usually hold credentials and connection strings; keep them out of prompts. A single `fs_read` deny blocks all read tools (read, glob, grep, code) for the path | 11.1 |
| 27 | `fs_read` / deny | `**/*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `**/id_rsa*`, `id_ecdsa*`, `id_ed25519*`, `secrets/**`, `**/secrets/**`, `~/.ssh/**`, `~/.aws/credentials`, `~/.aws/sso/cache/**`, `~/.aws/cli/cache/**`, `~/.kube/config`, `~/.docker/config.json`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.config/gh/hosts.yml` | Private keys, keystores and local credential or token caches must never be read into a prompt (prompts are stored and processed in the Kiro profile region) | 10.2, 11.1, 9.2 |
| 28 | `fs_read` / deny | `**/*.ppk`; under `**/Users/*/`: `.ssh/**`, `.aws/credentials` and caches, `.kube/config`, `.docker/config.json`, `.netrc`, `_netrc`, `.git-credentials`, `.npmrc`, `.azure/**`; `~/.azure/**`; `**/AppData/Roaming/GitHub CLI/hosts.yml`, `**/AppData/…/Microsoft/Credentials/**`, `Protect/**`, `Vault/**`; `**/NTUSER.DAT`; the Chrome `Login Data` file | **Windows.** Sibling of rule 27, written against the Windows profile path because Kiro does not document whether `~` expands to `%USERPROFILE%`; adds PuTTY keys, Credential Manager and DPAPI stores, Azure CLI tokens in the home folder on every OS (a project-level `.azure` folder is not matched), the user registry hive and the browser password database | 10.2, 11.1, 9.2 |
| 29 | `fs_write` / deny | Key files (`*.pem`, `*.key`, `*.p12`, `*.pfx`), `~/.ssh/**`, `~/.aws/**`, shell start-up files (`~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`, `~/.zprofile`, `~/.zshenv`), `~/.gitconfig`, `~/.npmrc`, `~/Library/LaunchAgents/**`, `~/.config/autostart/**` | Prevents credential tampering and persistence (start-up files, launch agents, global git config such as `core.hooksPath`) outside the workspace | 11.3, 9.2 |
| 30 | `fs_write` / deny | `**/*.ppk`; under `**/Users/*/`: `.ssh/**`, `.aws/**`, `.gitconfig`, `.npmrc`, `_netrc`, `.git-credentials`; the Startup folders (`**/Start Menu/Programs/Startup/**`, both spellings); PowerShell profile scripts (`**/Documents/WindowsPowerShell/*profile.ps1`, `**/Documents/PowerShell/*profile.ps1`, and the all-users locations) | **Windows.** Sibling of rule 29: the Startup folders and PowerShell profiles are the Windows equivalents of LaunchAgents and `.bashrc`. The profile patterns are anchored to the profile folders, so a `profile.ps1` inside a repository is not caught | 11.3, 9.2 |
| 31 | `fs_write` / ask | `**/.github/workflows/**`, `**/.github/actions/**`, `**/.gitlab-ci.yml`, `**/Jenkinsfile`, `**/buildspec*.yml`, `**/azure-pipelines*.yml`, `**/CODEOWNERS`, `**/.pre-commit-config.yaml` | CI/CD definitions and review-ownership files control what runs with pipeline credentials and who must approve; changes need explicit human approval and peer review | 6.3, 7.5 |
| 32 | `fs_write` / ask | `.kiro/steering/**`, `.kiro/skills/**`, `~/.kiro/steering/**`, `~/.kiro/skills/**`, `**/AGENTS.md` | Steering, skills and `AGENTS.md` change how the agent behaves in later sessions; a prompt-injected agent must not be able to rewrite its own instructions silently. (Kiro already asks for agents, hooks, workflows and powers directories.) | 7.5, 6.3 |
| 33 | `web_fetch` / ask | all URLs | Every fetch is visible to the developer; fetched pages can carry prompt-injection content and URLs can carry data out. If web tools are disabled in the Kiro console, this rule is redundant but harmless | 11.1, 11.2 |
| 34 | `web_search` / ask | all queries | Search queries can leak code or customer context to an external search provider | 11.1 |

### Windows rules (9–15, 20–25, 28, 30)

Rules marked **Windows** were added on 2026-11-19. On Windows the `shell` capability covers PowerShell (`execute_pwsh`), and the POSIX-shaped patterns do not match PowerShell cmdlets, `cmd.exe` commands or `.exe` / `.cmd` program names. The same file is deployed to every OS. Most Windows patterns never match on macOS or Linux; the exceptions are patterns for commands that exist there too, such as `cat` in rule 25 and `rm *-Force*` in rule 21.

How they are written, and why:

- **Anchored on the command name.** Every shell pattern starts with the command name, never with `*`, so a commit message or a search string that mentions a command is not matched.
- **No backslashes.** Kiro does not document what a backslash means in a pattern, and an unescaped backslash is invalid JSON, which would make Kiro reject the whole file. Paths use `/` and `**/`.
- **Two spellings, matched case-sensitively.** Cmdlets are listed in their canonical and lowercase forms. Kiro does not document whether shell matching is case-sensitive; it is (measured with Kiro CLI 3.5.0 on Windows Server 2022 and Windows 11, 2026-11-19 and 2026-11-20): `INVOKE-WEBREQUEST` in capitals ran past rule 13, although PowerShell runs every casing as the same cmdlet. No list of casings is complete; see [Measured limits on Windows](#measured-limits-on-windows-kiro-cli-350-2026-11-20).
- **Aliases are listed, not resolved.** Kiro does not document alias or parameter-abbreviation handling, so common aliases (`ri`, `iwr`, `irm`, `iex`, `saps`) are listed; abbreviated parameters (for example `-r` for `-Recurse`) are not all covered.
- **Nested PowerShell is covered only in its usual spellings.** PowerShell accepts any unambiguous prefix of `-Command` and `-EncodedCommand`, in any letter case, anywhere before the command, and also a command with no switch at all. Rule 10 lists the long names anywhere on the line and the short forms `-c`, `-e`, `-ec`, `-enc` in first position or after the usual leading switches; other spellings and switch orders are not matched. The PowerShell hook guards follow these wrappers at token level and are the second layer here. Matching `powershell *` broadly would also stop `powershell -File`, which MDM, CI and the hook commands need.
- **Routine work is not matched:** `powershell -File <script>` with or without `-ExecutionPolicy Bypass`, `bash <script>`, `Start-Process` without elevation, `reg query`, `certutil -hashfile`, `dotnet publish`, and deletion without `-Recurse` / `-Force`.
- **Same effect as the POSIX sibling** wherever one exists.

Unverified, check on a Windows pilot device before fleet rollout: alias and abbreviation handling; whether `~` in filesystem patterns expands to `%USERPROFILE%` and whether `\` paths are normalised to `/`; how `cmd.exe` command lines are split (Kiro documents only that commands for `cmd.exe` "still ask for approval"); and that every `ask` rule behaves acceptably in headless runs, where `ask` is treated as `deny` unless the run is started with `--trust-all-tools`. Case sensitivity and the effect of `--trust-all-tools` on admin `ask` rules were measured in Kiro CLI: see the next section. Kiro itself blocks PowerShell commands it cannot parse (IDE 1.4.51+, CLI V3). The PowerShell hook guards in [`../agent-hooks/windows/`](../agent-hooks/README.md) match case-insensitively and are the second layer for destructive deletes, git and secrets.

Optional stricter rules (not enabled by default): `{"capability": "mcp", "effect": "ask"}` forces a prompt for every MCP tool call, even when users or `autoApprove` allow it (Kiro's governance page; in headless Kiro CLI 3.5.0 runs `--trust-all-tools` approved a shell command under an admin `ask`, finding F2 in the [next section](#measured-limits-on-windows-kiro-cli-350-2026-11-20); not measured for MCP; use `deny` where it must hold); `{"capability": "web_fetch", "exclude": ["docs.aws.amazon.com", "kiro.dev"], "effect": "deny"}` turns rule 33 into a domain allow list (excluded domains fall through to the user's own rules).

### Measured limits on Windows (Kiro CLI 3.5.0, 2026-11-20)

Measured with Kiro CLI 3.5.0 in headless V3 runs (`kiro-cli chat --v3 --no-interactive`) as a standard user, with this policy deployed (34 rules) and the hook guards off unless stated: on Windows Server 2022 (two end-to-end runs plus a follow-up run with rule 21 as `deny`, 2026-11-19) and on Windows 11 Enterprise Evaluation 26H2, build 26300.9457, in a Hyper-V VM (runs 2 and 3, 2026-11-20; run 3 ended with 31 pass, 0 fail). Each check asked the agent to run one exact command. A workspace hook recorded every tool call, so "ran" means the recorded call had that exact text and its side effect exists. One model run per case. Not tested: Kiro IDE, casings other than all capitals, and a real Intune tenant. Both findings are reported to Kiro on GitHub (kirodotdev/Kiro); issue #43 tracks the open checks.

| Finding | Measured | Consequence |
|---------|----------|-------------|
| **F1:** shell rules match case-sensitively; PowerShell does not | Rule 13 refused `Invoke-WebRequest`, lowercase `invoke-webrequest` and `irm`. `INVOKE-WEBREQUEST https://example.com/ -OutFile <file>` (all capitals) ran and fetched the page on both platforms, also with the guard hooks on (Windows 11). With the guards on, `REMOVE-ITEM .git -RECURSE -FORCE` was blocked by `destructive-fs-guard.ps1`, which matches case-insensitively | A casing the policy does not list runs, and no admin can list every casing. The model chose nothing here (the prompt gave the casing); a model or a prompt injection can produce such a casing too (not measured). It needs no administrative access |
| **F2:** `--trust-all-tools` approves commands under an admin `ask` rule | `Remove-Item <file> -Force` (rule 21, `ask`) with `--trust-all-tools`: ran, file deleted, nobody asked (both platforms). Without the flag: refused. Rule 21 changed to `deny`, with the flag: the canonical spelling was refused (Windows Server 2022 follow-up run, Windows 11 run 3), but `REMOVE-ITEM <file> -FORCE` in capitals ran and deleted the file (Windows 11 run 3) | An admin `ask` does not hold against a flag that any user can add. A `deny` holds, but only for the casings it lists (F1) |

Kiro's pages disagree on F2: the permission policies page says an admin `ask` forces a prompt even over a user `allow`, while the permissions page says `--trust-all-tools` and `/tools trust-all` trust every tool action the rules do not deny. The measured behaviour follows the second page. `/tools trust-all` in an interactive session and `--trust-tools=<tool>` were not measured; treat them like `--trust-all-tools`.

Design rules for Windows devices:

- **Deny, not ask, for anything that must never run.** An admin `ask` is a prompt for interactive work, not a control for unattended runs.
- **Forbid `--trust-all-tools` and `--trust-tools` in unattended and agent configurations:** pipelines, scheduled tasks, scripts and agent wrappers. Check for them in code review or with a CI check. A developer can still add the flag by hand, so this keeps automation honest; it does not enforce anything on the device.
- **Windows shell deny rules are a guardrail, not a boundary.** They stop the usual spellings. Listing more casings does not close F1.
- **Egress needs a network control.** No guard hook covers network commands (`INVOKE-WEBREQUEST` still ran with the guards on), so control egress at the network layer: a proxy or a DNS Firewall allowlist (see the `cdk/` network stack).
- **Guard hooks are a backstop.** The PowerShell guards in [`../agent-hooks/windows/`](../agent-hooks/README.md) match case-insensitively and back up the policy only for what they cover (destructive deletes, git and secrets). The hook file in the user's profile is user-owned, so MDM must restore it.

## How admin rules combine with other permission sources

- **Deny-overrides.** Kiro evaluates the Kiro (hardcoded), administration, user, workspace, agent and session scopes together. The result is `deny > ask > allow`, regardless of scope (except an admin `ask` under `--trust-all-tools` in headless runs, F2 below). Admin rules may only use `deny` or `ask`: they restrict but never grant.
- **Session overrides do not weaken an admin `deny`; `--trust-all-tools` does weaken an admin `ask`.** `kiro-cli --trust-all-tools`, `/tools trust-all` (CLI V3), "Always allow … This session", policy presets requested by ACP clients, user `permissions.yaml` and agent `permissions` rules are all allow sources. They remove Kiro's default prompts, and an admin `deny` still blocks (measured with `--trust-all-tools`). Kiro's governance page says an admin `ask` still prompts, but in headless runs of Kiro CLI 3.5.0 on Windows, `--trust-all-tools` approved a command under an admin `ask` without asking anyone (finding F2, [measured](#measured-limits-on-windows-kiro-cli-350-2026-11-20)). Denials show the rule source as "administration".
- **Headless runs** (no interactive client) treat every `ask` as `deny`, unless the run is started with `--trust-all-tools`, which approves it (F2). A pipeline that runs Kiro headless without the flag therefore cannot push, publish, deploy or fetch under this policy. That is intended; keep `--trust-all-tools` and `--trust-tools` out of pipeline and agent configurations, and use `deny` for anything that must never run.
- **Kiro hardcoded invariants** (cannot be configured): the agent is always denied writes to `~/.kiro/settings/`, `.kiro/settings/`, `~/.kiro/workspace-roots/`, an installed Power's `mcp.json` and Kiro's state stores, so it cannot edit its own permission or MCP files. Writes to `.git/**`, `.vscode/**`, `**/*.code-workspace`, `.kiroignore` and the agents, hooks, workflows and powers directories under `.kiro` and `~/.kiro` always ask; no allow rule from any scope removes that prompt.
- **IDE autonomy.** `kiroAgent.agentAutonomy` (Autopilot or Supervised) decides whether the IDE proceeds or prompts; the permission rules apply after that decision. Supervised mode does not replace admin rules, and Autopilot does not bypass them.

## Failure behaviour

| Part of the file | Behaviour on error | Examples |
|------------------|--------------------|----------|
| Permission rules | **Fails closed.** The whole file is rejected and **all tool calls are denied** until it is fixed or removed | Malformed JSON; any rule with `"effect": "allow"`; unknown fields (for example `effct`); a BOM or UTF-16 encoding |
| Permission rules: unknown capability | That rule is skipped with a warning; the other rules load | A capability name added in a newer Kiro version |
| Sign-in method restriction (`signin_method`) | **Fails open.** The restriction is dropped and every sign-in method is offered (a warning names the cause) | Invalid or unreadable file; effect other than `deny`; unrecognized name in `exclude`; rules that deny every method; more than 16 entries in a rule |
| Sign-in portal (`auth_portal_url`, or the `AuthPortalUrl` OS policy; Kiro CLI 3.5.0+) | **Does not fail open to the user's own portal settings, and does not block sign-in:** an invalid value, or a file that cannot be read or parsed, makes `kiro-cli login` use a valid `AuthPortalUrl` policy or else the default portal `https://app.kiro.dev` | Not `https`; credentials, a query or a fragment in the URL; over 2,048 bytes; unreadable file |
| Other settings keys | Invalid value dropped on its own; unknown keys ignored | Non-https URL; value over 2,048 bytes of UTF-8 |

An invalid file therefore removes the sign-in restriction **and** blocks the agent's tools at the same time. Validate before every deployment and monitor for the warning.

## Client-side enforcement

Kiro documents both permission policies and sign-in controls as **enforced by the installed client**: they "can be circumvented by users, e.g., via administrative access to their local machine". Treat them as strong guardrails, not as a boundary. On Windows, shell rules are also matched case-sensitively, so a casing the policy does not list runs without any administrative access ([measured](#measured-limits-on-windows-kiro-cli-350-2026-11-20)):

- Developers work as standard users (no local admin or root), ideally on a managed VDI such as Amazon WorkSpaces.
- MDM keeps the file in place and reports drift; file-integrity monitoring alerts on changes.
- The real boundaries stay outside Kiro: Git server branch protection and required reviews, least-privilege IAM roles for developers, egress filtering (see `cdk/` network stack), and subscription management in the IdP and Kiro console.
- Kiro Web (Cloud Sessions) and devices without the file are not covered. Keep Cloud Sessions off.

## Workspace trust

Kiro treats a workspace as untrusted until the user trusts it, and stores the decision outside the repository, so a repository cannot trust itself. While a workspace is untrusted Kiro does not load its custom agents, steering, MCP configuration, skills or workflow files; asks before every shell command (even if a rule allows it), before every MCP tool call and Power activation (even with `autoApprove`); and refuses writes to `~/.kiro/memories/` and the session store. Admin rules still apply in untrusted workspaces.

Guidance: trust only repositories from your organization's Git server after review; open third-party code, pull requests from forks and downloaded samples untrusted; do not grant a blanket `fs_write` allow (no `match`) in user `permissions.yaml`, because that is the one rule that lifts the untrusted-only `.kiro` write prompts.

## Glob limitations

Glob rules match the command text, not its effect. They stop the obvious forms and make intent explicit, but they can be evaded, for example:

- quoting or escaping: `r""m -rf /`, `\rm -rf /`, `command rm -rf /`, `env rm -rf /`;
- options before the subcommand: `git -c color.ui=false push --force`, or combined flags such as `git push -uf`;
- indirection not listed here: shell variables (`X=rm; $X -rf /`), aliases, `npm run <script>` or `make` targets that run the denied command, a script file written by the agent and then executed.
- on Windows: a letter case (measured: matching is case-sensitive, PowerShell is not), spelling, alias or abbreviated parameter that is not listed, .NET method calls instead of cmdlets, a value held in a variable, or a script file written and then run with `powershell -File`.

They can also match too much: a command whose text only mentions a denied form is matched as well, for example `git commit -m "docs: explain --no-verify"` (reword the message).

Defense in depth therefore continues after this file: PreToolUse hooks in [`../agent-hooks/`](../agent-hooks/) inspect the full tool input (and block with exit code 2, including on internal errors), and OS/VDI controls, server-side branch protection, IAM and egress filtering enforce the outcome regardless of how a command is written.

## Validation

Run from the repository root before every change and in CI:

```bash
# 1. Valid JSON (all files)
jq -e . managed-settings/*.json > /dev/null

# 2. Admin rules use only deny or ask (an allow rule makes Kiro reject the whole file)
jq -e '[.rules[].effect] | all(. == "deny" or . == "ask")' managed-settings/managed-settings.*.json

# 3. Only the documented keys (unknown fields make Kiro reject the whole file)
jq -e '(keys - ["rules","settings"]) == [] and ([.rules[] | keys[]] - ["capability","match","exclude","effect"]) == []' \
  managed-settings/managed-settings.*.json

# 4. Sign-in rule: effect deny, at most 16 names, https URLs only
jq -e '[.rules[] | select(.capability == "signin_method") | (.effect == "deny" and ((.match // []) + (.exclude // []) | length) <= 16)] | all' \
  managed-settings/managed-settings.*.json
jq -e '[(.settings // {}) | to_entries[] | select(.key | endswith("_url")) | .value | startswith("https://")] | all' \
  managed-settings/managed-settings.*.json

# 5. No UTF-8 BOM (first byte must be "{")
for f in managed-settings/*.json; do [ "$(head -c 1 "$f")" = "{" ] || echo "BOM or bad start: $f"; done

# 6. User template parses as YAML
ruby -ryaml -e 'YAML.load_file("managed-settings/permissions.banking.yaml")'

# 7. Registry: exact versions only (no ^, ~, >=, x or * ranges)
jq -e '[.servers[].server.version | test("^[0-9]+\\.[0-9]+\\.[0-9]+$")] | all' managed-settings/mcp-registry.example.json

# 8. Policy regression tests: both files carry the same rules apart from rule 1, pattern shape (no backslash,
#    shell patterns start with the command and end with *), the rule table above matches the file order,
#    and tests/shell-vectors.tsv gives the expected effect (routine commands must not match)
bash managed-settings/tests/test-policy.sh
```

Then verify on a pilot machine: restart Kiro, confirm that no policy warning appears, ask the agent to run a denied command (for example `git push --force`) and confirm the denial names "administration", sign out and confirm that only the permitted sign-in method is offered with the start URL and Region prefilled.

## User permissions template

[`permissions.banking.yaml`](permissions.banking.yaml) is the user scope (`~/.kiro/settings/permissions.yaml`). Users copy it themselves, or MDM places it in each profile (the agent itself can never write `~/.kiro/settings/`). Its allow rules only remove prompts for low-risk local work; every admin deny/ask above still applies. Workspace-scope rules are created through the "Always allow … This workspace" picker and stored per user outside the repository in `~/.kiro/workspace-roots/<hash>/permissions.yaml`, so a cloned repository cannot inject rules. In the CLI, convert legacy agent `toolsSettings` with `kiro-cli agent migrate` (or `/upgrade-agent`); `autoAllowReadonly` and `denyByDefault` have no equivalent in the new model.

## MCP registry example

[`mcp-registry.example.json`](mcp-registry.example.json) follows the registry file format on the official MCP governance page (a subset of the MCP registry standard v0.1 server schema) and validates against the JSON schema published there.

- **Entries:** `aws-documentation` (local stdio server from PyPI, run with `uvx`) and `bank-internal-standards` (remote `streamable-http` server). Both versions (`1.2.3`, `1.0.0`) are **examples**: replace them with the exact versions your third-party review approved. Version ranges (`^1.2.3`, `~1.2.3`, `>=1.2.3`, `1.x`, `1.*`) are rejected.
- **Hosting:** serve the file over HTTPS with a certificate from a trusted CA (self-signed certificates are rejected). The URL may be private to the corporate network. Enter it in Kiro console > Settings > Shared settings > MCP Registry URL, with MCP turned on.
- **Behaviour:** Kiro fetches the registry at startup and every 24 hours. A locally installed server that is no longer listed is terminated; a server with a different version is relaunched at the registry version. Servers not in the registry are hidden, including entries in the user's own `mcp.json`. Users can only add environment variables, HTTP headers, a timeout, the server scope and tool trust on top of a registry entry.
- **Who it applies to:** IAM Identity Center and API-key users, in the IDE and CLI. It does not apply to Builder ID or social sign-in users, or to Kiro Web. If the client cannot reach the governance API, MCP **fails closed** (MCP disabled until it reconnects). Like the permission policy, it is client-enforced.
- **Runners:** clients need `npx` (npm), `uvx` (PyPI) or `docker` (OCI) pre-installed. If you mirror packages internally, set `registryBaseUrl` to the mirror and test how your Kiro version passes it to the runner.
- **Docs conflict:** the user-facing registry page refers to `~/.kiro/mcp.json` and `.kiro/mcp.json`, while the MCP configuration page documents `~/.kiro/settings/mcp.json` and `.kiro/settings/mcp.json`. This repository follows the configuration page. `C:\ProgramData\Kiro\mcp.json` is not a Kiro location.

See [`../kiro-docs/mcp-security.md`](../kiro-docs/mcp-security.md) and [`../kiro-docs/permissions-and-managed-settings.md`](../kiro-docs/permissions-and-managed-settings.md) for the reference snapshots.

## Official references (verified 2026-10-08)

- Permissions: https://kiro.dev/docs/permissions/
- Permission policies (managed-settings.json): https://kiro.dev/docs/enterprise/governance/permissions/
- Sign-in controls: https://kiro.dev/docs/enterprise/governance/sign-in/
- MCP governance and registry file format: https://kiro.dev/docs/enterprise/governance/mcp/
- MCP registry (user view): https://kiro.dev/docs/mcp/registry/
- MCP configuration: https://kiro.dev/docs/mcp/configuration/
- Enterprise governance overview: https://kiro.dev/docs/enterprise/governance/
- Managed updates: https://kiro.dev/docs/enterprise/managed-updates/
