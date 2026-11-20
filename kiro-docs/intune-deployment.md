# Windows Deployment with Microsoft Intune

Runbook for deploying Kiro, the admin policy (`managed-settings.json`) and the optional hooks to Windows devices with Microsoft Intune, and for detecting and repairing drift. It complements [`mdm-endpoint-enforcement.md`](mdm-endpoint-enforcement.md), which covers every MDM and OS.

> **Last verified:** 2026-11-19 against the official documentation: Kiro [managed updates](https://kiro.dev/docs/enterprise/managed-updates/) (page updated 2026-10-29), the [IDE 1.4.62 changelog](https://kiro.dev/changelog/ide/1-4-62/), [IDE troubleshooting](https://kiro.dev/docs/ide/troubleshooting/), [hooks](https://kiro.dev/docs/hooks/), [hook types](https://kiro.dev/docs/hooks/types/) and [steering](https://kiro.dev/docs/steering/); Microsoft Learn [Remediations](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/remediations), [Win32 app management](https://learn.microsoft.com/en-us/intune/intune-service/apps/apps-win32-add) and [registry keys affected by WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys). Also Kiro [sign-in controls](https://kiro.dev/docs/enterprise/governance/sign-in/) and [installation](https://kiro.dev/docs/getting-started/installation/), and Microsoft Learn [platform scripts](https://learn.microsoft.com/en-us/intune/intune-service/apps/powershell-scripts) and [Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature). On 2026-11-20 also Kiro [permissions](https://kiro.dev/docs/permissions/) and [permission policies](https://kiro.dev/docs/enterprise/governance/permissions/) for the Kiro CLI notes. Items marked *(verify)* are neither documented by Kiro or Microsoft nor measured in the lab; test them on a pilot device.
>
> **What was tested, and what was not.** The scripts, the Intune wrappers and the PowerShell hook guards were run on **Windows Server 2022 as SYSTEM**, from 64-bit and 32-bit PowerShell ([evidence](aws-integration-test-evidence.md)). On the same runner, on 2026-11-19, the Kiro IDE 1.4.236 system-wide installer was run as SYSTEM in phase WC, and the installer started like the Intune agent (T1 to T6) and the per-user build as SYSTEM in separate runs; Kiro CLI 3.5.0 was installed as SYSTEM and run headless by a standard user (phase WK, two end-to-end runs plus a follow-up run). On 2026-11-19 and 2026-11-20 the Windows 11 client kit W2 ([`../security-tests/windows-client/`](../security-tests/windows-client/README.md)) was run on a **Windows 11 Enterprise Evaluation 26H2** test VM (build 26300.9457, Hyper-V on an EC2 host with nested virtualization): the system-wide installer as an elevated administrator, the policy and the wrappers in 64-bit and 32-bit SYSTEM contexts, **Kiro IDE 1.4.236 (system setup) used by a standard user at the console** (policy enforcement, sign-in restriction, `UpdateMode=none`, an invalid policy file, global hooks and steering), and Kiro CLI 3.5.0 in three runs of phase WK. Measured statements on this page name the platform, the version and the date. **Not tested:** a real Intune tenant (its execution contexts were emulated with SYSTEM tasks and 32-bit `cmd.exe`), a licensed or physical Windows 10/11 device, ARM64, the per-user build installed by a user, a user profile created after the deployment in Kiro IDE, and the case check of finding F1 in Kiro IDE ([Kiro CLI on Windows](#kiro-cli-on-windows)). Each agent check ran once per run (one model run per case). Issue #43 stays open for these items.

## The Intune objects

| # | Intune object | Runs | Purpose |
|---|---------------|------|---------|
| 1 | Win32 app **Kiro IDE (system-wide)** | Kiro system-wide installer, System context | Installs Kiro for every user of the device ([section 1](#1-kiro-ide-per-user-vs-system-wide-installer)) |
| 2 | Win32 app **Kiro policy** | `mdm\lockdown-windows.ps1 -StageSources`, System context | Deploys `managed-settings.json` and the optional controls, and stages the sources the on-device checks need ([section 3](#3-the-kiro-policy-win32-app)) |
| 3 | Remediations package **Kiro policy drift** | `mdm\intune\Detect-KiroPolicy.ps1` / `Remediate-KiroPolicy.ps1` | Detects and repairs drift on a schedule ([section 4](#4-remediations-drift-detection-and-repair)) |
| 4 | Win32 app **Kiro CLI** (optional), with a Win32 app **Microsoft Visual C++ 2015-2022 Redistributable (x64)** as its dependency | Kiro CLI MSI with `INSTALLFOLDER`, System context | Installs Kiro CLI for every user of the device ([Kiro CLI on Windows](#kiro-cli-on-windows)) |

Without the Remediations licence, object 2 uses `mdm\intune\Detect-KiroPolicy-Win32.ps1` as its detection script and repairs drift by reinstalling ([section 4](#without-the-remediations-licence)).

### Why `-Check` is not used directly

Earlier versions of this repository named `lockdown-windows.ps1 -Check` as the Intune detection script. That does not work:

| Mechanism | "Healthy" | "Issue" or "not installed" | Arguments |
|-----------|-----------|----------------------------|-----------|
| Remediations detection script | Any exit code **other than 1** | Exit **1** only; only then does the remediation script run | None: one uploaded `.ps1` |
| Win32 app custom detection script | Exit **0** and output on **STDOUT** and nothing on **STDERR** | Anything else | None: one uploaded `.ps1` |
| `lockdown-windows.ps1 -Check` | Exit 0 | Exit 3 (drift), 2 (policy source missing or refused), 1 (error) | `-Check` plus the deployment options |

So a device with drift (exit 3) or without the policy source on disk (exit 2) was reported as "without issues" and never repaired, and the script could not receive `-Check` anyway. The fix has two parts: the Win32 app **stages** the sources on the device, and three **wrappers** call the staged script and translate its exit code:

| Wrapper | For | Exit codes |
|---------|-----|------------|
| `Detect-KiroPolicy.ps1` | Remediations detection | 0 → 0; 3, 2, 1, any other code, or no staged script → **1**. One summary line (Remediations keeps at most 2,048 characters) |
| `Remediate-KiroPolicy.ps1` | Remediations remediation | Runs the staged deployment; 0 on success, 1 otherwise |
| `Detect-KiroPolicy-Win32.ps1` | Win32 app detection | Writes to STDOUT and exits 0 **only** when `-Check` passes; otherwise exits 1 with no output; never writes to STDERR |

Each wrapper appends the full output of the staged script to `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\KiroPolicy-*.log` when that folder exists (at 512 KB the file is kept as `<name>.1` and a new one is started), so the record of a drift survives the next clean run. The mapping is tested by `mdm\tests\test-lockdown-windows.ps1` (CI job `validate-windows`).

## 1. Kiro IDE: per-user vs system-wide installer

Kiro IDE **1.4.62** added Windows system-wide installers for x64 and ARM64 ([changelog](https://kiro.dev/changelog/ide/1-4-62/)). The managed-updates page lists three Windows variants: `-system` (the default), `-user` and `-archive` (portable).

**Use the system-wide installer for MDM.** The per-user build deployed in System context installs into the SYSTEM account's profile, so users do not see Kiro and detection fails. Measured on 2026-11-19 with `kiro-ide-1.4.236-stable-win32-x64.exe` (the per-user build, same signer as the system-wide build) on Windows Server 2022, started as SYSTEM from 32-bit `cmd.exe` with `/VERYSILENT /SP- /SUPPRESSMSGBOXES /NORESTART /LOG=...`:

- Exit code 0 after 164 seconds; the log says "User privileges: Administrative".
- App folder `C:\Windows\system32\config\systemprofile\AppData\Local\Programs\Kiro\`; uninstaller under `C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Programs\Kiro\` (the 32-bit installer's System32 path is redirected).
- Uninstall key `{A2CA08B5-C756-463E-B13D-F051F4F11F0B}_is1`, DisplayName "Kiro (User)", under `HKU\S-1-5-18` (SYSTEM's own HKCU); nothing under HKLM in either registry view.
- Its `bin` folder is added to SYSTEM's user PATH only; no Start Menu shortcut for any user; nine `Kiro.exe` processes left running as SYSTEM in session 0.
- A detection rule on `C:\Program Files\Kiro\Kiro.exe` or on an HKLM Uninstall key finds nothing: "not detected".

A per-user install made by the user registers under HKCU, not HKLM *(verify)*.

The IDE troubleshooting page says "Kiro does not support system-level installation". That sentence is part of the error message shown when the **per-user** build is run as Administrator ("Updates are disabled because you are running the user-scope installation of Kiro as Administrator"). It does not say the system-wide installer is unsupported; the page does not mention that installer.

| Win32 app setting | Value |
|-------------------|-------|
| Package | The system-wide installer for the device architecture (x64 or ARM64), wrapped with `IntuneWinAppUtil.exe` |
| Install command | `<installer>.exe /VERYSILENT /SP- /SUPPRESSMSGBOXES /NORESTART /MERGETASKS=!runcode /LOG="C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\kiro-install.log"` (measured on Windows Server 2022 as SYSTEM: exit code 0 after 48 to 53 seconds in seven installs and after 91 seconds in one, on a runner that had come online a few minutes before; on Windows 11 26H2, run by an elevated administrator: exit code 0 after 39 seconds, no Kiro process started. **Keep `/MERGETASKS=!runcode`:** without it the installer starts Kiro when it finishes, and under Intune that Kiro runs as SYSTEM. These are Inno Setup switches; Kiro does not document them) |
| Uninstall command | `"C:\Program Files\Kiro\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART` (measured: exit code 0 within seconds; the install folder and the Uninstall entry are removed. Exit code 1 while Kiro is running) |
| Install behaviour | **System** |
| Detection rule | File: `C:\Program Files\Kiro`, file `Kiro.exe`, "File or folder exists" (measured path and file name). For version-aware detection use the file version of `Kiro.exe`, which equals the release (1.4.236) |
| Requirements | Architecture matching the package; one app per architecture |
| Minimum version | **IDE 1.4.62** (first release with the system-wide installer) |

**What the installer does** (measured on 2026-11-19 with the Kiro IDE 1.4.236 x64 system-wide installer on Windows Server 2022, which is outside Kiro's listed operating systems (integration phase WC, [evidence](aws-integration-test-evidence.md#wc--kiro-installer-mechanics-windows-runner-system)). On 2026-11-19 the W2 kit confirmed the install folder, `Kiro.exe` 1.4.236, the Uninstall entry in the 64-bit view, the machine PATH entry, the all-users shortcut and the signer on Windows 11 Enterprise Evaluation 26H2, installed by an elevated administrator, not by SYSTEM):

| Item | Measured |
|------|----------|
| Technology | Inno Setup: the Uninstall key name ends in `_is1` and the uninstaller is `unins000.exe` |
| Install folder | `C:\Program Files\Kiro`, with `Kiro.exe` (file version = release) and `bin\` |
| Uninstall entry | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{ECDD7648-5B69-4BDC-9D21-C3452CE76CD2}_is1` in the **64-bit (native) registry view**; `DisplayName` Kiro, `DisplayVersion` the release, `UninstallString` `"C:\Program Files\Kiro\unins000.exe"`. Whether the key name is the same for other releases and for ARM64 was not checked *(verify)* |
| PATH and shortcuts | `C:\Program Files\Kiro\bin` is added to the machine PATH; one Start Menu shortcut for all users |
| Signature | Authenticode status Valid; signer subject, the full string as Windows prints it: `CN="Amazon.com, Inc.", OU=AWS Kiro, O="Amazon.com, Inc.", L=Seattle, S=Washington, C=US, SERIALNUMBER=2620453, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Delaware, OID.1.3.6.1.4.1.311.60.2.1.3=US`; certificate thumbprint `936E025D82E8C1A04C1AFF51FBA6D5F72455C512`, valid until 2027-03-26, so expect a new certificate after that; issuer DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1. `Kiro.exe` carries the same signer |
| After a silent install | **With the default tasks the installer starts Kiro.** Installed as SYSTEM, eight `Kiro.exe` processes were left running as SYSTEM in session 0. With `/MERGETASKS=!runcode` no Kiro process is started (checked on a fresh install and on an install over an existing one) |
| While Kiro is running | Measured with the Kiro processes that the installer itself had started (as SYSTEM, in session 0): the silent install ends after 1 to 2 seconds with **exit code 1**, the silent uninstall ends at once with **exit code 1**, and neither changes anything. The installer log says "Setup has detected that Kiro is currently running"; in silent mode that prompt defaults to Cancel |
| Install over an existing install | Exit code 0 when Kiro is not running |

What follows for Intune: expect an update by supersedence and an uninstall to fail with exit code 1 while Kiro is running. This was measured only with Kiro running in the installer's own session (session 0). Whether the installer also detects a Kiro that a logged-on user has open in another session, and how Intune reports and retries the failure, was not tested *(verify)*. Decide how updates reach such devices (for example a maintenance window, or asking users to close Kiro); Inno Setup's `/CLOSEAPPLICATIONS` and `/FORCECLOSEAPPLICATIONS` switches were not tested *(verify)*, and force-closing an editor can lose unsaved work.

**Get and check the installer before packaging.** Kiro's installation page says only to download the installer from kiro.dev; it documents no direct URL for the system-wide build, and Kiro publishes no checksum or signer name for the Windows installer. Create your own baseline and check every new version against it:

```powershell
$sig = Get-AuthenticodeSignature .\<installer>.exe
$sig.Status                      # must be Valid
$sig.SignerCertificate.Subject   # must equal the subject your organisation recorded (see the table above for 1.4.236)
Get-FileHash .\<installer>.exe -Algorithm SHA256   # record with the package
```

`Valid` alone is not a publisher check: a correctly signed file from any publisher reports `Valid`. The comparison of the signer subject (and, if you pin it, the certificate thumbprint) with your recorded value is the actual check.

**Registry detection rules and the 32-bit view.** The detection rule above is a file rule. If you use a registry rule on the installer's Uninstall entry instead, note that `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` is **redirected** under WOW64 (it inherits this from `HKLM\SOFTWARE`; Microsoft's table has no row of its own for it): a 32-bit installer registers under `HKLM\SOFTWARE\WOW6432Node\...\Uninstall`. The Intune setting "Associated with a 32-bit app on 64-bit clients" (default No, the 64-bit registry) must match the view the installer used. The x64 system-wide installer registers in the 64-bit view (measured, see above), so leave the setting at No. This is also why the commands in this runbook start 64-bit PowerShell. It does not affect `HKLM\SOFTWARE\Policies`, which is a shared key ([section 2](#2-registry-policies-managed-updates-and-sign-in-portal)).

**Devices that already have the per-user build.** Kiro does not document how the per-user and system-wide builds coexist or how to move from one to the other. Expected, all *(verify)*: the per-user build registers under HKCU and installs under the user's profile, so an uninstall has to run in that user's context before or after the system-wide build is deployed. Kiro's statement that "settings, extensions, and sign-in state are preserved across reinstalls" appears under "Downgrade to a previous version" and describes reinstalling the same build; whether it holds when switching builds is not documented. Test the order and the result on a pilot device before a fleet rollout. A copy that an earlier deployment of the per-user build left in SYSTEM's profile was removed with its registered `UninstallString` plus `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`, run as SYSTEM: exit code 0 after 3 seconds; the key, both folders and the PATH entry were gone (measured on Windows Server 2022, 2026-11-19). If `Kiro.exe` still runs as SYSTEM on such a device, restart it first.

**WorkSpaces.** AWS-provided Windows bundles run Windows Server; Windows 10/11 needs BYOL. Kiro lists Windows 10/11 for the IDE; see [Part 1, Section 4.1.1](../Kiro-Agentic-SDLC-Banking-Best-Practices.md).

### Kiro CLI on Windows

Kiro CLI is installed separately. Kiro lists Windows 11 for the CLI and documents only `irm 'https://cli.kiro.dev/install.ps1' | iex`, which downloads the MSI and runs `msiexec` for the current account ([installation page](https://kiro.dev/docs/getting-started/installation/)); its Windows update mirror serves the same MSI ([managed updates](https://kiro.dev/docs/enterprise/managed-updates/)). Kiro documents no per-machine install, no MSI property and no runtime prerequisite. The values below were measured with Kiro CLI 3.5.0 (`kiro-cli-x86_64-pc-windows-msvc.msi` from Kiro's CLI manifest), installed as SYSTEM the way Intune runs a Win32 app, on Windows Server 2022 (2026-11-19, two runs) and Windows 11 Enterprise Evaluation 26H2 (2026-11-20, three runs).

| Win32 app setting | Value |
|-------------------|-------|
| Package | `kiro-cli-x86_64-pc-windows-msvc.msi` (x64; ARM64 not tested), wrapped with `IntuneWinAppUtil.exe`. Authenticode Valid; signer `CN="Amazon Web Services, Inc.", OU=AWS Kiro, O="Amazon Web Services, Inc.", L=Seattle, S=Washington, C=US, SERIALNUMBER=4152954, ...`, thumbprint `FE9F5C2AC9D17DB2553E8996462A9A00EAD46863`, valid until 2027-03-10. This is **not** the Kiro IDE signer: keep one baseline per product ("Get and check the installer before packaging" above) |
| Dependency | Win32 app **Microsoft Visual C++ 2015-2022 Redistributable (x64)**, install command `vc_redist.x64.exe /install /quiet /norestart`, set as a dependency with automatic install (measured: exit code 0 with 14.44.35211.0, Authenticode Valid, signer Microsoft Corporation). Without it `kiro-cli.exe` does not start (finding F3 below) |
| Install command | `msiexec /i kiro-cli-x86_64-pc-windows-msvc.msi /quiet /norestart INSTALLFOLDER="C:\Program Files\Kiro-Cli"` (measured: exit code 0 after 7 to 15 seconds; the folder holds `kiro-cli.exe` only). `INSTALLFOLDER` is the property name from the package's own log; Kiro does not document it *(verify on every new release)*. Without it the CLI lands in SYSTEM's profile (finding F4 below) |
| Machine PATH | Not set by the MSI: PATH is set only for the installing account (SYSTEM). **Add `C:\Program Files\Kiro-Cli` to the machine PATH yourself** (snippet below), or users must call the full path |
| Uninstall command | `msiexec /x {539162FB-DCCC-4E50-8AA5-423F78632CA8} /quiet /norestart` (measured: exit code 0; the file and the Uninstall entry are removed). Whether the product code stays the same for other releases was not checked *(verify)*. A PATH entry you added stays |
| Install behaviour | **System** |
| Detection rule | File: `C:\Program Files\Kiro-Cli`, file `kiro-cli.exe`, "File or folder exists". Do not detect on the product code or the Uninstall key: a default install into SYSTEM's profile writes the same key |
| Validation | As a standard user, `kiro-cli --version` prints `kiro-cli 3.5.0` (measured from the full path). A missing runtime shows here, not in the MSI exit code |

To add the folder to the machine PATH, run a script like this after `msiexec` in the same System-context install. It was not run in the lab *(verify)*. It keeps the value's type (`REG_EXPAND_SZ`), so entries such as `%SystemRoot%` stay unexpanded; users see the change in a new terminal:

```powershell
$dir = 'C:\Program Files\Kiro-Cli'
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment', $true)
$path = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
if (($path -split ';') -notcontains $dir) { $key.SetValue('Path', ($path.TrimEnd(';') + ';' + $dir), [Microsoft.Win32.RegistryValueKind]::ExpandString) }
$key.Close()
```

**Findings F3 and F4: installing Kiro CLI as SYSTEM** (measured, platforms and dates as above):

| Case | Measured |
|------|----------|
| F4: `msiexec /i ... /quiet /norestart` as SYSTEM, without `INSTALLFOLDER` | Exit code 0, but `kiro-cli.exe` lands in SYSTEM's own profile, `C:\Windows\system32\config\systemprofile\AppData\Local\Kiro-Cli\` (the package log shows `INSTALLFOLDER = <LocalAppDataFolder>\Kiro-Cli\`). A per-machine Uninstall entry is still written: HKLM, 64-bit view, `{539162FB-DCCC-4E50-8AA5-423F78632CA8}`, DisplayName `Kiro CLI`, DisplayVersion `3.5.0.0`. PATH: SYSTEM's user PATH only. A registry or product-code detection rule therefore reports the app as installed although it sits in SYSTEM's profile (running it from there as a standard user was not tried; Windows gives standard users no access to that profile by default). Kiro's `install.ps1` prints `C:\Program Files\Kiro-Cli\` as the location in either case (kirodotdev/Kiro#11581; related: kirodotdev/Kiro#11584). Reported to Kiro on GitHub (kirodotdev/Kiro) |
| F4: the same with `INSTALLFOLDER="C:\Program Files\Kiro-Cli"` | Exit code 0; `C:\Program Files\Kiro-Cli\kiro-cli.exe`; a standard user runs it (`kiro-cli 3.5.0`); the machine PATH has no `Kiro-Cli` entry |
| F3: clean Windows 11 26H2 image, no Visual C++ runtime (run 1) | The MSI exits 0 in both cases, but `kiro-cli.exe --version` exits with -1073741515 (0xC0000135, `STATUS_DLL_NOT_FOUND`) and prints nothing, as SYSTEM and as the standard user. `kiro-cli.exe` 3.5.0 imports `MSVCP140.dll`, `MSVCP140_1.dll`, `VCRUNTIME140.dll` and `VCRUNTIME140_1.dll`; none was on the clean image. Kiro's `install.ps1` does not install them |
| F3: after the Visual C++ 2015-2022 Redistributable x64 14.44.35211.0 (runs 2 and 3) | Kiro CLI runs as SYSTEM and as the standard user; run 3 ended pass=31 fail=0 info=7. The Windows Server 2022 runner already had the runtime, which is why it did not show there. Kiro tracks this as kirodotdev/Kiro#9752 (opened for 2.9.0; still reproduces with 3.5.0). Many managed devices have the runtime from other software; declare the dependency anyway |

**Design notes for the policy on Windows: findings F1 and F2.** Measured with Kiro CLI 3.5.0 headless (`kiro-cli chat --v3 --no-interactive`), run by a standard user created after the deployment, with the repository policy (34 rules) and the hook guards switched off unless stated; shell commands used the `execute_pwsh` tool. Windows Server 2022: two runs on 2026-11-19 plus a follow-up run; Windows 11 26H2: runs 2 and 3 on 2026-11-20. Both findings were reported to Kiro on GitHub (kirodotdev/Kiro). Not tested in Kiro IDE. The policy-side consequences are in [`../managed-settings/README.md`](../managed-settings/README.md) ("Windows rules" and "How admin rules combine with other permission sources").

- **F1: shell rules are matched case-sensitively; PowerShell is not case-sensitive.** Deny rule 13 refused `Invoke-WebRequest`, `irm` and lowercase `invoke-webrequest`, but `INVOKE-WEBREQUEST https://example.com/ -OutFile ...`, a casing the rule does not list, ran and fetched the page on both platforms, on Windows 11 also with the guard hooks on. Kiro's permissions page describes shell patterns as globs and says nothing about case, and an administrator cannot list every casing. So on Windows **a shell deny rule is a guardrail against the usual spellings, not a security boundary.** Control network egress with a network control (proxy or DNS firewall allowlist). The PowerShell guards match case-insensitively and back up only what they cover: `destructive-fs-guard.ps1` blocked `REMOVE-ITEM .git -RECURSE -FORCE` (Windows 11 runs 2 and 3), while no guard covers network commands.
- **F2: `--trust-all-tools` approves commands under an admin `ask` rule.** `Remove-Item <file> -Force` (admin `ask`, rule 21) ran in a headless run with `--trust-all-tools` and deleted the file without asking anyone, on both platforms; without the flag it was refused. An admin `deny` held with the flag (the suite starts every end-to-end check except the one without the flag with `--trust-all-tools`, so the denials under F1 were measured with it): rule 21 changed to `deny` refused the same command (Windows Server 2022 follow-up run, Windows 11 run 3), but `REMOVE-ITEM <file> -FORCE` in capitals then ran (Windows 11 run 3): F1 defeats the deny. Kiro's pages disagree: [permission policies](https://kiro.dev/docs/enterprise/governance/permissions/) says an admin `ask` "forces a prompt even if the user has an `allow` rule", while [permissions](https://kiro.dev/docs/permissions/) says the CLI's trust-all options trust every tool action the rules do not deny. The measured behaviour follows the second page, and any user can add the flag (related: kirodotdev/Kiro#12036, trust-all over an agent deny). Use `deny`, not `ask`, for anything that must never run unattended; keep `--trust-all-tools` out of pipeline and agent configurations (code review or a CI check); keep the F1 backstops.
- **API-key sessions.** A Kiro CLI session authenticated with a Kiro API key ran commands under the policy's `idc`-only sign-in rule (both platforms): the sign-in rule is one layer, not an access control for the CLI.

## 2. Registry policies: managed updates and sign-in portal

Kiro IDE and Kiro CLI use separate, independent update mechanisms ([managed updates](https://kiro.dev/docs/enterprise/managed-updates/)).

**Kiro IDE**

| Registry value (`HKLM\SOFTWARE\Policies\Kiro`) | Type | Effect |
|-------------------------------------------------|------|--------|
| `UpdateMode` = `none` | REG_SZ | Disables all update checks for every user of the device, regardless of `UpdateUrl`. Kiro recommends it on shared machines where Kiro is installed for all users, because standard users cannot apply updates there |
| `UpdateUrl` = `https://updates.example.com` | REG_SZ | Self-hosted update site; `https://` only (other values fall back to the default). Windows manifests: `{base}/stable/metadata-win32-x64-system-stable.json` and `metadata-win32-arm64-system-stable.json` for the system-wide build |

- `lockdown-windows.ps1 -DisableUpdates` writes `UpdateMode` in the 64-bit registry view and `-Check` reports a missing or changed value. Microsoft lists `HKLM\SOFTWARE\Policies` as a **shared** key under WOW64 (one physical copy for both views), so a value written from 32-bit PowerShell, whether `UpdateMode`, `UpdateUrl` or `AuthPortalUrl`, lands in the same place; the integration test checks this on Windows Server 2022 (`W4.wow64-policies-shared`).
- Kiro reads both values at startup: users must restart Kiro.
- **Measured** in Kiro IDE 1.4.236 (system setup) on Windows 11 26H2 with a standard user, 2026-11-20: with `UpdateMode=none` the command palette has no "Check for Updates" command, and Help > About shows the version ("1.4.236 (system setup)") but no text about managed or disabled updates. With the value removed and Kiro restarted, "Check for Updates" was back and ran. Kiro gives the user no hint that updates are managed, so tell users.
- With `UpdateMode=none`, IT updates Kiro by superseding the Kiro IDE Win32 app with the new version.
- **Pilot, then fleet:** point the pilot group's `UpdateUrl` at a manifest that advertises the new version, validate, then advertise it on the production endpoint. **Pin** a version by advertising the version the fleet runs.
- **Limits:** pinning governs only the automatic update check. A user can still install another version by hand; the per-user build needs no administrator rights. Use application control (for example WDAC or AppLocker) where that matters. `managed-settings.json` lives in a machine-wide path, so it applies to whichever Kiro build runs on the device.
- **Kiro's pages conflict here:** managed updates (updated 2026-10-29) suggests blocking `prod.download.desktop.kiro.dev` together with `UpdateUrl`, while the newer [firewall page](https://kiro.dev/docs/privacy-and-security/firewalls/) (updated 2026-11-18) lists the same host for "Auto-updates, Powers registry, and icons". Following the newer page, do not block it fleet-wide; if you must, test the effect on Powers on a pilot device first *(verify)*.

**Sign-in portal (`AuthPortalUrl`, optional, Kiro CLI 3.5.0+)**

- A string value `AuthPortalUrl` under `HKLM\SOFTWARE\Policies\Kiro` sets the portal that `kiro-cli login` opens in the browser instead of `https://app.kiro.dev` ([sign-in controls](https://kiro.dev/docs/enterprise/governance/sign-in/)). It takes precedence over `auth_portal_url` in `managed-settings.json`, which in turn wins over the user's `KIRO_AUTH_PORTAL_URL` and `auth.portalUrl`.
- Browser sign-in only (the device-code flow does not use it), and Kiro describes it for the CLI, not for the IDE.
- Create it as a string (REG_SZ): a value of the wrong type reads as unset and the next source applies. A value that is present but not a valid `https` URL sends users to the default portal, not to an error. If neither administrator source is set, the user's environment variable applies and Kiro does not validate it.
- The scripts in this repository do not write `AuthPortalUrl`; the lockdown scripts validate `auth_portal_url` in the policy file (https, no credentials, query or fragment, at most 2,048 bytes).
- The portal host must be reachable from managed devices; add it to the egress allowlist.

**Kiro CLI updates**

- Policy `update.baseUrl` (REG_SZ) in `HKLM\SOFTWARE\Policies\Kiro\CLI`, "typically deployed via Group Policy" according to Kiro; an Intune Settings-catalog or custom registry deployment that writes the same value is equivalent *(verify)*.
- The Windows mirror serves `<base>/latest/manifest.json` (current version only). Pin by keeping its `version` at the fleet's release; a user can still reinstall or downgrade with `kiro-cli update --force`.
- Defining the `KIRO_NO_AUTO_UPDATE` environment variable (any value) disables background updates on Windows.
- An enforced policy wins over the `KIRO_DESKTOP_RELEASE_URL` environment variable.

## 3. The Kiro policy Win32 app

### Package

Build the package from a checkout with **LF** line endings (the repository's `.gitattributes` does this for a fresh clone; a CRLF checkout makes the `SHA256SUMS` check fail with exit 2). Keep the repository layout:

```
package\
  mdm\lockdown-windows.ps1
  managed-settings\managed-settings.banking.json      (or managed-settings.option-b.json)
  agent-hooks\SHA256SUMS                              (only with -DeployHooks / -InstallUser)
  agent-hooks\<every file listed in SHA256SUMS>       (*.sh, windows\*.ps1, hooks\banking-guards.windows.json)
```

```powershell
IntuneWinAppUtil.exe -c .\package -s mdm\lockdown-windows.ps1 -o .\out
```

### Settings

| Setting | Value |
|---------|-------|
| Install command | `%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File mdm\lockdown-windows.ps1 -StageSources -DeployHooks -InstallUser -DisableUpdates` (drop the switches you do not use; add `-OptionB` for the direct-federation policy) |
| Uninstall command | `C:\Windows\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File mdm\lockdown-windows.ps1 -RemoveSources` (Intune does not expand environment variables in the uninstall command) |
| Install behaviour | **System** |
| Return codes | Keep the defaults. The script returns 0 (success), 1 (environment error) or 2 (validation refused); Intune reports 1 and 2 as failed |
| Detection rule | Custom script `mdm\intune\Detect-KiroPolicy-Win32.ps1`, "Run script as 32-bit process on 64-bit clients" = No. Set its `$Options` to the install switches without `-StageSources`, and `$ExpectedPolicySha256` to the hash of this package's policy file ([section 4](#4-remediations-drift-detection-and-repair)) |
| Assignment | Required, to **device** groups |

Microsoft documents that `powershell.exe` in an install or uninstall command starts 32-bit PowerShell; `Sysnative` starts the 64-bit one. The script also works from 32-bit PowerShell (it opens the 64-bit registry view explicitly, and `C:\ProgramData` is not redirected); the integration test runs the install that way (`W4.win32-install-32bit-host`).

### What `-StageSources` does

After deploying, the script copies itself, the validated policy and (with `-DeployHooks`) `SHA256SUMS` plus every file it lists to `C:\ProgramData\Kiro\deploy\`, in the repository layout. Each folder and file gets the same ACL as the policy: owner Administrators, SYSTEM and Administrators Full Control, Users Read, and a Users deny on Delete, Write, Append and attribute changes on each file. A standard user therefore cannot plant a modified source that a later remediation would deploy. The script also never trusts what was there before: it prepares each file in an administrators-only work folder (`C:\ProgramData\Kiro\.staging`) and renames it over the old one, putting the old file back if the rename fails; it creates each folder under a random name, locks it and renames it into place; and it moves aside (to `<name>.untrusted-<id>`) any existing folder that a non-administrator owns or can re-permission, because a handle opened before the lockdown would stay usable after it. Devices on which an earlier version of the script ran over a folder created by a standard user are not detected by this check: remove `C:\ProgramData\Kiro` there once and redeploy. A local administrator can still change the files; developers must not be local administrators.

To pin the hook manifest, add `'-ManifestSha256', '<sha256 of SHA256SUMS>'` to the wrappers' `$Options`. The wrappers are delivered by Intune, separately from the staged files, so the pin is out of band.

`-RemoveSources` (the uninstall command) deletes only `C:\ProgramData\Kiro\deploy\`. The policy, the hook scripts, the per-user hook files and `UpdateMode` stay in place, so an accidental unassignment does not remove the primary control. Remove them deliberately (unlock the files with `icacls <file> /remove:d *S-1-5-32-545`, then delete them).

## 4. Remediations: drift detection and repair

| Setting | Value |
|---------|-------|
| Detection script | `mdm\intune\Detect-KiroPolicy.ps1` |
| Remediation script | `mdm\intune\Remediate-KiroPolicy.ps1` |
| Run this script using the logged-on credentials | **No**, set explicitly. Microsoft documents for this setting that No runs the script in the system context and Yes with the user's credentials ([platform scripts](https://learn.microsoft.com/en-us/intune/intune-service/apps/powershell-scripts)); the Remediations page says only that it depends on the script. The wrappers need SYSTEM: `lockdown-windows.ps1` refuses to deploy as a standard user |
| Enforce script signature check | Your policy (sign the scripts if you enforce it) |
| Run script in 64-bit PowerShell | **Yes** (Microsoft's walkthrough uses No; the wrappers also reach 64-bit PowerShell through `Sysnative` from a 32-bit host) |
| Schedule | At least daily; hourly for VDI pools |
| Assignment | The same device groups as the Kiro policy app |

**New package versions.** The wrappers compare the device with its own staged copy, so on their own they cannot tell that a newer package exists. Set `$ExpectedPolicySha256` in all three wrappers to the SHA-256 of the policy file in the current package (`lockdown-windows.ps1 -DryRun` prints it as `sha256=...`), and update it with every package version. A device whose deployed policy is not that file is then reported as non-compliant by the Remediations detection and as not installed by the Win32 detection, so Intune installs the new package. Without it, a device with an older but internally consistent package is reported as healthy. The value covers the policy file only: for a package that changes only the hook files or the script, use Intune supersedence or a new app version so that every device reinstalls.

Before uploading, set `$Options` in both scripts to the install switches **without** `-StageSources`, for example `@('-DeployHooks', '-InstallUser', '-DisableUpdates')`. Add `'-SettingsPath', 'C:\ProgramData\Kiro\deploy\managed-settings\<file>.json'` if you package a policy file with another name, or `'-OptionB'` for the direct-federation policy.

The detection output is one line, for example `NON-COMPLIANT: drift in 2 item(s); first: C:\ProgramData\Kiro\managed-settings.json content differs (...)`. A device without the staged script reports `NON-COMPLIANT: staged script not found ...`; the remediation cannot fix that (it exits 1), so check the Kiro policy app's installation status on that device.

### Without the Remediations licence

Remediations requires Windows Enterprise E3 or E5, Windows Education A3 or A5, or Windows VDA per user. Without it:

- **Win32 app re-evaluation (recommended):** with `Detect-KiroPolicy-Win32.ps1` as the detection rule, a device with drift reports the required app as not installed, and Intune reinstalls it, which restores the controls, on its next evaluation. Intune sets that interval, not you *(verify the interval in your tenant)*.
- **Scheduled task:** register a daily SYSTEM task that runs the staged script, for example from the Win32 install:

```powershell
$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$arg = '-NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\Kiro\deploy\mdm\lockdown-windows.ps1 -DeployHooks -InstallUser -DisableUpdates'
Register-ScheduledTask -TaskName 'Kiro policy self-repair' -User 'SYSTEM' -RunLevel Highest -Force `
  -Action (New-ScheduledTaskAction -Execute $ps -Argument $arg) `
  -Trigger @((New-ScheduledTaskTrigger -Daily -At 03:00), (New-ScheduledTaskTrigger -AtStartup))
```

## 5. Per-user hooks and steering (optional)

These are defense in depth and guidance. The enforced control is `managed-settings.json`; on Windows its shell deny rules match case-sensitively (finding F1, [Kiro CLI on Windows](#kiro-cli-on-windows)), and the guards, which match case-insensitively, back them up only for the commands they cover.

**Hooks.** `-DeployHooks` deploys the PowerShell guards (`agent-hooks\windows\pii-guard.ps1`, `git-guard.ps1`, `destructive-fs-guard.ps1`) to `C:\ProgramData\Kiro\hooks\` with the policy's ACL. `-InstallUser` writes the v1 hook file `banking-guards.windows.json` to `.kiro\hooks\` in every local user profile and in `C:\Users\Default` (new profiles), skipping any profile where `.kiro`, `.kiro\hooks` or the file is a junction or symbolic link. The guards block with exit code 2, like the bash versions.

- **Surface:** Kiro documents global hooks in `~/.kiro/hooks/` for **Kiro CLI V3** only. **Measured:** Kiro IDE 1.4.236 on Windows 11 26H2 lists the global hooks from `%USERPROFILE%\.kiro\hooks` in its Agent Hooks panel and runs them before tool calls (2026-11-20, standard user, workspace without hooks); Kiro CLI 3.5.0 loads them in headless V3 runs (Windows Server 2022, 2026-11-19; Windows 11 26H2, 2026-11-20). In both clients a PreToolUse hook that exits 2 blocked the tool call, and `pii-guard.ps1` blocked a write of a test NRIC. For the IDE this is observed, not documented: re-test after each Kiro IDE update.
- **Shell:** Kiro does not document which shell runs hook commands on Windows. **Measured:** `cmd.exe`, in Kiro IDE 1.4.236 on Windows 11 26H2 (parent chain `cmd.exe < Kiro.exe`) and in Kiro CLI 3.5.0 on Windows Server 2022 and Windows 11 26H2 (`cmd.exe < node.exe < kiro-cli.exe`); the probe hook's `powershell.exe` ran as 64-bit Windows PowerShell 5.1. The commands use the form `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:/ProgramData/Kiro/hooks/<guard>.ps1`, with forward slashes, so they also work from PowerShell and Git Bash.
- **Matchers:** the shell guards use the `shell` tag, which matches `execute_pwsh` (Windows) and `execute_bash` ([hook types](https://kiro.dev/docs/hooks/types/)). The `banking-secure` agent's own hooks match `execute_bash` and reference `/opt/kiro/hooks`, so the agent is not installed on Windows.
- **Editable by the user:** the script sets no owner or ACL on the hook files; they inherit the profile folder's permissions, so the user can edit or delete them. Measured on Windows 11 26H2 (2026-11-19 and 2026-11-20): the standard user renamed the hook file in their profile, and after `pii-guard` blocked a write in Kiro IDE the agent itself suggested changing or exempting the hook. The owner and the effective permissions were not recorded *(verify with `icacls` on a pilot device, including for a user created later from the Default profile)*. `-Check` reports a change and the next run restores it. The audit logger has no PowerShell port.
- **Residual risk:** SYSTEM writes into folders the user controls. The script refuses the links it finds and never deletes recursively there, but its checks and its writes are separate steps: a user who swaps `.kiro` or `.kiro\hooks` for a link at the right moment could redirect the creation of the folder, the deletion of the old hook file or the write of the new one (content fixed, not user-controlled) to another place. If that is not acceptable, leave `-InstallUser` out and deliver the hook file in user context instead.

**Which context for per-user files.** Kiro's global hooks and steering live in each user's profile, so there are two ways to deliver them:

| | SYSTEM copy (this repository: `-InstallUser`) | User context (Win32 app with install behaviour User, or a script run with the logged-on credentials) |
|---|---|---|
| Reaches | Every existing local profile, and `C:\Users\Default` for profiles created later (measured for the hook file: a local user created after the deployment had `.kiro\hooks\banking-guards.windows.json`, Windows Server 2022 2026-11-19 and Windows 11 26H2 2026-11-20; Kiro IDE in such a profile not tested) | The user the script runs for *(verify when Intune runs it; Microsoft's pages do not state it for every case)* |
| Source | Reads the staged, verified files; validates the hook file before writing | Can also read `C:\ProgramData\Kiro\deploy\`: the folder is readable by standard users and protected only against writing |
| Writes | Into user-controlled folders as SYSTEM, so the script refuses junctions and symbolic links | With the user's own rights; cannot write admin-only locations |
| Drift | Reported by `-Check` and repaired by the Remediations wrapper | Needs its own detection script |
| In this repository | Implemented and tested (`-InstallUser`) | Not implemented; `lockdown-windows.ps1` and the wrappers must stay in System context |

Either way the user can change the files afterwards: they are guidance and defense in depth. The enforced control is `managed-settings.json`.

**Steering.** The scripts do not deploy steering because it is guidance only, but Kiro explicitly allows pushing team steering "via MDM solutions or Group Policies" into `~/.kiro/steering` ([steering](https://kiro.dev/docs/steering/)). To distribute it for consistency (not enforcement):

```powershell
# Win32 app, System context: package this script together with a team-steering folder (*.md).
# (A platform script is uploaded as a single file and cannot carry the folder.)
# SYSTEM writes into user-controlled folders here, so links are never followed.
function Test-Link($p) { try { [bool]([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) } catch { $false } }
$src = Join-Path $PSScriptRoot 'team-steering'
if (-not (Get-ChildItem -Path $src -Filter '*.md' -File -ErrorAction SilentlyContinue)) { Write-Error "no steering files in $src"; exit 1 }
$profiles = @(Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special } | ForEach-Object { $_.LocalPath }) + 'C:\Users\Default'
foreach ($p in $profiles) {
  $kiro = Join-Path $p '.kiro'; $dir = Join-Path $kiro 'steering'
  if ((Test-Link $kiro) -or (Test-Link $dir)) { continue }
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  if ((Test-Link $kiro) -or (Test-Link $dir)) { continue }
  foreach ($f in Get-ChildItem -Path $src -Filter '*.md' -File) {
    $dest = Join-Path $dir $f.Name
    if (Test-Link $dest) { continue }
    if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force }
    Copy-Item -LiteralPath $f.FullName -Destination $dest
  }
}
```

- Global steering from `%USERPROFILE%\.kiro\steering` is loaded (measured: Kiro IDE 1.4.236 on Windows 11 26H2, 2026-11-20; Kiro CLI 3.5.0 on Windows Server 2022, 2026-11-19, and Windows 11 26H2, 2026-11-20).
- The developer can change or delete the files.
- Workspace steering wins over global steering on conflict.
- Custom agents do not load steering automatically: list it in the agent's `resources`. `banking-secure` loads workspace steering (`file://.kiro/steering/**/*.md`); Kiro documents absolute and relative paths for `resources` but not `~`, so check how to reference global steering before relying on it *(verify)*.
- Kiro Enterprise Management (preview) can deliver steering files from the Kiro service instead; see [`security-governance-features.md`](security-governance-features.md#29-enterprise-management-preview).

## 6. Troubleshooting

| Log | Location |
|-----|----------|
| Intune Management Extension (app and script processing) | `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log` |
| Win32 app download, install and detection | `...\IntuneManagementExtension\Logs\AppWorkload.log` |
| Kiro IDE installer (from the `/LOG=` switch above) | `...\IntuneManagementExtension\Logs\kiro-install.log` |
| Kiro wrappers (full `lockdown-windows.ps1` output) | `...\IntuneManagementExtension\Logs\KiroPolicy-Detect.log`, `KiroPolicy-Remediate.log`, `KiroPolicy-Win32Detect.log` |
| Kiro CLI | `%TEMP%\kiro-log\logs\kiro-chat.log` ([installation page](https://kiro.dev/docs/getting-started/installation/)) |

| Symptom | Cause and fix |
|---------|---------------|
| Install fails, log shows `hook hash verification FAILED` (exit 2) | The package was built from a CRLF checkout. Rebuild from an LF checkout |
| Install fails with `must run as SYSTEM or an elevated Administrator` (exit 1) | Install behaviour is User. Set it to System |
| Install fails with `refusing to use C:\ProgramData\Kiro: it is a junction` (exit 1) | A user pre-created a junction. Remove it as an administrator and reinstall |
| "The application was not detected after installation completed successfully" | The detection script's `$Options` do not match the install command, or `-Check` found an issue: read `KiroPolicy-Win32Detect.log` |
| Install log shows `moved aside to ...untrusted-...` | `C:\ProgramData\Kiro` (or a subfolder) existed and was owned or controlled by a non-administrator. The script recreated it; review the old folder and delete it. If this happened during a remediation, the staged sources went with the old folder: reinstall the Kiro policy app |
| Detection reports `not the version of the current package` | The device still has an older policy package, or `$ExpectedPolicySha256` in the wrapper was not updated for the new package |
| The wrappers or the staged script fail under WDAC or AppLocker script enforcement | They use .NET calls that Constrained Language Mode blocks. Sign the scripts or allow them by policy *(verify in your application-control setup)*. Signing changes a file's bytes: sign the guards **before** you regenerate `agent-hooks/SHA256SUMS` for the package |
| An existing Windows clone still fails the `SHA256SUMS` check after `.gitattributes` was added | The working tree still has CRLF files; `.gitattributes` applies when files are checked out. Clone afresh, or, with no uncommitted work, run `git rm -rq --cached .` followed by `git reset --hard` |
| Remediations shows `staged script not found` | The Kiro policy app is not installed on the device, or it was uninstalled |
| Users do not see Kiro after the IDE app installed, or the app is "not detected" although the install returned 0 | The per-user build was deployed in System context: it installed into SYSTEM's profile and registered under `HKU\S-1-5-18`, not HKLM (measured on Windows Server 2022, 2026-11-19; [section 1](#1-kiro-ide-per-user-vs-system-wide-installer)). Remove that copy with its registered uninstaller, restart the device if `Kiro.exe` runs as SYSTEM, and deploy the system-wide installer |
| Kiro IDE shows "Permissions: Failed" and every tool call is denied | The policy file does not parse, for example it was saved with a UTF-8 BOM. Measured in Kiro IDE 1.4.236 on Windows 11 26H2, 2026-11-20: tools fail closed, while the sign-in restriction is dropped (all four sign-in methods were offered). The notification names neither the cause nor the path, and the agent may advise the user to empty the rules. Do not edit the file on the device: let the remediation redeploy it, and validate packages with `lockdown-windows.ps1 -Strict` |
| `kiro-cli.exe` exits with -1073741515 (0xC0000135) and prints nothing, although the MSI returned 0 | The Microsoft Visual C++ 2015-2022 Redistributable (x64) is missing (measured on a clean Windows 11 26H2 with Kiro CLI 3.5.0; kirodotdev/Kiro#9752). Add it as a dependency of the Kiro CLI app ([Kiro CLI on Windows](#kiro-cli-on-windows)) |
| Intune reports Kiro CLI installed, but `C:\Program Files\Kiro-Cli\kiro-cli.exe` does not exist | The MSI ran as SYSTEM without `INSTALLFOLDER` and installed into `C:\Windows\system32\config\systemprofile\AppData\Local\Kiro-Cli\`; a registry or product-code detection rule still reports it. Uninstall it, reinstall with `INSTALLFOLDER="C:\Program Files\Kiro-Cli"` and detect on the file |
| `kiro-cli` is not recognised in a user's terminal, but `C:\Program Files\Kiro-Cli\kiro-cli.exe` exists | The MSI sets PATH only for the installing account. Add the folder to the machine PATH; the user opens a new terminal |
| The Kiro IDE install, update or uninstall fails with exit code 1 within a few seconds | Kiro is running on the device (measured with Kiro running in session 0; a Kiro that a logged-on user has open *(verify)*). The installer log (`/LOG=`) says "Setup has detected that Kiro is currently running". Close Kiro and retry |
| `Kiro.exe` processes run as SYSTEM after the install | The install command lacks `/MERGETASKS=!runcode`, so the installer started Kiro. Add the switch; stop the processes or restart the device |

## 7. Pilot checklist

The W2 kit in [`../security-tests/windows-client/`](../security-tests/windows-client/README.md) runs most of these items on a Windows 11 **test device** and records the results: `Invoke-W2Checks.ps1` for the installer, the registry, the policy file and the wrappers in the Intune execution contexts, and `W2-manual-checklist.md` for the steps in the Kiro window. Its table "Where confirmed values go" names the place in this page that each check W2.1 to W2.10 settles. The kit needs no Intune tenant, so the items about Intune itself (app installation status, reinstall after drift, supersedence) still need a pilot group. The kit and phase WK were run on a Windows 11 Enterprise Evaluation 26H2 test VM on 2026-11-19 and 2026-11-20, without an Intune tenant; items marked **Lab** were measured there (and, where stated, on Windows Server 2022). Repeat every item on the pilot device: the lab emulated Intune, used an Evaluation edition in a VM and ran each agent check once.

- [ ] Kiro IDE (system-wide, 1.4.62 or later) installs, appears for a standard user, and the detection rule finds it; record the real install path, uninstall path and silent switches. **Lab** (Windows 11 26H2, 2026-11-19, installed by an elevated administrator, not SYSTEM): exit code 0, `C:\Program Files\Kiro\Kiro.exe`, Uninstall entry in the 64-bit view, all-users shortcut; a standard user used Kiro. Intune detection not tested.
- [ ] An update or an uninstall of Kiro IDE while a standard user has Kiro open: record the installer's exit code and what Intune then reports and retries (on the test runner both ended with exit code 1 while Kiro ran in session 0).
- [ ] The Kiro policy app installs as System; `C:\ProgramData\Kiro\managed-settings.json` and the files under `C:\ProgramData\Kiro\deploy\` carry the Users deny ACE (folders have Users Read and Execute only, without a deny entry). **Lab** (Windows 11 26H2, 2026-11-19): the policy file carried the Users deny ACE (34 rules, no BOM, hash equal to the repository file).
- [ ] A standard user cannot modify or delete the policy or any staged file. **Lab** (phase WK, Windows Server 2022 2026-11-19, Windows 11 26H2 2026-11-20): a standard user could neither append to nor delete the policy file; the staged files were not tried.
- [ ] Kiro applies the policy (a denied command is blocked) and the sign-in restriction after a restart, and **no managed-settings warning appears** on the test device. A warning means the file was rejected: permission rules then block every tool call, while the sign-in method restriction is dropped (it fails open; see [Failure behaviour](../managed-settings/README.md#failure-behaviour)). **Lab** (Kiro IDE 1.4.236, Windows 11 26H2, 2026-11-19 and 2026-11-20): denied commands were refused with "Blocked by administration permission policy" and the managed file as the source; an Entra ID-only policy offered only "Your organization"; with a UTF-8 BOM in the file Kiro showed "Permissions: Failed", tools failed closed and all four sign-in methods were offered.
- [ ] The Windows rules in the policy behave as intended in the Kiro client: a few commands from `managed-settings/tests/shell-vectors.tsv` are denied, asked or left alone as listed, including lowercase and alias spellings. Also try one spelling in capitals (for example `INVOKE-WEBREQUEST`) and record the result: in Kiro CLI it runs (finding F1), so it is expected, not a pilot failure; egress must be stopped by the network control. **Lab:** in Kiro IDE 1.4.236 (Windows 11 26H2) `Invoke-WebRequest`, `irm`, lowercase `invoke-webrequest` and `powershell -NoProfile -Command` were refused and `git.exe push` was asked; in Kiro CLI 3.5.0 (Windows Server 2022, Windows 11 26H2) the same denials held and the capitals spelling ran. The capitals case in Kiro IDE was not tested.
- [ ] No pipeline, scheduled task or agent configuration starts Kiro CLI with `--trust-all-tools` where an admin `ask` rule is meant to stop a command (finding F2: the flag approves it). **Lab** (Kiro CLI 3.5.0, Windows Server 2022 and Windows 11 26H2): the `ask` command ran with the flag and was refused without it; as a `deny` rule it was refused with the flag, except in capitals.
- [ ] Remediations: detection reports compliant; after an administrator edits the policy it reports non-compliant and the remediation restores it. **Lab** (Windows 11 26H2, 2026-11-19 and 2026-11-20): the wrappers in 64-bit and 32-bit SYSTEM contexts reported compliant, detected the drift (exit 1) and remediated it; Intune Remediations itself was not used.
- [ ] Without Remediations: an edited policy makes the app "not installed" and Intune reinstalls it. **Lab:** the Win32 detection wrapper reported "not detected" after the drift (same runs); the Intune reinstall was not tested.
- [ ] `UpdateMode=none`: Kiro no longer offers updates, and the Kiro IDE app supersedence updates Kiro. **Lab** (Kiro IDE 1.4.236, Windows 11 26H2, 2026-11-20): no "Check for Updates" command; Help > About shows no text about updates. Supersedence not tested.
- [ ] The installer's Authenticode signature is `Valid` and its signer subject is recorded; if a per-user build was present, the migration order and what carried over are recorded. **Lab** (Windows 11 26H2, 2026-11-19): `Valid`, signer equal to the recorded subject. Migration not tested.
- [ ] Per-user files: as a standard user, `icacls` shows the owner and permissions of the hook file; a user created after deployment received it from the Default profile. **Lab** (phase WK, Windows Server 2022 and Windows 11 26H2): a user created after the deployment had the hook file; `icacls` not recorded.
- [ ] If used: `AuthPortalUrl` opens the expected portal host with `kiro-cli login` (Kiro CLI 3.5.0+), and a malformed value opens the default portal.
- [ ] Hooks: Kiro CLI V3 blocks a force-push and an NRIC write through the PowerShell guards; Kiro IDE loads the global hook file. **Lab:** Kiro IDE 1.4.236 (Windows 11 26H2, 2026-11-20) and Kiro CLI 3.5.0 (Windows Server 2022, Windows 11 26H2) ran the global hooks through `cmd.exe`, honoured exit code 2 and blocked a test NRIC write; in Kiro CLI on Windows 11 `destructive-fs-guard.ps1` blocked `REMOVE-ITEM .git -RECURSE -FORCE`. The force-push through `git-guard.ps1` was not exercised.
- [ ] Kiro CLI, if deployed: the Visual C++ 2015-2022 Redistributable (x64) dependency installs first; the CLI lands in `C:\Program Files\Kiro-Cli`; a standard user runs `kiro-cli --version` in a new terminal through the machine PATH. **Lab** (Kiro CLI 3.5.0, Windows 11 26H2, 2026-11-20): without the runtime the CLI did not start; with it, installed as SYSTEM with `INSTALLFOLDER`, a standard user ran it from the full path. The machine PATH step and the Intune dependency were not tested.
- [ ] Blocking `prod.download.desktop.kiro.dev` (not recommended; see section 2) does not break Powers, if you plan it anyway.
- [ ] Uninstalling the Kiro policy app removes only `C:\ProgramData\Kiro\deploy\`.

## Open questions

The W2 kit ([`../security-tests/windows-client/`](../security-tests/windows-client/README.md)) and phase WK were run on a Windows 11 Enterprise Evaluation 26H2 test VM on 2026-11-19 and 2026-11-20, without an Intune tenant; that run answered questions 2 and 3 and part of 1 and 10. Question 9 needs the kit's check W2.3, which was not run. Questions 11 to 14 come from the Kiro CLI findings ([Kiro CLI on Windows](#kiro-cli-on-windows)).

| # | Question | Status (2026-11-20) |
|---|----------|---------------------|
| 1 | Official silent switches, install path and uninstall path of the system-wide installer | **Measured** for 1.4.236 x64 on Windows Server 2022 as SYSTEM and on Windows 11 26H2 by an elevated administrator, 2026-11-19 ([section 1](#1-kiro-ide-per-user-vs-system-wide-installer)); still to do: ARM64, an install by Intune itself, and a statement from Kiro, which documents none of this |
| 2 | Does Kiro IDE load global hooks from `%USERPROFILE%\.kiro\hooks`? | **Measured, yes:** Kiro IDE 1.4.236 on Windows 11 26H2 lists and runs them, and exit code 2 blocks (2026-11-20). Kiro documents global hooks for CLI V3 only, so re-test after Kiro IDE updates |
| 3 | Which shell runs hook commands on Windows? | **Measured:** `cmd.exe`, in Kiro IDE 1.4.236 (Windows 11 26H2) and Kiro CLI 3.5.0 (Windows Server 2022, Windows 11 26H2); not documented by Kiro |
| 4 | How is the Kiro CLI `update.baseUrl` policy delivered on Windows? | **Documented:** REG_SZ `update.baseUrl` in `HKLM\SOFTWARE\Policies\Kiro\CLI` ([managed updates](https://kiro.dev/docs/enterprise/managed-updates/)) |
| 5 | Does blocking `prod.download.desktop.kiro.dev` affect the Powers registry or icons? | **Likely yes:** Kiro's firewall page (2026-11-18) lists the host for the Powers registry and icons, which conflicts with the managed-updates suggestion to block it. Confirm on a pilot device |
| 6 | Does a 32-bit write to `HKLM\SOFTWARE\Policies\Kiro` (`UpdateMode`, `AuthPortalUrl`) land in the 64-bit view? | **Answered:** `HKLM\SOFTWARE\Policies` is a shared key ([WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys)), and the integration test confirmed it on Windows Server 2022; the script writes the 64-bit view explicitly anyway |
| 7 | Can the troubleshooting page's "does not support system-level installation" wording be updated? | Open: a request to Kiro |
| 8 | Are Kiro IDE and CLI supported on Windows Server (the OS of AWS-provided WorkSpaces bundles)? | Open: Kiro lists Windows 10/11 for the IDE and Windows 11 for the CLI. In the lab the IDE installers and Kiro CLI 3.5.0 worked on Windows Server 2022, which is not a support statement; confirm with Kiro or use BYOL Windows 11 |
| 9 | How do the per-user and system-wide builds coexist, and what carries over when switching? | Open: not documented by Kiro and not measured (W2 kit: check W2.3). Measured only: the per-user build installed as SYSTEM lands in SYSTEM's profile and can be removed with its registered uninstaller (Windows Server 2022) |
| 10 | Who owns a hook file that SYSTEM writes into a user profile, and does a new user get it from the Default profile? | **Partly answered:** a local user created after the deployment had the hook file from `C:\Users\Default` (phase WK, Windows Server 2022 2026-11-19, Windows 11 26H2 2026-11-20). Open: the owner and permissions (`icacls`, W2 kit: check W2.9, part B), and Kiro IDE in such a profile |
| 11 | Does Kiro IDE match shell rules case-sensitively, like Kiro CLI 3.5.0 (finding F1)? | Open: measured in Kiro CLI only (Windows Server 2022, Windows 11 26H2). Reported to Kiro on GitHub (kirodotdev/Kiro) |
| 12 | Does an admin `ask` rule hold against `--trust-all-tools` (finding F2)? | **Measured, no:** in headless Kiro CLI 3.5.0 runs the flag approved the command; an admin `deny` held (for the listed spelling; in capitals it ran, F1). Kiro's two pages disagree. Reported to Kiro on GitHub (kirodotdev/Kiro) |
| 13 | Is there a supported per-machine install of Kiro CLI on Windows, with the machine PATH (finding F4)? | Open: `INSTALLFOLDER="C:\Program Files\Kiro-Cli"` works (measured) but is not documented, and the MSI sets PATH only for the installing account. Reported to Kiro on GitHub (kirodotdev/Kiro) |
| 14 | Does Kiro CLI need a runtime prerequisite on Windows (finding F3)? | **Measured, yes:** the Visual C++ 2015-2022 Redistributable (x64) on a clean Windows 11 26H2 (Kiro CLI 3.5.0, 2026-11-20). Tracked by Kiro as kirodotdev/Kiro#9752 (open) |

## MAS TRM mapping

| MAS TRM | Covered by |
|---------|------------|
| 7.5 Change management | Versioned Win32 packages; `UpdateMode` / `UpdateUrl` for pilot-then-fleet updates |
| 9.1 Access control | Administrator-only policy and staged sources; System-context installs |
| 11.3 System security | Policy ACL with a Users deny; junction refusal |
| 12.2 Cyber event monitoring | Remediations detection output and logs; drift reported as non-compliant |

## References

- [`mdm-endpoint-enforcement.md`](mdm-endpoint-enforcement.md): deployment model for every OS.
- [`../mdm/lockdown-windows.ps1`](../mdm/lockdown-windows.ps1) and [`../mdm/intune/`](../mdm/intune/): the scripts.
- [`../agent-hooks/README.md`](../agent-hooks/README.md): the guard hooks, including the PowerShell ports.
- [`aws-integration-test-evidence.md`](aws-integration-test-evidence.md): results of the Windows runs.
- [`../security-tests/windows-client/`](../security-tests/windows-client/README.md): the Windows client validation kit (W2, issue #43) for the pilot checklist and the open questions; run on a Windows 11 Enterprise Evaluation 26H2 test VM on 2026-11-19 and 2026-11-20.
