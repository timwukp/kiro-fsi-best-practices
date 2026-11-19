# Windows client validation kit (W2)

A test kit that a person runs on a **Windows 11 client with Kiro IDE installed**, to record what Kiro actually does there: the system-wide installer, the admin policy, global hooks, global steering and the Intune execution contexts. It is a defensive validation kit for the endpoint guardrails in this repository. It tracks GitHub issue #43.

> **Last verified:** 2026-11-19 against the official Kiro documentation: [permission policies](https://kiro.dev/docs/enterprise/governance/permissions/), [sign-in controls](https://kiro.dev/docs/enterprise/governance/sign-in/), [hooks](https://kiro.dev/docs/hooks/), [hook types](https://kiro.dev/docs/hooks/types/), [hook actions](https://kiro.dev/docs/hooks/actions/), [steering](https://kiro.dev/docs/steering/), [managed updates](https://kiro.dev/docs/enterprise/managed-updates/), [installation](https://kiro.dev/docs/getting-started/installation/) and [IDE troubleshooting](https://kiro.dev/docs/ide/troubleshooting/). Items marked *(verify)* are not documented by Kiro or Microsoft; recording them is the purpose of this kit.
>
> **Test devices only.** Several switches install software, deploy the admin policy and tamper with it. Do not run the kit on a device that somebody works on.
>
> **Stop if the device already carries an organisation policy.** The kit is for a clean test device. Do not continue if one of these exists before your first run:
>
> - `C:\ProgramData\Kiro\` (the policy `managed-settings.json`, the staged sources in `deploy\`, the hook guards in `hooks\`);
> - the registry key `HKLM\SOFTWARE\Policies\Kiro` (`UpdateMode`, `UpdateUrl`, `AuthPortalUrl`);
> - `.kiro\hooks\banking-guards.windows.json` in a user profile or in `C:\Users\Default`.
>
> On such a device `-InstallPolicy` would replace the organisation's policy with the sample from this repository, and the clean-up would remove the policy and turn updates back on. [Step 2](#elevated-session) of the run order is the check.
>
> **Status (2026-11-19): this kit has not yet been run on a Windows 11 client.** Only the SYSTEM path of `Invoke-W2Checks.ps1` was executed (`-InstallerPath -Install -ExpectedSignerSubject -InstallPolicy -Wrappers -TamperTest`, in some runs with `-InstallerArgs`, and `-InstallerPath -ExpectedSignerSubject` under PowerShell 7), on Windows Server 2022 in the integration phase WC ([evidence](../../kiro-docs/aws-integration-test-evidence.md#wc--kiro-installer-mechanics-windows-runner-system)). Never executed: `hook-probe.ps1`, `-InstallProbes`, `-ReadProbes`, `-RemoveProbes`, `-UserContext`, `-NoSanitize`, the elevated-administrator path with the `KiroW2-<id>` scheduled tasks, every run as a standard user, the manual checklist, and the sanitizer's replacements (no output line of those runs held a user name, a computer name or an account SID, so nothing was replaced).
>
> The PowerShell snippets on this page (the folder lock-down, the clean-device check, the `Invoke-W2AsSystem` helper, the clean-up) were written without a Windows machine and have not been executed either. Read them before you run them.

## Why W2 exists

The integration test in [`../aws-integration/`](../aws-integration/README.md) runs the MDM script, the Intune wrappers and the PowerShell hook guards on **Windows Server 2022 as SYSTEM** (phases W1, W3 and W4, without a Kiro client). Its opt-in phase WC also installed Kiro IDE 1.4.236 there with the system-wide installer and measured the installer mechanics; Kiro was never opened or signed in. The evidence page says so in its section "Coverage: what was and was not tested" ([`kiro-docs/aws-integration-test-evidence.md`](../../kiro-docs/aws-integration-test-evidence.md#coverage-what-was-and-was-not-tested)). Not tested there:

- Kiro IDE or Kiro CLI that somebody opens or signs in to, and the system-wide installer on Windows 10/11 and on ARM64;
- a Windows 10/11 client;
- a logged-on standard user;
- Kiro reading `C:\ProgramData\Kiro\managed-settings.json`, loading global hooks or loading global steering.

Everything the Windows and Intune documentation in this repository says about those points comes from Kiro's documentation or is marked *(verify)*, except the installer values that phase WC measured on Windows Server 2022 ([runbook, section 1](../../kiro-docs/intune-deployment.md#1-kiro-ide-per-user-vs-system-wide-installer)). W2 replaces the markers with observed values and repeats the installer checks on Windows 11.

## Contents

| File | Purpose |
|------|---------|
| [`Invoke-W2Checks.ps1`](Invoke-W2Checks.ps1) | The automated checks. Windows PowerShell 5.1 and PowerShell 7 |
| [`hook-probe.ps1`](hook-probe.ps1) | A hook that logs which client and which process chain called it. Used for W2.7 and W2.8 |
| [`W2-manual-checklist.md`](W2-manual-checklist.md) | The checks that need a signed-in Kiro window, with a result block for each |
| [`../aws-integration/windows-client-suite.ps1`](../aws-integration/windows-client-suite.ps1) | Runs the automatable part on the Windows Server 2022 runner of the integration test ([last section](#optional-the-client-stage-of-the-integration-test)) |

## Test environment

| Item | Requirement |
|------|-------------|
| Device | A disposable **Windows 11 Enterprise** client (for example a virtual machine with a snapshot), or a **BYOL Windows 11** Amazon WorkSpace. Do not use the AWS-provided Windows WorkSpaces bundles: they run Windows Server, which would repeat the gap of the integration test. On a Windows Server OS the script reports `W2.0.os` as INFO "outside Kiro's listed operating systems (Windows 10/11)" |
| Clean device | No `C:\ProgramData\Kiro`, no `HKLM\SOFTWARE\Policies\Kiro` and no `banking-guards.windows.json` in a user profile or in `C:\Users\Default` before the test (step 2 checks this). The device must not be targeted by a Kiro policy app or a Remediations package of your organisation: Intune would deploy over the test, and the kit would replace or remove what Intune deployed |
| Developer account | A **standard user** without local administrator rights. Check in that user's session: `whoami /groups` must not list `BUILTIN\Administrators` (S-1-5-32-544). The script reports the same in `W2.0.context`. On a WorkSpace the directory can make users local administrators; turn that off before you create the WorkSpace *(verify in the WorkSpaces directory settings)* |
| Administrator account | A second account that can open an elevated PowerShell window |
| Kiro IDE | **1.4.62 or later, system-wide build**. 1.4.62 is the first release with a Windows system-wide installer ([changelog](https://kiro.dev/changelog/ide/1-4-62/)). Download it from kiro.dev yourself; the script does not download anything |
| Kiro CLI | Optional: **3.x**, for the CLI parts of W2.7 to W2.9. Kiro lists Windows 11 with Windows Terminal or PowerShell for the CLI ([installation](https://kiro.dev/docs/getting-started/installation/)) |
| Kiro account | A test account that can sign in with the method the policy permits. The bundled policy permits only IAM Identity Center (`idc`) |
| Intune | Not needed. The kit starts the scripts in the contexts Intune uses: 64-bit SYSTEM, 32-bit SYSTEM and the logged-on user |

## Safety: what each switch changes and how to undo it

With no action switch the script only reads, and writes its results to `-OutDir`. Before each change outside `-OutDir` it prints one `ACTION` line that says what it is about to do.

| Switch | What it changes | Undo |
|--------|-----------------|------|
| (none) | Nothing outside `-OutDir`. Read-only inventory. An elevated or SYSTEM run sets the owner and the ACL of `-OutDir` (Administrators; SYSTEM and Administrators only) | - |
| `-InstallerPath <exe>` | Nothing. Reads the file (signature, hash, version) | - |
| `-Install` | Runs the installer silently: installs Kiro IDE for all users. Writes `<OutDir>\kiro-install.log`. The installer is started only in an elevated or SYSTEM session, with `-InstallerPath`, and only when W2.2 passed: `W2.2.signature` is PASS and, when `-ExpectedSignerSubject` is given, `W2.2.signer` is PASS. Otherwise `W2.1.install` is SKIP and nothing is installed. The kit does not stop Kiro processes that the installer leaves running; it lists them in `W2.1.install` and in a `NOTE` line | Uninstall Kiro: **Settings > Apps > Installed apps** ([installation](https://kiro.dev/docs/getting-started/installation/)), or the uninstall command that `W2.1.uninstall-entry` recorded. Stop left-over Kiro processes or restart the device before the manual steps |
| `-InstallPolicy` | Elevated or SYSTEM only. Runs `mdm\lockdown-windows.ps1 -StageSources -DeployHooks -InstallUser -DisableUpdates` from `-RepoDir`: writes `C:\ProgramData\Kiro\managed-settings.json` with a locked ACL, the hook guards in `C:\ProgramData\Kiro\hooks\`, the staged sources in `C:\ProgramData\Kiro\deploy\`, `.kiro\hooks\banking-guards.windows.json` in every local user profile and in `C:\Users\Default`, and `UpdateMode=none` under `HKLM\SOFTWARE\Policies\Kiro`. **A policy that is already there is replaced.** The result is the line `W2.5.policy-file:install` | `mdm\lockdown-windows.ps1 -RemoveSources` removes only `deploy\`. For the rest see [Clean up](#clean-up) |
| `-Wrappers` | Copies the three Intune wrappers to `<OutDir>\wrappers\`, with `$Options` set to `-DeployHooks -InstallUser -DisableUpdates` and the log file set to `<OutDir>\wrappers\<wrapper name>.log`, and runs them. The Intune log folder of the device is not written to. From an elevated session that is not SYSTEM the script registers one-shot scheduled tasks named `KiroW2-<id>` that run as SYSTEM, and removes each task after its run. In the SYSTEM contexts, without `-TamperTest`, only the two detection wrappers run, and they only read | Delete `<OutDir>`. If a run was interrupted, look for a leftover task with `Get-ScheduledTask -TaskName 'KiroW2-*'` and remove it with `Unregister-ScheduledTask` |
| `-TamperTest` | With `-Wrappers`, elevated or SYSTEM only, and only when the detection wrapper reported the device as compliant first. For each SYSTEM context it removes the Users DENY entry from `C:\ProgramData\Kiro\managed-settings.json` and appends one space, then runs the remediation wrapper, which deploys the policy, the hook files and `UpdateMode` again from the staged sources. If the policy file is not as before at the end, the script runs the staged `lockdown-windows.ps1` itself, and reports FAIL on `detect-after-remediate` if that does not restore it either | If the run was interrupted, run the script again with `-InstallPolicy` |
| `-UserContext` | Nothing. For the logged-on standard user: `-Install` and `-InstallPolicy` are skipped, and `-Wrappers` runs the context `user` instead of the two SYSTEM contexts (the remediation wrapper is started as the standard user and must be refused). The inventory, W2.4 and `W2.5.policy-file` run as in every other run | - |
| `-InstallProbes` | In the **current user's** profile: `%LOCALAPPDATA%\KiroW2\hook-probe.ps1`, `%USERPROFILE%\.kiro\hooks\w2-probe.json` and `%USERPROFILE%\.kiro\steering\w2-steering-probe.md`. From then on a Kiro client that loads global hooks starts the probe for every tool call of that user (one PowerShell start per call), and the steering sentence is part of that user's Kiro context. The switch reports INFO lines only (`W2.7.probe`, `W2.8.probe`, `W2.9.probe` with the steering marker). It is refused as SYSTEM (`W2.7.probe` SKIP): SYSTEM has no Kiro session | `-RemoveProbes` |
| `-ReadProbes` | Nothing. Reads `%LOCALAPPDATA%\KiroW2\hook-probe.log` and the steering marker | - |
| `-RemoveProbes` | Deletes the three files that `-InstallProbes` wrote, and only if they carry the kit's marker. It keeps `%LOCALAPPDATA%\KiroW2\hook-probe.log` as evidence | Delete `%LOCALAPPDATA%\KiroW2` by hand after you saved the evidence |
| `-NoSanitize` | Nothing on the device. The output then keeps the computer name, domain name, user names and SIDs, and is appended to `w2-results-UNSANITIZED.txt` instead of `w2-results.txt` | Do not publish that output or that file |

Other parameters, none of which changes the device:

| Parameter | Meaning |
|-----------|---------|
| `-OutDir <path>` | Folder for `w2-results.txt`, `kiro-install.log` and `wrappers\`. Default: `C:\ProgramData\KiroW2` when elevated or SYSTEM, otherwise `%LOCALAPPDATA%\KiroW2`. An elevated or SYSTEM run sets the owner and the ACL of this folder on every run, also when it already exists (Administrators as owner; SYSTEM and Administrators only; no inheritance): never name a folder that holds other data |
| `-RepoDir <path>` | Repository root. Default: two levels above the script. `-InstallPolicy` and `-Wrappers` take `mdm\lockdown-windows.ps1` and `mdm\intune\` from it |
| `-InstallerArgs <string>` | Replaces the default installer switches `/VERYSILENT /SP- /SUPPRESSMSGBOXES /NORESTART /MERGETASKS=!runcode /LOG="<OutDir>\kiro-install.log"` |
| `-InstallTimeoutMinutes <n>` | Time limit for the installer. Default 15; after it the installer process is stopped and `W2.1.install` is FAIL |
| `-ExpectedSignerSubject <subject>` | `W2.2.signer` is FAIL unless the signer subject of the installer equals this text (case-sensitive; double quotes are ignored on both sides, because they do not survive every command line). Without it `W2.2.signer` is INFO |

Further points:

- **Probe-only runs.** A run with only probe switches (`-InstallProbes`, `-ReadProbes`, `-RemoveProbes`; none of `-InstallerPath`, `-Install`, `-InstallPolicy`, `-Wrappers`, `-TamperTest`, `-UserContext`) prints the run header, the three `W2.0` checks and the probe checks. The inventory, W2.4 and W2.5 are not run.
- **The probe logs no content.** `hook-probe.ps1` records the UTC time, the hook event name, the tool name, whether the hook input could be read, whether the call was a block test, the PowerShell edition, version and bitness, and the names of its parent processes (up to 6 levels). It does not log `tool_input`, command lines or user names. It always exits 0, with one exception: a command that contains the text `W2-BLOCK-TEST` makes it exit 2 (used for W2.8). It stops appending once `hook-probe.log` is larger than 5 MB.
- **The kit does not overwrite other files.** `-InstallProbes` refuses (`W2.7.probe` SKIP) to overwrite a file it did not create, and refuses when `%LOCALAPPDATA%\KiroW2`, `.kiro`, `.kiro\hooks` or `.kiro\steering` is a junction or symbolic link.
- **Keep the kit where a standard user cannot change it.** Parts of the kit run elevated or as SYSTEM, so a copy that the standard user can edit would let that user run code as SYSTEM. Step 1 creates a locked folder. The script protects its output folder itself: an elevated or SYSTEM run refuses an existing `-OutDir` that a non-administrator owns or controls (`CHECK W2.0.context FAIL refusing to use the output folder`), and sets the owner and the ACL of the folder on every such run.
- **The simplest undo is to discard the device:** restore the snapshot or rebuild the WorkSpace.

## Run order

Two PowerShell windows are used: an **elevated** one (administrator account, "Run as administrator") and a normal one in the **standard user's** Windows session. Use 64-bit Windows PowerShell 5.1 unless a step says otherwise.

Results: an elevated or SYSTEM run writes to `C:\ProgramData\KiroW2\`, a standard-user run to `%LOCALAPPDATA%\KiroW2\`. Each run appends to `w2-results.txt` in that folder.

### Elevated session

1. **Create a locked kit folder and copy the files.** In the elevated window, paste the block as a whole. It is one statement: it stops when the folder already exists, because a folder that somebody else created can have another owner.

   ```powershell
   if (Test-Path -LiteralPath 'C:\KiroW2Kit') {
     throw 'C:\KiroW2Kit already exists: remove it as an administrator or choose another name'
   } else {
     New-Item -ItemType Directory -Path 'C:\KiroW2Kit' -ErrorAction Stop | Out-Null
     icacls 'C:\KiroW2Kit' /setowner "*S-1-5-32-544"
     icacls 'C:\KiroW2Kit' /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"
   }
   ```

   `icacls C:\KiroW2Kit` must then list only SYSTEM and Administrators with full control and Users with read and execute. Copy the repository to `C:\KiroW2Kit\repo` (a fresh `git clone`, which keeps the LF line endings that `agent-hooks\SHA256SUMS` needs) and the Kiro installer to `C:\KiroW2Kit\<installer>.exe`. Then set two variables for the following steps:

   ```powershell
   $W2 = 'C:\KiroW2Kit\repo\security-tests\windows-client\Invoke-W2Checks.ps1'
   $Ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
   ```

2. **Baseline inventory and clean-device check** (read-only).

   ```powershell
   & $Ps -NoProfile -ExecutionPolicy Bypass -File $W2
   Test-Path -LiteralPath 'C:\ProgramData\Kiro'                                          # must print False
   Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\Kiro'                                 # must print False
   Test-Path -LiteralPath 'C:\Users\Default\.kiro\hooks\banking-guards.windows.json'    # must print False
   ```

   On a clean device the run ends with `fail=1` and exit code 1, because `W2.5.policy-file` is FAIL with "not found"; that is expected here. `W2.4.updatemode` must say "key not present" for both registry views.

   **Stop here** if `W2.5.policy-file` reports anything else, if `W2.4.updatemode` shows a key or a value, or if one of the three lines prints `True`. The device then carries a policy that this kit did not deploy; see the note at the top of this page. The only exception is a device on which you ran this kit before and have not cleaned up yet.

3. **W2.2: installer signature.** Nothing is installed.

   ```powershell
   & $Ps -NoProfile -ExecutionPolicy Bypass -File $W2 -InstallerPath 'C:\KiroW2Kit\<installer>.exe'
   ```

   Continue only if `W2.2.signature` is PASS (status `Valid`) and `W2.2.signer` names the publisher you expect. `Valid` alone is not a publisher check ([runbook, section 1](../../kiro-docs/intune-deployment.md#1-kiro-ide-per-user-vs-system-wide-installer)). Record the signer subject.

4. **W2.3 (optional, fresh device only).** If you want to test a device that already has the per-user build, do steps 1 to 4 of [checklist section W2.3](W2-manual-checklist.md#w23-per-user-build-then-system-wide-build) now, before Kiro is installed system-wide.

### SYSTEM contexts

Intune installs a Win32 app as SYSTEM. To run the whole script as SYSTEM without extra tools, define this helper in the elevated window. It registers a one-shot scheduled task, waits for it and removes it:

```powershell
function Invoke-W2AsSystem([string]$KitArgs) {
  $task = 'KiroW2-AsSystem'
  $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$W2`" $KitArgs"
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $task -User 'SYSTEM' -RunLevel Highest -Force -Settings $settings `
    -Action (New-ScheduledTaskAction -Execute $Ps -Argument $arg) | Out-Null
  try {
    Start-ScheduledTask -TaskName $task
    do { Start-Sleep -Seconds 5 } while ((Get-ScheduledTask -TaskName $task).State -eq 'Running')
    "task result: $((Get-ScheduledTaskInfo -TaskName $task).LastTaskResult)"
  } finally {
    Unregister-ScheduledTask -TaskName $task -Confirm:$false
  }
  Get-Content -LiteralPath 'C:\ProgramData\KiroW2\w2-results.txt' -Tail 40
}
```

The task result is the script's exit code: 0, or 1 when a check failed.

5. **W2.1: silent install as 64-bit SYSTEM.** Put the signer subject from step 3 between the double quotes, **without the double quotes it contains**: write `CN="Amazon.com, Inc.", OU=AWS Kiro, ...` as `CN=Amazon.com, Inc., OU=AWS Kiro, ...`. The subject of the Kiro installer contains double quotes, which do not survive this command line, so the script ignores double quotes when it compares. The default installer switches are `/VERYSILENT /SP- /SUPPRESSMSGBOXES /NORESTART /MERGETASKS=!runcode /LOG="<OutDir>\kiro-install.log"`. They are Inno Setup switches that Kiro does not document *(verify)*; whether they work is one of the things this step records. `/MERGETASKS=!runcode` is there because, without it, the 1.4.236 installer, run as SYSTEM, started Kiro as SYSTEM in session 0 when it ended (measured on Windows Server 2022; see the [evidence page](../../kiro-docs/aws-integration-test-evidence.md#wc--kiro-installer-mechanics-windows-runner-system)). Use `-InstallerArgs` to try others and `-InstallTimeoutMinutes` (default 15) for a slow device.

   ```powershell
   Invoke-W2AsSystem '-InstallerPath C:\KiroW2Kit\<installer>.exe -Install -ExpectedSignerSubject "<signer subject without its double quotes>"'
   ```

   `W2.2.signer` must be PASS ("the signer subject equals -ExpectedSignerSubject (double quotes ignored)"). On FAIL the installer is not started; compare the two subjects in the line.

   Read the `W2.1.install` line. `SKIP ... refused` means the installer was not started because W2.2 did not pass. The detail ends with "Kiro processes started during the install and still running". If it names a process, a `NOTE` line says so too: stop those processes or restart the device before the manual steps (as SYSTEM they run in session 0, where the standard user does not see them).

   Without SYSTEM (a weaker test, because Intune uses SYSTEM), the same from the elevated window:

   ```powershell
   & $Ps -NoProfile -ExecutionPolicy Bypass -File $W2 -InstallerPath 'C:\KiroW2Kit\<installer>.exe' -Install -ExpectedSignerSubject '<signer subject without its double quotes>'
   ```

6. **Inventory after the install** (elevated window). Records the Uninstall registry entries and their registry view, the install folder, `Kiro.exe`, PATH and the Start Menu.

   ```powershell
   & $Ps -NoProfile -ExecutionPolicy Bypass -File $W2
   ```

7. **Deploy the policy, then W2.10 for the two SYSTEM contexts** (elevated window). Do this only on a device that passed the check of step 2. If the Kiro test account needs your own Identity Center start URL, first put it into `managed-settings\managed-settings.banking.json` of the copy on the device; never commit that edit. With `-Wrappers` the script starts the `system64` and `system32` contexts itself, each through a one-shot scheduled task that runs as SYSTEM.

   ```powershell
   & $Ps -NoProfile -ExecutionPolicy Bypass -File $W2 -InstallPolicy -Wrappers
   & $Ps -NoProfile -ExecutionPolicy Bypass -File $W2 -Wrappers -TamperTest
   ```

   In the first run `W2.5.policy-file:install` must be PASS (it shows the exit code and the last output line of `lockdown-windows.ps1`), and `W2.5.policy-file` and `W2.4.updatemode` then show the deployed state. To run the wrapper checks with the script itself as SYSTEM instead:

   ```powershell
   Invoke-W2AsSystem '-Wrappers -TamperTest'
   ```

### Standard user

Sign in to Windows as the standard user (a real sign-in, not "Run as"), open a normal PowerShell window and set:

```powershell
$W2 = 'C:\KiroW2Kit\repo\security-tests\windows-client\Invoke-W2Checks.ps1'
```

8. **User-context checks and W2.10 for the logged-on user.** This repository has no per-user wrappers. The kit runs the policy wrappers as the standard user to record what happens when an Intune script is set to run with the logged-on credentials: the detection result is recorded as INFO, and the remediation must fail without changing the policy file.

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File $W2 -UserContext -Wrappers
   ```

9. **Checklist, first part: sections W2.1, W2.4, W2.5 and W2.6** of [`W2-manual-checklist.md`](W2-manual-checklist.md), in the Kiro window. The probes are **not** installed yet, and sections W2.5 and W2.6 rename the hook guard file of the standard user for the time of the test: a refusal must come from the admin policy alone. Section W2.6 needs the elevated window again.

10. **Install the probes** for W2.7, W2.8 and W2.9. The script prints the steering marker (`W2-STEERING-<8 hex>`) in the `W2.9.probe` line; note it. Restart Kiro afterwards.

    ```powershell
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File $W2 -InstallProbes
    ```

11. **Checklist, second part: sections W2.7, W2.8 and W2.9.**

12. **Read the probes.** Run it whenever a checklist step asks for it, and once at the end.

    ```powershell
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File $W2 -ReadProbes
    ```

13. **Save the evidence, then remove the probes.** Copy `%LOCALAPPDATA%\KiroW2\w2-results.txt` and `hook-probe.log` to your evidence folder first. `-RemoveProbes` keeps `hook-probe.log`.

    ```powershell
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File $W2 -RemoveProbes
    ```

### Clean up

14. In the elevated window, copy `C:\ProgramData\KiroW2\` to your evidence folder. Then discard the device, or undo the changes.

    **Test device only.** The five lines below remove the admin policy and the hook guards and turn Kiro updates back on. Never run them on a device whose policy was deployed by your organisation (see the note at the top of this page).

    ```powershell
    & $Ps -NoProfile -ExecutionPolicy Bypass -File C:\KiroW2Kit\repo\mdm\lockdown-windows.ps1 -RemoveSources
    icacls C:\ProgramData\Kiro /remove:d *S-1-5-32-545 /T /C
    Remove-Item -LiteralPath C:\ProgramData\Kiro -Recurse -Force
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Kiro' -Name 'UpdateMode'
    $k = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Policies\Kiro'; if ($k.ValueCount -eq 0 -and $k.SubKeyCount -eq 0) { Remove-Item -LiteralPath 'HKLM:\SOFTWARE\Policies\Kiro' }
    ```

    `-RemoveSources` removes only `C:\ProgramData\Kiro\deploy\`; the other four lines remove the policy, the hook guards, `UpdateMode` and, when nothing else is in it, the key `HKLM\SOFTWARE\Policies\Kiro`, which the clean-device check of step 2 looks for ([runbook, section 3](../../kiro-docs/intune-deployment.md#3-the-kiro-policy-win32-app)). Also delete `.kiro\hooks\banking-guards.windows.json` in each user profile and in `C:\Users\Default`, uninstall Kiro, and delete `C:\ProgramData\KiroW2`, `%LOCALAPPDATA%\KiroW2` and `C:\KiroW2Kit`.

## Output

The script writes four kinds of lines to STDOUT:

| Line | Meaning |
|------|---------|
| `NOTE <text>` | Context. The first line of every run is the run header: `NOTE W2 run <UTC time>; switches: <switches given>; output folder: <path>; sanitized=<True or False>`. Other `NOTE` lines are remarks, for example that the installer left Kiro processes running or that the policy file was restored after the tamper test |
| `ACTION <text>` | Printed before a change outside `-OutDir`: the installer, `-InstallPolicy`, the scheduled tasks of `-Wrappers`, each tamper of `-TamperTest` (and a restore after it, if one is needed), `-InstallProbes` and `-RemoveProbes` |
| `CHECK <id> <STATUS> <detail>` | One line per check. `PASS` and `FAIL` are verdicts. `SKIP` means the check did not apply, its switch was not given or the step was refused. `INFO` is a fact to record, for example a value Kiro does not document; it is never a verdict |
| `PHASE W2 RESULT pass=<n> fail=<n> skip=<n> info=<n>` | The last line. It counts the `CHECK` lines; `NOTE` and `ACTION` lines are not counted |

- The same lines are appended to `<OutDir>\w2-results.txt`. A `-NoSanitize` run appends to `<OutDir>\w2-results-UNSANITIZED.txt` instead, so `w2-results.txt` only holds sanitized lines. `-OutDir` defaults to `C:\ProgramData\KiroW2` when elevated or SYSTEM, otherwise to `%LOCALAPPDATA%\KiroW2`.
- Exit code 1 if any check is FAIL, otherwise 0.
- If the script cannot start its work, it prints one `CHECK ... FAIL` line and `PHASE W2 RESULT pass=0 fail=1 skip=0 info=0` on STDOUT only, and exits 1: `W2.0.powershell` when PowerShell runs in Constrained Language Mode, `W2.0.context` when the output folder cannot be used or is refused, or when the sanitizer cannot be built.
- `-RepoDir` defaults to the repository root, two levels above the script.
- SIDs, user names, the computer name and the domain name are replaced with `<sid>`, `<user>`, `<computer>` and `<domain>` unless `-NoSanitize` is given. The replacement is a best effort: a user or domain name that is shorter than three characters or is also an ordinary word of the output (for example an account called `tw` or `admin`) is replaced only inside a profile path, with no `NOTE`; a computer name of that kind (for example `TEST`) is not replaced, and a `NOTE` line says so. The Start Menu search does not enter a junction at or below a `Start Menu\Programs` folder; a link in one of its parent folders inside the profile is not detected (the search only reads, and stops four levels down). Check the output by hand before you publish it.

## Coverage: issue checks W2.1 to W2.11

| Issue check | Automated by the script (check IDs) | Manual ([checklist](W2-manual-checklist.md) section) |
|-------------|-------------------------------------|------------------------------------------------------|
| W2.1 Silent system-wide install as 64-bit SYSTEM | `W2.1.install` (with `-Install`); `W2.1.uninstall-entry:hklm64`, `:hklm32`, `:hkcu`, `:hku` (one line per Uninstall entry, named after the registry view it was found in; plain `W2.1.uninstall-entry` SKIP when there is none); `W2.1.install-folder`, `W2.1.exe`, `W2.1.path`, `W2.1.start-menu` | W2.1: the standard user can launch Kiro |
| W2.2 Authenticode signature of the installer | `W2.2.signature`, `W2.2.signer`, `W2.2.sha256` (with `-InstallerPath`) | - |
| W2.3 Per-user build, then the system build | `W2.3.per-user-build` (inventory of both locations) | W2.3: what stays installed, what carries over, the migration order tried |
| W2.4 `UpdateMode = none` | `W2.4.updatemode` (64-bit and 32-bit registry view; INFO, or FAIL if they differ) | W2.4: what Help > About shows |
| W2.5 Valid policy read by Kiro IDE | `W2.5.policy-file:install` (with `-InstallPolicy`: the result of the deployment); `W2.5.policy-file` (the file only: exists, no BOM, parses, rule count, Users DENY ACE; in a run that is not elevated also that this account cannot open the file for writing) | W2.5: no warning, a denied command, the sign-in screen, Windows rules |
| W2.6 Invalid policy file | - (`W2.5.policy-file` can confirm the planted file and the restore) | W2.6: BOM, malformed JSON, unknown capability |
| W2.7 Global hooks | `W2.7.probe` (with `-ReadProbes`: calls per client, from the probe log; also the result line of `-InstallProbes` and `-RemoveProbes`) | W2.7: Kiro IDE and Kiro CLI V3 |
| W2.8 Hook shell and exit code 2 | `W2.8.probe` (distinct parent process chains, PowerShell edition and bitness of the probe) | W2.8: the `W2-BLOCK-TEST` marker and a guard from issue #42 |
| W2.9 Global steering, also for a new profile | `W2.9.probe` (repeats the marker) | W2.9: Steering panel and marker, current user and a user created later |
| W2.10 Detect and Remediate wrappers in the Intune contexts | `W2.10.system64.*`, `W2.10.system32.*`, `W2.10.user.*` (with `-Wrappers`) | - |
| W2.11 W1 asserts the Intune-facing exit codes | - | - |

W2.11 is **already covered by the integration test (W4, issue #42)**: W4 runs the three wrappers from 64-bit and 32-bit PowerShell and asserts their Intune-facing exit codes and output streams ([evidence](../../kiro-docs/aws-integration-test-evidence.md)).

The environment checks `W2.0.os`, `W2.0.powershell` and `W2.0.context` belong to every run.

Steps of W2.10 per context:

| Context | Steps |
|---------|-------|
| `system64`, `system32` | `detect-compliant`, `win32-detected`; with `-TamperTest` also `detect-drift`, `win32-not-detected`, `remediate`, `detect-after-remediate` |
| `user` | `detect` (INFO: the exit code and the first output line), `remediate-refused` (PASS when the remediation wrapper exits 1 and the hash of the policy file is unchanged) |

A context or step that cannot run is reported as SKIP on its first step: the SYSTEM contexts in a session that is not elevated, `W2.10.user.detect` in an elevated or SYSTEM session, the tamper steps when the device was not compliant before them.

## Recording evidence

- **Results files.** Keep `w2-results.txt` from `C:\ProgramData\KiroW2\` and from the standard user's `%LOCALAPPDATA%\KiroW2\`, plus `hook-probe.log` and `kiro-install.log`. The files are appended to on every run, so note the order of your runs; each run starts with its `NOTE W2 run` header. Do not publish `w2-results-UNSANITIZED.txt`.
- **Manual steps.** Take one screenshot per checklist step that asks for it and name it after the check, for example `W2.5-03-denied.png`. Write the file name into the result block of that section.
- **Fill in the checklist.** Each section has a result block (date, Kiro IDE version, Windows build, PASS / FAIL / observed value, evidence file name). The last page is a summary table for the evidence page.
- **Remove before publishing.** The script masks SIDs, user names, the computer name and the domain name in its own output only. Check every file and screenshot by hand for:
  - user names, also inside paths such as `C:\Users\<name>` and in window titles;
  - device and host names;
  - tenant and organisation names, the Identity Center start URL and directory ID, AWS account IDs;
  - account e-mail addresses (the Kiro account menu and the sign-in page show them);
  - licence keys and product keys;
  - IP addresses.
- `kiro-install.log` is written by the installer and is not masked. The wrapper logs in `<OutDir>\wrappers\` hold the full output of `lockdown-windows.ps1`, including profile paths, and are not masked either. Kiro warns that its own logs can contain file paths, code and account IDs ([IDE troubleshooting](https://kiro.dev/docs/ide/troubleshooting/)); do not publish raw Kiro logs.
- Raw results stay outside the repository. Only the reviewed summary is committed.

## Where confirmed values go

After a run, update the documentation in the same pull request (the "Docs move with the change" rule in [`AGENTS.md`](../../AGENTS.md)). The table lists every place that holds a statement the check settles. "Runbook" is [`kiro-docs/intune-deployment.md`](../../kiro-docs/intune-deployment.md).

| Check | Observed value (from) | Places to update |
|-------|-----------------------|------------------|
| W2.1 | Whether the silent switches work, the install folder, `Kiro.exe`, the uninstall command, the registry view of the Uninstall entry (`W2.1.install`, `W2.1.install-folder`, `W2.1.exe`, `W2.1.uninstall-entry:<view>`); the standard user can launch Kiro (checklist W2.1) | Runbook section 1: the Win32 app settings table (install command, uninstall command, detection rule) and "Registry detection rules and the 32-bit view"; runbook pilot checklist, first item; runbook open question 1. [`kiro-docs/mdm-endpoint-enforcement.md`](../../kiro-docs/mdm-endpoint-enforcement.md), "Windows: per-user vs system-wide installer". [Part 1](../../Kiro-Agentic-SDLC-Banking-Best-Practices.md), section 4.2.3 |
| W2.2 | Signer subject of the installer (`W2.2.signer`) | Runbook section 1, "Get and check the installer before packaging"; runbook pilot checklist (signature item) |
| W2.3 | Per-user and system-wide builds side by side, migration order (`W2.3.per-user-build`, checklist W2.3) | Runbook section 1, "Devices that already have the per-user build"; runbook pilot checklist (signature and migration item); runbook open question 9 |
| W2.4 | What Help > About and "Check for Updates" show with `UpdateMode=none` (checklist W2.4) | Runbook pilot checklist (`UpdateMode=none` item) and runbook section 2 |
| W2.5 | Kiro IDE on Windows enforces the policy and the sign-in restriction; case and alias handling of shell rules (checklist W2.5) | Runbook: the "What was tested, and what was not" note and the pilot checklist (policy item and Windows rules item). [`managed-settings/README.md`](../../managed-settings/README.md), "Windows rules": the bullets "Two spellings" and "Aliases are listed, not resolved" and the paragraph that starts "Unverified" |
| W2.6 | Behaviour and wording of the warning with an invalid file (checklist W2.6) | [`managed-settings/README.md`](../../managed-settings/README.md#failure-behaviour), "Failure behaviour"; runbook pilot checklist (policy item, the sentence about the warning) |
| W2.7 | Whether Kiro IDE loads global hooks (`W2.7.probe`, checklist W2.7) | Runbook section 5 ("Surface"), pilot checklist (hooks item) and open question 2. [`agent-hooks/README.md`](../../agent-hooks/README.md), "Windows pilot items". [`kiro-docs/agent-runtime-governance.md`](../../kiro-docs/agent-runtime-governance.md): the sentence "whether Kiro IDE loads them on Windows is a pilot item". The header of [`mdm/lockdown-windows.ps1`](../../mdm/lockdown-windows.ps1), `-InstallUser` paragraph |
| W2.8 | Which shell runs hook commands; whether exit 2 blocks (`W2.8.probe`, checklist W2.8) | Runbook section 5 ("Shell"), pilot checklist (hooks item) and open question 3. [`agent-hooks/README.md`](../../agent-hooks/README.md), "Windows pilot items". [`kiro-docs/mdm-endpoint-enforcement.md`](../../kiro-docs/mdm-endpoint-enforcement.md), "Platform notes", Windows |
| W2.9 | Global steering is loaded; steering and hook file for a user created later; owner of the hook file (checklist W2.9) | Runbook section 5: "Editable by the user" and the row "Reaches" of the table "Which context for per-user files"; pilot checklist (per-user files item); open question 10 |
| W2.10 | The wrappers as a standard user (`W2.10.user.*`); the wrappers as 64-bit and 32-bit SYSTEM on a Windows 11 client (`W2.10.system64.*`, `W2.10.system32.*`) | Runbook section 4 (the row "Run this script using the logged-on credentials") and the table "Which context for per-user files" |
| All | The validation scope: what was run on a Windows 11 client, and when | [`README.md`](../../README.md), "Validation scope" note. Runbook, "What was tested, and what was not" note. [`kiro-docs/aws-integration-test-evidence.md`](../../kiro-docs/aws-integration-test-evidence.md): a new section, the column "Windows 10/11 client" of the coverage table and the paragraph about issue #43 below that table. [`security-tests/aws-integration/README.md`](../aws-integration/README.md), "Not covered by any phase". [`CHANGELOG.md`](../../CHANGELOG.md) |

In each place remove the matching *(verify)* marker or "pilot item" wording, or replace it with what was observed, and set the row of the runbook's **Open questions** table to answered with the date.

W2 does not settle these, so their markers stay: the per-user build deployed in System context, the effect of blocking `prod.download.desktop.kiro.dev` on Powers, the delivery of the Kiro CLI `update.baseUrl` policy by Intune, the Win32 app re-evaluation interval, what Intune itself does when a script runs with the logged-on credentials, application control (WDAC, AppLocker), how a custom agent references global steering, and in `managed-settings/README.md` the points about `~` and `\` in filesystem patterns, `cmd.exe` command lines and headless runs.

The new section in the evidence page can be called "Run of <date>: Windows 11 client (W2)". It holds the Windows edition and build, the Kiro IDE and CLI versions, the summary table from the checklist and the reviewed `CHECK` lines.

Last step: search the repository for the old wording, as `AGENTS.md` requires, for example:

```bash
grep -rn 'verify)' --include='*.md' .
grep -rn -i 'pilot item\|issue #43\|not documented by Kiro' --include='*.md' --include='*.ps1' .
```

## Optional: the client stage of the integration test

`run-integration.sh` has an opt-in stage `client` (phase WC). It is never part of `all`. It runs [`windows-client-suite.ps1`](../aws-integration/windows-client-suite.ps1) on the disposable Windows Server 2022 runner, as SYSTEM through AWS Systems Manager:

- it reads Kiro's update manifest, downloads the current system-wide installer (the URL must be on `prod.download.desktop.kiro.dev`) and records its version, size and SHA-256 (`WC.manifest`, `WC.download`);
- it runs this kit with `-InstallerPath -InstallPolicy -Wrappers -TamperTest`, and adds `-Install` and `-ExpectedSignerSubject` only when the Authenticode status of the installer is `Valid` and its signer subject starts with the CN, OU and O of the subject measured for release 1.4.236 (`WC.signature-gate`). Otherwise the installer is not run, and the kit still records W2.2 and the other checks. The kit's `CHECK W2.*` lines are passed through unchanged;
- it repeats the read-only part (`-InstallerPath`, with the same `-ExpectedSignerSubject` when the gate passed) under PowerShell 7 and compares the results (`WC.kit-pwsh7`). This needs the `windows` stage first, which installs PowerShell 7; without it `WC.kit-pwsh7` is SKIP;
- it lists the install folder and records the uninstall command, which it runs only with `IT_WC_UNINSTALL=1`.

```bash
bash security-tests/aws-integration/run-integration.sh preflight up bundle
bash security-tests/aws-integration/run-integration.sh windows   # installs PowerShell 7 (about 20 minutes with W1, W3 and W4)
bash security-tests/aws-integration/run-integration.sh client
bash security-tests/aws-integration/run-integration.sh down leftovers
```

It shows that the kit and the installer mechanics work as SYSTEM. It does not replace the run on Windows 11: Windows Server is outside Kiro's listed operating systems, no standard user is logged on, and no Kiro window is opened or signed in.

## References

- [`kiro-docs/intune-deployment.md`](../../kiro-docs/intune-deployment.md): the Intune runbook, its pilot checklist and its open questions.
- [`mdm/lockdown-windows.ps1`](../../mdm/lockdown-windows.ps1) and [`mdm/intune/`](../../mdm/intune/): the script and the wrappers under test.
- [`agent-hooks/README.md`](../../agent-hooks/README.md): the hook guards, including the PowerShell ports.
- [`managed-settings/README.md`](../../managed-settings/README.md): the admin policy and its Windows rules.
