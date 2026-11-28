# MDM examples

Small example scripts that are **not** part of the reference deployment. They are not covered by the test suites in
[`../tests/`](../tests/) and are not used by the Intune wrappers in [`../intune/`](../intune/).

## `Deploy-KiroPolicy-CLM.ps1`

A minimal script for the **policy step** of a custom Microsoft Intune Win32 app: it copies a packaged
`managed-settings.json` to `C:\ProgramData\Kiro\managed-settings.json` and locks the file.

It uses no .NET types, no `Add-Type` and no `New-Object` (only `Get-Content -Encoding Byte`, `ConvertFrom-Json`,
`Copy-Item`, `icacls.exe` and `Get-FileHash`). So it also runs when Windows PowerShell is in **Constrained Language
Mode**, which App Control for Business or AppLocker script enforcement turns on for scripts the policy does not trust.

**It is not a replacement for [`../lockdown-windows.ps1`](../lockdown-windows.ps1).** The reference script also hardens
the ownership and ACL of the folder, checks for symbolic links and junctions at the target paths, writes each file as a new file in an
administrators-only work folder, checks the policy against the documented schema rules (for example it refuses an
`allow` rule), deploys the hooks, sets `UpdateMode` and stages its sources for the Intune wrappers. This example does
none of that. Because it stages nothing, the wrappers in `../intune/` cannot be used with it. Use it only where the
reference script cannot run, and only as a starting point for your own script.

### What it does

1. Checks the packaged file: no UTF-8 BOM, not UTF-16, parses as JSON.
2. Removes the deny entry for `BUILTIN\Users` from the deployed file, if there is one (the entry also stops a write by
   SYSTEM).
3. Copies the packaged file unchanged.
4. Locks the file: owner Administrators, no inheritance, SYSTEM and Administrators Full, Users Read, and a deny entry
   for Users (delete, write, append, write attributes).
5. Verifies that the deployed file has the same SHA-256 as the packaged file and starts with `{`.

When it starts in a 32-bit host, it starts itself again in the 64-bit Windows PowerShell. It writes a log to
`C:\Windows\Temp\kiro-policy-deploy.log`. After an error it tries to put the deny entry back.

### Package and install command

Package two files in one folder: `Deploy-KiroPolicy-CLM.ps1` and your `managed-settings.json` (UTF-8 without BOM).

Validate the policy file **before** you package it, because this example does not check the policy rules:

```powershell
powershell -ExecutionPolicy Bypass -File mdm\lockdown-windows.ps1 -DryRun -Strict -SettingsPath <path>\managed-settings.json
```

`-DryRun` changes nothing and needs no administrator rights. Exit 0 means the file passed; exit 2 means it was refused.

Install command of the Win32 app (install behaviour: System), as in the script header:

```
%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File Deploy-KiroPolicy-CLM.ps1
```

### Exit codes

| Exit code | Meaning |
|-----------|---------|
| 0 | The policy file is deployed, locked and verified |
| 2 | The packaged file is invalid (UTF-8 BOM, UTF-16, or not JSON) |
| 4 | Write or ACL error |
| 5 | Verification failed (hash or first byte) |

### What was measured

Environment for every row: Windows 11 Enterprise 26H2 VM, 2026-11-21, Kiro IDE 1.5.11 installed, Windows PowerShell 5.1,
the script unsigned, emulated Intune context (a SYSTEM scheduled task started from the 32-bit `cmd.exe`; **not a real
Intune tenant**). **One run per row.** Constrained Language Mode came from one lab App Control for Business policy
(built from Microsoft's "AllowMicrosoft" example policy, with script enforcement on). The language mode is taken from
the script's own log.

| ID | Language mode | Case | Measured |
|----|---------------|------|----------|
| R2-61 | FullLanguage (the App Control policy not enforced) | Update with changed content over the locked file | Exit 0 |
| R2-61 | FullLanguage | Packaged file with a UTF-8 BOM | Refused, exit 2 |
| R2-65 | ConstrainedLanguage | Update with changed content over the locked file | Exit 0; hash equals the packaged file; first byte `7B`; deny entry present |
| R2-65 | ConstrainedLanguage | A second update with other content | Exit 0 |
| R2-65 | ConstrainedLanguage | Packaged file with a UTF-8 BOM | Refused, exit 2 |
| R2-81 | ConstrainedLanguage | First deploy (no policy file on the device) | Exit 0; hash equals the packaged file; first byte `7B`; deny entry present |

### Limits and what was not tested

- **Not run in a real Intune tenant.** Scheduling, status and error codes in the portal, retries and the Intune
  Management Extension were not tested.
- **One lab App Control policy.** Your App Control or AppLocker policy may behave differently. AppLocker script rules
  were not tested. A signed copy of this script and an allow rule by path or hash were not tested.
- **Header comment.** The file here differs from the script that was run in the lab only in its first comment lines (the description at the top). The code is the same.
- **The file check is small.** The script checks the first bytes and that the file parses as JSON. It does not check
  strict UTF-8 validity, and it does not check the Kiro policy rules. Validate the file with
  `lockdown-windows.ps1 -DryRun -Strict` before you package it (command above).
- Not run with this script: a first deploy in FullLanguage, a repeat with identical content, a UTF-16 file, exit
  codes 4 and 5, a write while Kiro has the policy file open, and PowerShell 7.
- These rows show the file on disk. Whether Kiro loads a file deployed by this script was not tested.
- The results are for this script as it is in this folder. Test your own copy again after any change.

## `Install-KiroIde-CheckFirst.ps1`

A small wrapper for the **Kiro IDE installer step**: it looks for a running Kiro before it starts the installer.

1. If a process named `Kiro` exists on the device, it prints
   `Kiro is running (<n> processes); not starting the installer` and ends with **exit code 1618**. The installer is
   not started. By reading the code, the check finds a process of any user in any session; tested was one case only:
   Kiro of one standard user in the console session (T-FIX-01a).
2. Otherwise it starts the system-wide installer with
   `/VERYSILENT /SP- /SUPPRESSMSGBOXES /NORESTART /MERGETASKS=!runcode /LOG="<log file>"`, waits for it and ends with
   the installer's exit code.

**Why.** In the lab, the installer run while a signed-in user had Kiro open ended with exit code 5 and left a
reduced install folder, and Kiro's own "currently running" stop did not come (Round 3, tests T-INST-11a, T-INST-12a
and T-INST-13a in [`../../kiro-docs/mdm-test-evidence.md`](../../kiro-docs/mdm-test-evidence.md#round-3-spec-driven-re-test-windows-11-kiro-ide-1511-2026-11-27)).

### Package and start

Edit the two values in the line marked `EDIT`: the **full path** of the system-wide Kiro IDE installer, and the log
file inside `/LOG="..."` (its folder must exist). In the lab the installer was named by its full path and was in
another folder than the script. A relative path, `$PSScriptRoot` and an installer packaged next to the script were
not tested.

The start that was tested for the lab text, as SYSTEM from a 32-bit host:

```
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <script file>
```

### Exit codes

| Exit code | Meaning |
|-----------|---------|
| 1618 | A process named `Kiro` exists. The installer was not started. The value is chosen by this script. Measured once (T-FIX-01a) |
| 0 | Measured once (T-FIX-01b): the installer file was present, Kiro was stopped, the installer ran and ended with exit code 0. **Not tested:** what the script returns when the installer file is missing or cannot be started; by reading the code only, it may then also end with 0. Do not read 0 as proof of an install: check the version of `Kiro.exe` |
| other | The exit code of the installer. **Not measured through this script.** With the installer started directly the lab saw 1 when the `/LOG=` folder did not exist (T-INST-03a) and 5 when a user's Kiro was open (T-INST-11a; this script is meant to avoid that case). With the installer started directly and a Kiro that ran as SYSTEM the lab saw 1 (T-INST-08a, T-INST-13b); this script with a Kiro that runs as SYSTEM was not tested, and by reading the code it ends with 1618 before the installer starts |

### What was measured

Environment for both rows: one Windows 11 Enterprise 26H2 (Evaluation) lab VM, 2026-11-27, Kiro IDE 1.4.236
installed, the installer is the Kiro IDE 1.5.11 system-wide build, Windows PowerShell 5.1 in FullLanguage mode, the
lab text (see the differences below) run as SYSTEM from a scheduled task started from the 32-bit `cmd.exe`; **not a
real Intune tenant**. **One run per row.**

| Test | State | Measured | Control |
|------|-------|----------|---------|
| T-FIX-01a | Kiro open in the standard user's console session (17 `Kiro.exe` processes, none owned by SYSTEM) | Exit code 1618. The install folder had 6,401 files before and after. The user's Kiro processes kept running with the same process IDs. No installer log was written (the log folder was listed) | T-FIX-01b |
| T-FIX-01b | The same device, Kiro stopped | Exit code 0; `Kiro.exe` has version 1.5.11 | T-FIX-01a |

### Limits and what was not tested

- **Not run in a real Intune tenant.** What Microsoft Intune does with exit code 1618 (status, retry) was not
  measured. Check the return codes of your Win32 app; see
  [`../../kiro-docs/intune-deployment.md`](../../kiro-docs/intune-deployment.md#round-3-install-upgrade-and-uninstall-while-a-user-has-kiro-open).
- **The file here is not the text that was run, and it was not run in this form.** It differs in three ways: the
  installer path is a placeholder that you replace by a full path (the tested text held the full path of the lab's
  installer file, in another folder than the script); the log file name inside `/LOG="..."` is another one (the
  tested text held another file name in `C:\Windows\Temp`); and the statements are on separate lines with comment
  lines between them (the tested text was one line). The five statements, their order and the installer switches
  are those of the tested text.
- **The check and the start of the installer are two steps.** A Kiro that starts between them is not covered. Not
  tested.
- The script does not check that the installer file exists or that the installer started. The case "installer file
  not found" (also: the placeholder path not edited) was not tested; by reading the code only, the script may then
  end with exit code 0. Check the package, and check the version of `C:\Program Files\Kiro\Kiro.exe` after the
  install with your detection rule.
- It calls methods of a .NET process object. Constrained Language Mode (App Control or AppLocker script enforcement)
  was not tested with this script.
- By reading the code, it finds a process named `Kiro` of any user. Tested was Kiro of one standard user in the
  console session, none owned by SYSTEM (T-FIX-01a). A Kiro that runs as SYSTEM, and a device where another product
  uses that process name, were not tested.
- Not tested: a start from 64-bit PowerShell (`Sysnative`), PowerShell 7, other Kiro versions, ARM64, the per-user
  build, and an uninstall.
- The results are for the text that was run in the lab, not for this file (see the differences above). Test your own
  copy before use and again after any change.
