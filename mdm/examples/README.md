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
