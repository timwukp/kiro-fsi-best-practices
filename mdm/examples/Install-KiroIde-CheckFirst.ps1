# Install-KiroIde-CheckFirst.ps1 - example: look for a running Kiro before the Kiro IDE installer is started.
# Not part of the reference deployment; see README.md in this folder.
#
# What it does: if a process named "Kiro" exists on the device, it prints one line and ends with exit code 1618
# without starting the installer. Otherwise it starts the system-wide Kiro IDE installer silently, waits for it
# and ends with the exit code of the installer. By reading the code, Get-Process finds a process of any user in any
# session; tested was one case only (see below).
#
# Why: in the lab, the installer run while a signed-in user had Kiro open ended with exit code 5 and left a
# reduced install folder (kiro-docs/mdm-test-evidence.md, Round 3, tests T-INST-11a and T-INST-12a).
#
# What was tested (Round 3, 2026-11-27, tests T-FIX-01a and T-FIX-01b, one run each): one Windows 11 Enterprise
# 26H2 (Evaluation) lab VM, Kiro IDE 1.4.236 installed, installer = Kiro IDE 1.5.11 system-wide build. The tested
# text was written to a script file and run as SYSTEM from a scheduled task started from the 32-bit cmd.exe with
#   powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <script file>
# in FullLanguage mode. NOT a real Intune tenant.
#   T-FIX-01a, Kiro open in one standard user's console session (17 processes, none owned by SYSTEM): exit code
#     1618, the install folder unchanged (6,401 files before and after), the user's Kiro processes kept running,
#     no installer log written.
#   T-FIX-01b, same device, Kiro stopped, installer file present: exit code 0, Kiro.exe version 1.5.11.
#
# THIS FILE IS NOT THE TEXT THAT WAS RUN, and it was NOT run in this form. It differs in three ways:
#   1. the installer path: the tested text held the full path of the installer file, in another folder than the
#      script. Here it is a placeholder that you must replace by a full path;
#   2. the log file name inside /LOG="...": the tested text held another file name in C:\Windows\Temp;
#   3. the statements are on separate lines and there are comment lines (the tested text was one line, joined
#      with ";").
# The five statements, their order and the installer switches are those of the tested text.
#
# Limits and what was not tested:
#   - Exit code 0 was measured once, with the installer file present and Kiro stopped (T-FIX-01b). The script does
#     not check that the installer file exists or that the installer started. What it returns when the installer
#     cannot be started (a missing file, a path that was not edited) was NOT tested. By reading the code only, it
#     may then end with exit code 0. So do not read exit code 0 as proof of an install: check the version of
#     C:\Program Files\Kiro\Kiro.exe.
#   - A relative installer path, $PSScriptRoot and an installer packaged next to the script were not tested.
#   - The check and the start of the installer are two steps. A Kiro that starts between them is not covered.
#   - A Kiro that runs as SYSTEM was not tested with this text. By reading the code, the script then ends with
#     exit code 1618.
#   - 1618 is a value chosen by this script. What a management tool does with it was not measured.
#   - It calls methods of a .NET process object. Constrained Language Mode (App Control or AppLocker script
#     enforcement) was not tested with this script.
#   - Not tested: a start from 64-bit PowerShell, PowerShell 7, other Kiro versions, ARM64, the per-user build.
#
# Exit codes: 1618 = a Kiro process exists, the installer was not started (measured once, T-FIX-01a).
# Otherwise the exit code of the installer. Measured through this text: 0 only (T-FIX-01b). Other installer exit
# codes were measured with the installer started directly, not through this text: 1 when the /LOG= folder did not
# exist (T-INST-03a), 5 when a user's Kiro was open (T-INST-11a).

$k = @(Get-Process -Name 'Kiro' -ErrorAction SilentlyContinue)
if ($k.Count -gt 0) { 'Kiro is running (' + $k.Count + ' processes); not starting the installer'; exit 1618 }
# EDIT the two values in the next line. -FilePath: the full path of the system-wide Kiro IDE installer.
# /LOG=: the installer log; its folder must exist (with a /LOG= folder that does not exist the installer ended
# with exit code 1 and installed nothing, T-INST-03a).
$p = Start-Process -FilePath 'C:\EDIT-full-path\kiro-ide-EDIT-version-stable-win32-x64-system.exe' -ArgumentList '/VERYSILENT /SP- /SUPPRESSMSGBOXES /NORESTART /MERGETASKS=!runcode /LOG="C:\Windows\Temp\kiro-install.log"' -PassThru
$null = $p.Handle
$p.WaitForExit()
exit $p.ExitCode
