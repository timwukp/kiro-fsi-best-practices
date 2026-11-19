<#
Invoke-W2Checks.ps1 - Windows client validation kit (phase W2, GitHub issue #43).

PURPOSE
  Records what Kiro IDE actually does on a Windows 11 client: installer, Uninstall registry view,
  install folder, signature, UpdateMode, the admin policy file, and the Intune wrappers in the
  contexts Intune uses. It is a defensive validation kit for endpoint guardrails.

FOR TEST DEVICES ONLY
  -Install, -InstallPolicy, -TamperTest and -InstallProbes change the device; each prints one
  ACTION line before it changes anything. With no action switch the script only reads, and writes
  nothing outside -OutDir.

CONTEXTS
  SYSTEM                  everything; -Wrappers runs system64 and system32 as child processes
  elevated administrator  everything; -Wrappers starts system64 and system32 through one-shot
                          scheduled tasks (named KiroW2-<id>) that run as SYSTEM
  standard user           the read-only inventory; with -UserContext -Wrappers the context "user";
                          the probes (-InstallProbes, -ReadProbes, -RemoveProbes)

A PERSON IS NEEDED FOR THE MANUAL PARTS OF W2.1 AND W2.3 TO W2.9
  Whether Kiro enforces the policy, loads global hooks, blocks on exit 2 and loads global steering
  can only be seen in a signed-in Kiro window. The script prepares those checks and records
  evidence; the steps are in W2-manual-checklist.md.

  powershell -NoProfile -ExecutionPolicy Bypass -File Invoke-W2Checks.ps1 [switches]

  -RepoDir <path>             repository root (default: two levels above this script)
  -OutDir <path>              default C:\ProgramData\KiroW2 when elevated or SYSTEM, otherwise
                              %LOCALAPPDATA%\KiroW2. An elevated or SYSTEM run sets the owner
                              (Administrators) and the ACL (SYSTEM and Administrators only, no
                              inheritance) of this folder on every run, also when it already
                              exists: never name a folder that holds other data.
  -InstallerPath <exe>        W2.2 on the installer; with -Install also W2.1
  -Install                    run the installer silently (elevated or SYSTEM)
  -InstallerArgs <string>     default: /VERYSILENT /SP- /SUPPRESSMSGBOXES /NORESTART
                              /MERGETASKS=!runcode /LOG="<OutDir>\kiro-install.log" (Inno Setup
                              switches; Kiro does not document them (verify)). Without
                              /MERGETASKS=!runcode the installer starts Kiro when it ends
  -InstallTimeoutMinutes <n>  default 15
  -ExpectedSignerSubject <s>  W2.2.signer fails unless the signer subject equals it. Double
                              quotes are ignored in the comparison, because they do not survive
                              every command line: give CN="Amazon.com, Inc." as CN=Amazon.com, Inc.
  -InstallPolicy              run mdm\lockdown-windows.ps1 -StageSources -DeployHooks -InstallUser
                              -DisableUpdates from -RepoDir first (elevated or SYSTEM)
  -Wrappers                   W2.10: run the three Intune wrappers
  -TamperTest                 with -Wrappers, elevated or SYSTEM: tamper with the deployed policy,
                              then check detection and remediation
  -UserContext                run as the logged-on standard user: the read-only inventory, and with
                              -Wrappers the context "user"; -Install and -InstallPolicy are skipped
  -InstallProbes / -ReadProbes / -RemoveProbes
                              hook and steering probes (W2.7, W2.8, W2.9) in the CURRENT user's
                              profile. Given alone, only W2.0 and the probe checks run.
  -NoSanitize                 keep the computer name, user names and SIDs in the output; the
                              lines then go to <OutDir>\w2-results-UNSANITIZED.txt

OUTPUT
  "CHECK <id> <STATUS> <detail>" with STATUS PASS, FAIL, SKIP or INFO, then
  "PHASE W2 RESULT pass=<n> fail=<n> skip=<n> info=<n>". NOTE and ACTION lines carry context. The
  same lines are appended to <OutDir>\w2-results.txt (with -NoSanitize to
  <OutDir>\w2-results-UNSANITIZED.txt instead). Exit code 1 if any FAIL, otherwise 0.
  <OutDir>\kiro-install.log is written by the installer and is NOT sanitized.

Targets Windows PowerShell 5.1 and PowerShell 7 (pure ASCII source).
#>
[CmdletBinding()]
param(
  [string]$RepoDir,
  [string]$OutDir,
  [string]$InstallerPath,
  [switch]$Install,
  [string]$InstallerArgs,
  [int]$InstallTimeoutMinutes = 15,
  [string]$ExpectedSignerSubject,
  [switch]$InstallPolicy,
  [switch]$Wrappers,
  [switch]$TamperTest,
  [switch]$UserContext,
  [switch]$InstallProbes,
  [switch]$ReadProbes,
  [switch]$RemoveProbes,
  [switch]$NoSanitize
)

# Under application control (Constrained Language Mode) the .NET calls below are blocked.
if ([string]$ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
  Write-Output "CHECK W2.0.powershell FAIL language mode is $($ExecutionContext.SessionState.LanguageMode); the kit needs FullLanguage (sign the kit or allow it in the application-control policy)"
  Write-Output 'PHASE W2 RESULT pass=0 fail=1 skip=0 info=0'
  exit 1
}

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
$script:Pass = 0; $script:Fail = 0; $script:Skip = 0; $script:Info = 0
$script:ResultsFile = ''
$script:SanRules = New-Object System.Collections.Generic.List[object]
$St = @{ InstallerOk = $false; Entries = $null; OutDirProblem = '' }

$Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$IsSystem = ($Identity.User.Value -eq 'S-1-5-18')
$IsElevated = (New-Object System.Security.Principal.WindowsPrincipal $Identity).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
$IsAdmin = ($IsSystem -or $IsElevated)

$SidSystem = 'S-1-5-18'; $SidAdmins = 'S-1-5-32-544'; $SidUsers = 'S-1-5-32-545'
$SidTrustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$PolicyFile = Join-Path $env:ProgramData 'Kiro\managed-settings.json'
$StagedLockdown = Join-Path $env:ProgramData 'Kiro\deploy\mdm\lockdown-windows.ps1'
$WrapperOptions = @('-DeployHooks', '-InstallUser', '-DisableUpdates')
$ChildTimeoutSec = 600
$Icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'

# From a 32-bit process System32 is redirected to SysWOW64; Sysnative reaches the 64-bit files.
$PsExe64 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
  $PsExe64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
}
$PsExe32 = ''
if ([Environment]::Is64BitOperatingSystem) { $PsExe32 = Join-Path $env:SystemRoot 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe' }

# ------------------------------------------------------------------------------------------------
# Output
# ------------------------------------------------------------------------------------------------
function Add-SanRule([string]$Pattern, [string]$Replacement) {
  $rx = New-Object System.Text.RegularExpressions.Regex($Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  $script:SanRules.Add(@{ Rx = $rx; To = $Replacement })
}

function Get-ProfilesRoot {
  $root = ''
  try {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
      $k = $base.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList')
      if ($null -ne $k) { try { $root = [string]$k.GetValue('ProfilesDirectory') } finally { $k.Dispose() } }
    } finally { $base.Dispose() }
  } catch { }
  if (-not $root) { $root = Join-Path $env:SystemDrive 'Users' }
  return $root.TrimEnd('\')
}

# Rules, in order: SIDs, profile paths, user names as words, computer names.
function Initialize-Sanitizer {
  if ($NoSanitize) { return }
  Add-SanRule 'S-1-(?:5-21|12-1)(?:-\d+)+' '<sid>'
  $names = New-Object System.Collections.Generic.List[string]
  try { foreach ($d in [System.IO.Directory]::GetDirectories($ProfilesRoot)) { $names.Add([System.IO.Path]::GetFileName($d)) } } catch { }
  if ($env:USERNAME) { $names.Add([string]$env:USERNAME) }
  if ($env:USERPROFILE) { $names.Add([System.IO.Path]::GetFileName(([string]$env:USERPROFILE).TrimEnd('\'))) }
  $notNames = @('Public', 'Default', 'Default User', 'All Users', 'systemprofile')
  # A user name that is also an ordinary word of this output is replaced in profile paths only.
  $words = @('kiro', 'user', 'users', 'system', 'admin', 'administrator', 'guest', 'test', 'info', 'pass', 'fail', 'skip', 'check', 'none', 'windows', 'policy', 'hook', 'hooks', 'probe', 'local', 'view', 'dev', 'demo', 'setup', 'install', 'owner', 'home', 'work', 'temp', 'file', 'exit', 'path', 'client', 'server', 'intune', 'run', 'key', 'folder', 'machine', 'account', 'computer', 'domain', 'sid')
  $rootRx = [regex]::Escape($ProfilesRoot) -replace '\\\\', '[\\/]'
  $seen = @{}
  foreach ($n in @($names | Sort-Object -Property Length -Descending)) {
    if (-not $n) { continue }
    $key = $n.ToLowerInvariant()
    if (($notNames -contains $n) -or $n.EndsWith('$') -or $seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    $e = [regex]::Escape($n)
    Add-SanRule ('(' + $rootRx + '[\\/]+)' + $e + '(?![A-Za-z0-9_.-])') '${1}<user>'
    if (($n.Length -ge 3) -and ($words -notcontains $n)) { Add-SanRule ('(?<![A-Za-z0-9_.-])' + $e + '(?![A-Za-z0-9_-])') '<user>' }
  }
  $hosts = New-Object System.Collections.Generic.List[string]
  if ($env:COMPUTERNAME) { $hosts.Add([string]$env:COMPUTERNAME) }
  try { $hosts.Add([System.Net.Dns]::GetHostName()) } catch { }
  foreach ($h in @($hosts | Sort-Object -Property Length -Descending)) {
    # A computer named like a word of this output (KIRO, TEST, W2) is left alone: replacing it would garble the evidence.
    if ($h -and ($h.Length -ge 3) -and ($words -notcontains $h) -and ($h -ne 'W2')) { Add-SanRule ('(?<![A-Za-z0-9])' + [regex]::Escape($h) + '(?![A-Za-z0-9])') '<computer>' }
    elseif ($h) { $script:SanSkipped = $true }
  }
  foreach ($dom in @($env:USERDOMAIN, $env:USERDNSDOMAIN)) {
    if ($dom -and ($dom.Length -ge 3) -and ($words -notcontains $dom) -and ($hosts -notcontains $dom)) { Add-SanRule ('(?<![A-Za-z0-9])' + [regex]::Escape([string]$dom) + '(?![A-Za-z0-9])') '<domain>' }
  }
}

function Protect-Text([string]$Text) {
  if ($NoSanitize -or [string]::IsNullOrEmpty($Text)) { return $Text }
  $t = $Text
  foreach ($rule in $script:SanRules) { $t = $rule.Rx.Replace($t, [string]$rule.To) }
  return $t
}

# One line to STDOUT and to the results file. The caller sanitizes.
function Write-Raw([string]$Line) {
  # The ISE and remote sessions do not show [Console]::Out.
  $shown = $false
  if ($Host.Name -ne 'ConsoleHost') { try { $Host.UI.WriteLine($Line); $shown = $true } catch { } }
  if (-not $shown) { [Console]::Out.WriteLine($Line) }
  if ($script:ResultsFile) {
    try { [System.IO.File]::AppendAllText($script:ResultsFile, $Line + "`r`n", $Utf8NoBom) } catch { }
  }
}

# Sanitized first, then cut: a name that is cut at the limit would no longer match its rule.
function Format-Detail([string]$Text) {
  $d = Protect-Text (([string]$Text -replace '[\r\n\t]+', ' ').Trim())
  if ($d.Length -gt 1800) { $d = $d.Substring(0, 1800) + ' ...' }
  return $d
}

function Write-Note([string]$Text) { Write-Raw ('NOTE ' + (Format-Detail $Text)) }
function Write-Action([string]$Text) { Write-Raw ('ACTION ' + (Format-Detail $Text)) }

# The ID and the status are never sanitized; the detail is.
function Check([string]$Id, [string]$Status, [string]$Detail = '') {
  Write-Raw ("CHECK $Id $Status " + (Format-Detail $Detail))
  switch ($Status) {
    'PASS' { $script:Pass++ }
    'FAIL' { $script:Fail++ }
    'SKIP' { $script:Skip++ }
    default { $script:Info++ }
  }
}

# A failure inside one check must not stop the others.
function Invoke-Check([string]$CheckId, [scriptblock]$Body) {
  try { $null = & $Body }
  catch { Check $CheckId 'FAIL' "the check stopped with an error: $($_.Exception.Message)" }
}

function Get-FirstLine([string]$Text) {
  foreach ($l in ([string]$Text -split "`r?`n")) {
    $t = Protect-Text $l.Trim()
    if ($t) { if ($t.Length -gt 400) { return $t.Substring(0, 400) + ' ...' }; return $t }
  }
  return ''
}

# ------------------------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------------------------
# True for junctions and symbolic links, including dangling ones.
function Test-ReparsePoint([string]$Path) {
  if (-not $Path) { return $false }
  try { $a = [System.IO.File]::GetAttributes($Path) } catch { return $false }
  return [bool]($a -band [System.IO.FileAttributes]::ReparsePoint)
}

# Windows command-line quoting for one argument string (CreateProcess rules).
function ConvertTo-ArgString([string[]]$Argv) {
  $parts = New-Object System.Collections.Generic.List[string]
  foreach ($a in $Argv) {
    if (($a -ne '') -and ($a -notmatch '[\s"]')) { $parts.Add($a); continue }
    $s = $a -replace '(\\*)"', '$1$1\"'
    $s = $s -replace '(\\+)$', '$1$1'
    $parts.Add('"' + $s + '"')
  }
  return [string]::Join(' ', $parts.ToArray())
}

function Stop-ProcessTree($Process) {
  try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Join-Path $env:SystemRoot 'System32\taskkill.exe'
    $psi.Arguments = "/T /F /PID $($Process.Id)"
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $k = [System.Diagnostics.Process]::Start($psi)
    $null = $k.WaitForExit(15000)
    $k.Dispose()
  } catch { }
  try { if (-not $Process.HasExited) { $Process.Kill() } } catch { }
}

# Child process with a time limit; STDOUT and STDERR go to pipes that this script owns.
function Invoke-Child([string]$Exe, [string]$Arguments, [int]$TimeoutSec) {
  $r = @{ Code = $null; Out = ''; Err = ''; TimedOut = $false; Seconds = 0; Error = '' }
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $p = $null
  try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    # PowerShell 7 cleans PSModulePath only when it starts powershell.exe itself; Process.Start does not.
    if (($PSVersionTable.PSEdition -eq 'Core') -and ($Exe -like '*\WindowsPowerShell\v1.0\powershell.exe')) {
      try { $psi.EnvironmentVariables.Remove('PSModulePath') } catch { }
    }
    $p = [System.Diagnostics.Process]::Start($psi)
    try { $p.StandardInput.Close() } catch { }
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    if ($p.WaitForExit($TimeoutSec * 1000)) {
      $r.Code = [int]$p.ExitCode
    } else {
      $r.TimedOut = $true
      Stop-ProcessTree $p
    }
    # A grandchild that is still running keeps the pipe open: wait a short time only.
    try { if ($outTask.Wait(5000)) { $r.Out = [string]$outTask.Result } } catch { }
    try { if ($errTask.Wait(5000)) { $r.Err = [string]$errTask.Result } } catch { }
  } catch {
    $r.Error = $_.Exception.Message
  } finally {
    if ($null -ne $p) { try { $p.Dispose() } catch { } }
  }
  $sw.Stop()
  $r.Seconds = [int]$sw.Elapsed.TotalSeconds
  return $r
}

# Short text for a FAIL detail.
function Get-RunText($R) {
  if ($R.Error) { return "could not start: $($R.Error)" }
  if ($R.TimedOut) { return "timed out after $($R.Seconds) s; the process was stopped" }
  return "exit=$($R.Code); stdout=[$(Get-FirstLine $R.Out)]; stderr=[$(Get-FirstLine $R.Err)]"
}

function Get-RegValues([string]$Hive, [string]$View, [string]$Path, [string[]]$Names) {
  $res = @{ Exists = $false; Vals = @{}; Kinds = @{}; AllNames = @() }
  $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]$Hive, [Microsoft.Win32.RegistryView]$View)
  try {
    $k = $base.OpenSubKey($Path)
    if ($null -ne $k) {
      try {
        $res.Exists = $true
        $res.AllNames = @($k.GetValueNames())
        foreach ($n in $Names) {
          $v = $k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
          if ($null -ne $v) { $res.Vals[$n] = $v; $res.Kinds[$n] = [string]$k.GetValueKind($n) }
        }
      } finally { $k.Dispose() }
    }
  } finally { $base.Dispose() }
  return $res
}

# Uninstall entries whose DisplayName starts with Kiro, as a list of hashtables.
function Get-UninstallEntries([string]$Hive, [string]$View, [string]$Path, [string]$ViewId, [string]$Label) {
  $found = New-Object System.Collections.Generic.List[object]
  $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]$Hive, [Microsoft.Win32.RegistryView]$View)
  try {
    $u = $null
    try { $u = $base.OpenSubKey($Path) } catch { }
    if ($null -ne $u) {
      try {
        foreach ($name in @($u.GetSubKeyNames())) {
          $k = $null
          try { $k = $u.OpenSubKey($name) } catch { }
          if ($null -eq $k) { continue }
          try {
            $dn = [string]$k.GetValue('DisplayName')
            if ($dn -match '^kiro') {
              $found.Add(@{
                  ViewId = $ViewId; Label = $Label; Key = $name; DisplayName = $dn
                  DisplayVersion = [string]$k.GetValue('DisplayVersion')
                  InstallLocation = [string]$k.GetValue('InstallLocation')
                  UninstallString = [string]$k.GetValue('UninstallString')
                  QuietUninstallString = [string]$k.GetValue('QuietUninstallString')
                })
            }
          } finally { $k.Dispose() }
        }
      } finally { $u.Dispose() }
    }
  } finally { $base.Dispose() }
  return ,$found
}

# SIDs of the other user hives that are loaded (HKEY_USERS), without the current account.
function Get-LoadedUserSids {
  $list = New-Object System.Collections.Generic.List[string]
  $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
  try {
    foreach ($n in @($base.GetSubKeyNames())) {
      if (($n -match '^S-1-(5-21|12-1)-[0-9-]+$') -and ($n -ne $Identity.User.Value)) { $list.Add($n) }
    }
  } finally { $base.Dispose() }
  return ,$list
}

# Profile folders to inspect: every local profile when elevated or SYSTEM, else only this one.
function Get-ProfileDirs {
  $list = New-Object System.Collections.Generic.List[string]
  if ($IsAdmin) {
    try {
      foreach ($d in [System.IO.Directory]::GetDirectories($ProfilesRoot)) {
        $leaf = [System.IO.Path]::GetFileName($d)
        if ((@('Public', 'Default', 'Default User', 'All Users') -contains $leaf) -or (Test-ReparsePoint $d)) { continue }
        $list.Add($d)
      }
    } catch { }
  }
  if ($env:USERPROFILE -and ($list -notcontains $env:USERPROFILE) -and (Test-Path -LiteralPath $env:USERPROFILE -PathType Container)) { $list.Add([string]$env:USERPROFILE) }
  return ,$list
}

function Get-FileSha256([string]$Path) {
  try { return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop).Hash.ToLowerInvariant() } catch { return '' }
}

function Get-AceSid($Ace) {
  try { return $Ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
  catch { return [string]$Ace.IdentityReference.Value }
}

function Test-UsersDeny([string]$Path) {
  foreach ($ace in @((Get-Acl -LiteralPath $Path).Access)) {
    if (([string]$ace.AccessControlType -eq 'Deny') -and ((Get-AceSid $ace) -eq $SidUsers)) { return $true }
  }
  return $false
}

# '' when only administrators own the folder and can delete, rename or re-permission it; else the reason.
function Test-AdminControlled([string]$Path) {
  if (Test-ReparsePoint $Path) { return 'it is a junction or symbolic link' }
  $trusted = @($SidSystem, $SidAdmins, $SidTrustedInstaller, $Identity.User.Value)
  try { $acl = Get-Acl -LiteralPath $Path } catch { return "its ACL cannot be read ($($_.Exception.Message))" }
  $owner = [string]$acl.Owner
  try { $owner = (New-Object System.Security.Principal.NTAccount($acl.Owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { }
  if ($trusted -notcontains $owner) { return "its owner ($($acl.Owner)) is not SYSTEM or Administrators" }
  $bad = [int64][System.Security.AccessControl.FileSystemRights]'Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
  foreach ($ace in @($acl.Access)) {
    if ([string]$ace.AccessControlType -eq 'Deny') { continue }
    if ($trusted -contains (Get-AceSid $ace)) { continue }
    # Inherit-only entries do not apply to the folder itself.
    if ($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
    $raw = [int64]$ace.FileSystemRights
    if ((($raw -band $bad) -ne 0) -or (($raw -band [int64]0x10000000) -ne 0)) { return "$($ace.IdentityReference) can delete, rename or re-permission it" }
  }
  return ''
}

# Owner Administrators, no inheritance, SYSTEM and Administrators only. Returns '' or the reason.
function Lock-AdminDir([string]$Dir) {
  $steps = @(
    @($Dir, '/setowner', "*$SidAdmins"),
    @($Dir, '/inheritance:r'),
    @($Dir, '/grant:r', "*${SidSystem}:(OI)(CI)F", "*${SidAdmins}:(OI)(CI)F")
  )
  try {
    foreach ($s in $steps) {
      $r = Invoke-Child $Icacls (ConvertTo-ArgString $s) 60
      if ($r.Code -ne 0) { return "icacls $($s[1]) failed: $(Get-RunText $r)" }
    }
    # Entries that someone else planted are removed; the second round only checks.
    foreach ($round in 1, 2) {
      $left = New-Object System.Collections.Generic.List[string]
      foreach ($ace in @((Get-Acl -LiteralPath $Dir).Access)) {
        $sid = Get-AceSid $ace
        if ((@($SidSystem, $SidAdmins) -contains $sid) -and ([string]$ace.AccessControlType -ne 'Deny')) { continue }
        if ($left -notcontains $sid) { $left.Add($sid) }
      }
      if ($left.Count -eq 0) { return '' }
      if ($round -eq 2) { return "access entries for $([string]::Join(', ', $left.ToArray())) could not be removed" }
      foreach ($sid in $left) { $null = Invoke-Child $Icacls (ConvertTo-ArgString @($Dir, '/remove', "*$sid")) 60 }
    }
  } catch { return "the ACL could not be set: $($_.Exception.Message)" }
  return ''
}

# Never writes through an existing file or link: the old object is deleted and a new one created.
function Write-NewFile([string]$Path, [byte[]]$Bytes) {
  if ((Test-Path -LiteralPath $Path -PathType Container) -and -not (Test-ReparsePoint $Path)) { throw "$Path is a folder" }
  if ((Test-ReparsePoint $Path) -or (Test-Path -LiteralPath $Path)) {
    if ([System.IO.File]::GetAttributes($Path) -band [System.IO.FileAttributes]::Directory) { [System.IO.Directory]::Delete($Path, $false) }
    else { [System.IO.File]::Delete($Path) }
  }
  $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
  try { $fs.Write($Bytes, 0, $Bytes.Length) } finally { $fs.Dispose() }
}

# ------------------------------------------------------------------------------------------------
# W2.0 environment
# ------------------------------------------------------------------------------------------------
function Test-Environment {
  Invoke-Check 'W2.0.os' {
    $os = @(Get-CimInstance -ClassName Win32_OperatingSystem -OperationTimeoutSec 30)[0]
    $cv = Get-RegValues 'LocalMachine' 'Registry64' 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' @('DisplayVersion', 'UBR', 'EditionID')
    $build = [string]$os.BuildNumber
    if ($cv.Vals.ContainsKey('UBR')) { $build = $build + '.' + [string]$cv.Vals['UBR'] }
    $productType = [int]$os.ProductType
    $kind = 'client'
    if ($productType -ne 1) { $kind = 'server' }
    $d = "caption=$($os.Caption); version=$($os.Version); build=$build; display version=$($cv.Vals['DisplayVersion']); edition id=$($cv.Vals['EditionID']); edition=$kind (ProductType $productType); architecture=$($os.OSArchitecture)"
    if ($kind -eq 'server') { $d = $d + "; outside Kiro's listed operating systems (Windows 10/11)" }
    Check 'W2.0.os' 'INFO' $d
  }
  Invoke-Check 'W2.0.powershell' {
    $bits = [IntPtr]::Size * 8
    $osBits = 32
    if ([Environment]::Is64BitOperatingSystem) { $osBits = 64 }
    Check 'W2.0.powershell' 'INFO' "edition=$($PSVersionTable.PSEdition); version=$($PSVersionTable.PSVersion); process=${bits}-bit; operating system=${osBits}-bit; host=$($Host.Name)"
  }
  Invoke-Check 'W2.0.context' {
    $ctx = 'standard user (not elevated)'
    if ($IsSystem) { $ctx = 'SYSTEM' }
    elseif ($IsElevated) { $ctx = 'elevated administrator' }
    else {
      # A member of Administrators without elevation holds the group as a deny-only SID.
      try {
        foreach ($c in $Identity.Claims) {
          if (([string]$c.Value -eq $SidAdmins) -and ([string]$c.Type -like '*denyonlysid')) { $ctx = 'member of Administrators, not elevated (NOT a standard user)' }
        }
      } catch { }
    }
    $session = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    Check 'W2.0.context' 'INFO' "$ctx; session=$session; interactive=$([Environment]::UserInteractive)"
  }
}

# ------------------------------------------------------------------------------------------------
# W2.2 installer signature, W2.1 install
# ------------------------------------------------------------------------------------------------
function Test-Installer {
  if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
    Check 'W2.2.signature' 'FAIL' "installer not found: $InstallerPath"
    return
  }
  $St.Signature = $null
  $St.SignatureValid = $false
  $St.InstallerOk = $false
  Invoke-Check 'W2.2.signature' {
    $sig = Get-AuthenticodeSignature -LiteralPath $InstallerPath
    $St.Signature = $sig
    $status = [string]$sig.Status
    if ($status -eq 'Valid') {
      $St.SignatureValid = $true
      Check 'W2.2.signature' 'PASS' 'status=Valid (Valid alone is not a publisher check: compare the signer in W2.2.signer)'
    } else {
      Check 'W2.2.signature' 'FAIL' "status=$status; message=$($sig.StatusMessage)"
    }
  }
  Invoke-Check 'W2.2.signer' {
    $sig = $St.Signature
    if (($null -eq $sig) -or ($null -eq $sig.SignerCertificate)) {
      Check 'W2.2.signer' 'FAIL' 'the file has no signer certificate'
      return
    }
    $c = $sig.SignerCertificate
    $stamp = '(none)'
    if ($null -ne $sig.TimeStamperCertificate) { $stamp = [string]$sig.TimeStamperCertificate.Subject }
    $d = "subject=[$($c.Subject)]; issuer=[$($c.Issuer)]; thumbprint=$($c.Thumbprint); valid until=$($c.NotAfter.ToString('yyyy-MM-dd')); timestamp signer=[$stamp]"
    if ($ExpectedSignerSubject) {
      # Double quotes are ignored: a subject such as CN="Amazon.com, Inc." does not survive every command line.
      if ((([string]$c.Subject) -replace '"', '') -ceq ($ExpectedSignerSubject -replace '"', '')) { $St.InstallerOk = [bool]$St.SignatureValid; Check 'W2.2.signer' 'PASS' "the signer subject equals -ExpectedSignerSubject (double quotes ignored); $d" }
      else { Check 'W2.2.signer' 'FAIL' "the signer subject differs from -ExpectedSignerSubject [$ExpectedSignerSubject] (double quotes ignored); $d" }
    } else {
      $St.InstallerOk = [bool]$St.SignatureValid
      Check 'W2.2.signer' 'INFO' "$d; Kiro publishes no signer name (verify): record this subject as your baseline"
    }
  }
  Invoke-Check 'W2.2.sha256' {
    $item = Get-Item -LiteralPath $InstallerPath
    $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($InstallerPath)
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $InstallerPath).Hash.ToLowerInvariant()
    Check 'W2.2.sha256' 'INFO' "sha256=$hash; size=$($item.Length); file=$($item.Name); file version=$($vi.FileVersion); product version=$($vi.ProductVersion); product name=$($vi.ProductName)"
  }
}

function Invoke-Install {
  if ($UserContext) { Check 'W2.1.install' 'SKIP' '-Install is not run with -UserContext'; return }
  if (-not $InstallerPath) { Check 'W2.1.install' 'SKIP' '-Install needs -InstallerPath'; return }
  if (-not $IsAdmin) { Check 'W2.1.install' 'SKIP' 'refused: -Install needs an elevated or SYSTEM session, and this session is neither'; return }
  if (-not $St.InstallerOk) { Check 'W2.1.install' 'SKIP' 'refused: the installer did not pass W2.2 (signature Valid and, when given, the expected signer); it was not run'; return }
  Invoke-Check 'W2.1.install' {
    Write-Action "about to run the installer silently, which installs Kiro on this device: $InstallerPath $InstallerArgs (time limit $InstallTimeoutMinutes min)"
    $began = Get-Date
    $r = Invoke-Child $InstallerPath $InstallerArgs ($InstallTimeoutMinutes * 60)
    $how = "arguments=[$InstallerArgs] (Inno Setup switches; not documented by Kiro (verify))"
    # Recorded, not stopped: whether a silent install starts Kiro is not documented (verify).
    $running = 'not read'
    try {
      $counts = @{}
      foreach ($proc in @(Get-CimInstance -ClassName Win32_Process -Filter "Name LIKE 'Kiro%'" -Property Name, CreationDate -OperationTimeoutSec 30)) {
        if (($null -ne $proc.CreationDate) -and ($proc.CreationDate -ge $began)) { $counts[[string]$proc.Name] = 1 + [int]$counts[[string]$proc.Name] }
      }
      $running = 'none'
      if ($counts.Count -gt 0) { $running = (@($counts.Keys | Sort-Object) | ForEach-Object { "$_ x$($counts[$_])" }) -join ', ' }
    } catch { }
    $how = "$how; Kiro processes started during the install and still running: $running"
    if (($running -ne 'none') -and ($running -ne 'not read')) { Write-Note "the installer left Kiro processes running in this session ($running). Stop them or restart the device before the manual checks; under SYSTEM they run in session 0" }
    if ($r.Error) { Check 'W2.1.install' 'FAIL' "the installer could not be started: $($r.Error)" }
    elseif ($r.TimedOut) { Check 'W2.1.install' 'FAIL' "timed out after $InstallTimeoutMinutes min; the installer was stopped; $how" }
    elseif ($r.Code -eq 0) { Check 'W2.1.install' 'PASS' "exit=0; duration=$($r.Seconds) s; $how" }
    else { Check 'W2.1.install' 'FAIL' "exit=$($r.Code); duration=$($r.Seconds) s; $how; see the installer log named in the arguments" }
  }
}

function Invoke-InstallPolicy {
  $id = 'W2.5.policy-file:install'
  if ($UserContext) { Check $id 'SKIP' '-InstallPolicy is not run with -UserContext'; return }
  if (-not $IsAdmin) { Check $id 'SKIP' 'refused: -InstallPolicy needs an elevated or SYSTEM session, and this session is neither'; return }
  $lock = Join-Path $RepoDir 'mdm\lockdown-windows.ps1'
  if (-not (Test-Path -LiteralPath $lock -PathType Leaf)) { Check $id 'FAIL' "not found: $lock (check -RepoDir)"; return }
  Invoke-Check $id {
    Write-Action "about to run $lock -StageSources -DeployHooks -InstallUser -DisableUpdates: writes the policy, the hook guards and the staged sources under $(Join-Path $env:ProgramData 'Kiro'), a hook file in every user profile, and UpdateMode under HKLM\SOFTWARE\Policies\Kiro. A policy, hook files or staged sources that are already there are REPLACED (test devices only)"
    $argv = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $lock, '-StageSources') + $WrapperOptions
    $r = Invoke-Child $PsExe64 (ConvertTo-ArgString $argv) $ChildTimeoutSec
    $last = ''
    foreach ($l in ([string]$r.Out -split "`r?`n")) { if ($l.Trim()) { $last = $l.Trim() } }
    if ($r.Code -eq 0) { Check $id 'PASS' "lockdown-windows.ps1 exit=0; duration=$($r.Seconds) s; last line: $last" }
    else { Check $id 'FAIL' "lockdown-windows.ps1 $(Get-RunText $r); last line: $last" }
  }
}

# ------------------------------------------------------------------------------------------------
# W2.1 and W2.3 inventory (read-only)
# ------------------------------------------------------------------------------------------------
function Get-ShortcutTarget([string]$LnkPath) {
  try {
    if ($null -eq $St.Shell) { $St.Shell = New-Object -ComObject WScript.Shell }
    return [string]$St.Shell.CreateShortcut($LnkPath).TargetPath
  } catch { return '(target not read)' }
}

# *.lnk files below a folder, at most $Depth levels down. A Start Menu folder belongs to its user:
# junctions and symbolic links are not entered, so an elevated run cannot be led elsewhere.
function Get-LnkFiles([string]$Dir, [int]$Depth) {
  $out = New-Object System.Collections.Generic.List[string]
  if (Test-ReparsePoint $Dir) { return ,$out }
  try { foreach ($f in [System.IO.Directory]::GetFiles($Dir, '*.lnk')) { $out.Add([string]$f) } } catch { }
  if ($Depth -gt 0) {
    $subs = @()
    try { $subs = @([System.IO.Directory]::GetDirectories($Dir)) } catch { }
    foreach ($d in $subs) { foreach ($f in (Get-LnkFiles $d ($Depth - 1))) { $out.Add([string]$f) } }
  }
  return ,$out
}

function Get-KiroShortcuts([string]$Dir) {
  $res = New-Object System.Collections.Generic.List[string]
  if (-not $Dir -or -not (Test-Path -LiteralPath $Dir -PathType Container)) { return ,$res }
  foreach ($f in (Get-LnkFiles $Dir 4)) {
    if ([System.IO.Path]::GetFileName($f) -match 'kiro') { $res.Add("$f -> $(Get-ShortcutTarget $f)") }
  }
  return ,$res
}

function Test-Inventory {
  $St.Entries = New-Object System.Collections.Generic.List[object]
  $programFiles = $env:ProgramW6432
  if (-not $programFiles) { $programFiles = $env:ProgramFiles }
  $expected = Join-Path $programFiles 'Kiro'
  $profiles = Get-ProfileDirs

  Invoke-Check 'W2.1.uninstall-entry' {
    $sub = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    $sets = New-Object System.Collections.Generic.List[object]
    $sets.Add(@{ Hive = 'LocalMachine'; View = 'Registry64'; Path = $sub; Id = 'hklm64'; Label = 'HKLM 64-bit view (native)' })
    if ([Environment]::Is64BitOperatingSystem) { $sets.Add(@{ Hive = 'LocalMachine'; View = 'Registry32'; Path = $sub; Id = 'hklm32'; Label = 'HKLM 32-bit view (WOW6432Node)' }) }
    $sets.Add(@{ Hive = 'CurrentUser'; View = 'Registry64'; Path = $sub; Id = 'hkcu'; Label = 'HKCU of this account' })
    if ($IsAdmin) {
      try {
        foreach ($sid in (Get-LoadedUserSids)) { $sets.Add(@{ Hive = 'Users'; View = 'Registry64'; Path = ($sid + '\' + $sub); Id = 'hku'; Label = "HKEY_USERS\$sid (another signed-in user)" }) }
      } catch { }
    }
    foreach ($s in $sets) {
      $entries = $null
      try { $entries = Get-UninstallEntries $s.Hive $s.View $s.Path $s.Id $s.Label }
      catch { Check "W2.1.uninstall-entry:$($s.Id)" 'FAIL' "cannot read $($s.Label): $($_.Exception.Message)"; continue }
      foreach ($e in $entries) {
        $St.Entries.Add($e)
        Check "W2.1.uninstall-entry:$($e.ViewId)" 'INFO' "view=$($e.Label); key=$($e.Key); DisplayName=$($e.DisplayName); DisplayVersion=$($e.DisplayVersion); InstallLocation=$($e.InstallLocation); UninstallString=$($e.UninstallString); QuietUninstallString=$($e.QuietUninstallString)"
      }
    }
    if ($St.Entries.Count -eq 0) { Check 'W2.1.uninstall-entry' 'SKIP' 'no Uninstall entry whose DisplayName starts with Kiro (HKLM 64-bit view, HKLM 32-bit view, HKCU)' }
  }

  # System-wide install folder: InstallLocation of an HKLM entry, else the expected folder.
  $folder = ''; $source = ''
  foreach ($e in $St.Entries) {
    if (($e.ViewId -like 'hklm*') -and $e.InstallLocation) {
      $folder = $e.InstallLocation.Trim().Trim('"').TrimEnd('\')
      $source = "InstallLocation of the Uninstall entry in the $($e.Label)"
      break
    }
  }
  if (-not $folder -and (Test-Path -LiteralPath $expected -PathType Container)) { $folder = $expected; $source = 'the expected folder exists (no HKLM Uninstall entry names a folder)' }
  $St.SystemFolder = $folder

  Invoke-Check 'W2.1.install-folder' {
    if (-not $folder) { Check 'W2.1.install-folder' 'SKIP' "no system-wide install found: no HKLM Uninstall entry names a folder and the expected $expected does not exist"; return }
    $exists = Test-Path -LiteralPath $folder -PathType Container
    $same = [string]::Equals($folder, $expected, [System.StringComparison]::OrdinalIgnoreCase)
    Check 'W2.1.install-folder' 'INFO' "folder=$folder; exists=$exists; expected=$expected; matches the expected folder=$same; source: $source"
  }

  Invoke-Check 'W2.1.exe' {
    if (-not $folder -or -not (Test-Path -LiteralPath $folder -PathType Container)) { Check 'W2.1.exe' 'SKIP' 'no system-wide install folder to look in'; return }
    $exe = Join-Path $folder 'Kiro.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
      $names = @(Get-ChildItem -LiteralPath $folder -Filter '*.exe' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
      Check 'W2.1.exe' 'INFO' "no Kiro.exe in $folder; executables there: $($names -join ', ')"
      return
    }
    $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe)
    $sigText = 'not read'
    try {
      $sig = Get-AuthenticodeSignature -LiteralPath $exe
      $subject = '(none)'
      if ($null -ne $sig.SignerCertificate) { $subject = [string]$sig.SignerCertificate.Subject }
      $sigText = "$($sig.Status), signer [$subject]"
    } catch { }
    $readable = $false
    try { $fs = [System.IO.File]::OpenRead($exe); $fs.Dispose(); $readable = $true } catch { }
    Check 'W2.1.exe' 'INFO' "path=$exe; file version=$($vi.FileVersion); product version=$($vi.ProductVersion); product name=$($vi.ProductName); signature=$sigText; readable by this account=$readable"
  }

  Invoke-Check 'W2.1.path' {
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($scope in 'Machine', 'User') {
      $value = [Environment]::GetEnvironmentVariable('Path', $scope)
      $hits = @()
      if ($value) { $hits = @($value.Split(';') | Where-Object { $_ -match 'kiro' }) }
      $label = 'machine PATH'
      if ($scope -eq 'User') { $label = 'user PATH of this account' }
      if ($hits.Count -gt 0) { $parts.Add("${label}: $($hits -join ' | ')") } else { $parts.Add("${label}: none") }
    }
    $cmds = @(Get-Command -Name 'kiro', 'kiro-cli' -CommandType Application -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name) -> $($_.Path)" })
    if ($cmds.Count -gt 0) { $parts.Add("commands found on the PATH of this process: $($cmds -join ' | ')") } else { $parts.Add('commands found on the PATH of this process: none (kiro, kiro-cli)') }
    Check 'W2.1.path' 'INFO' ([string]::Join('; ', $parts.ToArray()))
  }

  Invoke-Check 'W2.1.start-menu' {
    $parts = New-Object System.Collections.Generic.List[string]
    $common = Get-KiroShortcuts ([Environment]::GetFolderPath('CommonPrograms'))
    if ($common.Count -gt 0) { $parts.Add("all users: $([string]::Join(' | ', $common.ToArray()))") } else { $parts.Add('all users: none') }
    $mine = New-Object System.Collections.Generic.List[string]
    foreach ($p in $profiles) {
      foreach ($x in (Get-KiroShortcuts (Join-Path $p 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs'))) { $mine.Add($x) }
    }
    if ($mine.Count -gt 0) { $parts.Add("per user: $([string]::Join(' | ', $mine.ToArray()))") } else { $parts.Add("per user: none ($($profiles.Count) profile(s) searched)") }
    Check 'W2.1.start-menu' 'INFO' ([string]::Join('; ', $parts.ToArray()))
  }

  Invoke-Check 'W2.3.per-user-build' {
    $perUser = New-Object System.Collections.Generic.List[string]
    foreach ($e in $St.Entries) {
      if ($e.ViewId -like 'hklm*') { continue }
      $perUser.Add("Uninstall entry in $($e.Label): $($e.DisplayName) $($e.DisplayVersion) at $($e.InstallLocation)")
    }
    foreach ($p in $profiles) {
      $programs = Join-Path $p 'AppData\Local\Programs'
      if (-not (Test-Path -LiteralPath $programs -PathType Container)) { continue }
      $dirs = @()
      try { $dirs = @([System.IO.Directory]::GetDirectories($programs, 'Kiro*')) } catch { }
      foreach ($d in $dirs) {
        $ver = ''
        $exe = Join-Path $d 'Kiro.exe'
        if (Test-Path -LiteralPath $exe -PathType Leaf) { try { $ver = " (Kiro.exe $([System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe).FileVersion))" } catch { } }
        $perUser.Add("folder $d$ver")
      }
    }
    $system = 'none found'
    if ($folder) { $system = $folder }
    if ($perUser.Count -eq 0) {
      Check 'W2.3.per-user-build' 'INFO' "none: no per-user install found (HKCU Uninstall entries, AppData\Local\Programs\Kiro* in $($profiles.Count) profile(s)); system-wide install: $system"
    } else {
      $both = [bool]$folder
      Check 'W2.3.per-user-build' 'INFO' "per-user: $([string]::Join(' | ', $perUser.ToArray())); system-wide install: $system; both present=$both; which one starts, and what carries over, is manual (W2.3)"
    }
  }
}

# ------------------------------------------------------------------------------------------------
# W2.4 UpdateMode, W2.5 policy file (read-only)
# ------------------------------------------------------------------------------------------------
function Test-UpdateMode {
  Invoke-Check 'W2.4.updatemode' {
    $texts = New-Object System.Collections.Generic.List[string]
    $shown = New-Object System.Collections.Generic.List[string]
    foreach ($view in 'Registry64', 'Registry32') {
      $r = Get-RegValues 'LocalMachine' $view 'SOFTWARE\Policies\Kiro' @('UpdateMode')
      $t = 'key not present'
      if ($r.Exists) {
        $t = 'UpdateMode not set'
        if ($r.Vals.ContainsKey('UpdateMode')) { $t = "UpdateMode=$($r.Vals['UpdateMode']) ($($r.Kinds['UpdateMode']))" }
        $others = @($r.AllNames | Where-Object { $_ -and ($_ -ne 'UpdateMode') })
        if ($others.Count -gt 0) { $t = "$t, other value names: $($others -join ', ')" }
      }
      $texts.Add($t)
      $label = '64-bit view'
      if ($view -eq 'Registry32') { $label = '32-bit view' }
      $shown.Add("${label}: $t")
    }
    $d = "HKLM\SOFTWARE\Policies\Kiro, $([string]::Join('; ', $shown.ToArray())); what Kiro shows in Help > About is manual (W2.4)"
    if ($texts[0] -cne $texts[1]) { Check 'W2.4.updatemode' 'FAIL' "the two registry views differ: $d" }
    else { Check 'W2.4.updatemode' 'INFO' $d }
  }
}

function Test-PolicyFile {
  Invoke-Check 'W2.5.policy-file' {
    $id = 'W2.5.policy-file'
    if (Test-ReparsePoint $PolicyFile) { Check $id 'FAIL' "$PolicyFile is a symbolic link"; return }
    if (-not (Test-Path -LiteralPath $PolicyFile -PathType Leaf)) { Check $id 'FAIL' "not found: $PolicyFile (deploy the policy first, for example with -InstallPolicy)"; return }
    $problems = New-Object System.Collections.Generic.List[string]
    $facts = New-Object System.Collections.Generic.List[string]
    $bytes = [System.IO.File]::ReadAllBytes($PolicyFile)
    $facts.Add("size=$($bytes.Length)")
    if (($bytes.Length -ge 3) -and ($bytes[0] -eq 0xEF) -and ($bytes[1] -eq 0xBB) -and ($bytes[2] -eq 0xBF)) { $problems.Add('starts with a UTF-8 BOM') }
    elseif (($bytes.Length -ge 2) -and ((($bytes[0] -eq 0xFF) -and ($bytes[1] -eq 0xFE)) -or (($bytes[0] -eq 0xFE) -and ($bytes[1] -eq 0xFF)))) { $problems.Add('is UTF-16 (starts with a UTF-16 BOM)') }
    else { $facts.Add('no BOM') }
    $text = $null
    try { $text = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes) } catch { $problems.Add('is not valid UTF-8') }
    if ($null -ne $text) {
      $json = $text.TrimStart([char]0xFEFF)
      if ($json -notmatch '^\s*\{') {
        $problems.Add('the top level is not a JSON object')
      } else {
        $obj = $null
        try { $obj = $json | ConvertFrom-Json } catch { $problems.Add("does not parse as JSON: $($_.Exception.Message)") }
        if ($null -ne $obj) {
          $facts.Add('parses as JSON')
          $prop = $obj.PSObject.Properties['rules']
          if ($null -eq $prop) {
            $problems.Add('has no "rules" field')
          } else {
            $rules = @()
            if ($null -ne $prop.Value) { $rules = @($prop.Value) }
            $deny = @($rules | Where-Object { $_.effect -ceq 'deny' }).Count
            $ask = @($rules | Where-Object { $_.effect -ceq 'ask' }).Count
            $facts.Add("rules=$($rules.Count) (deny=$deny, ask=$ask)")
            if (($deny + $ask) -ne $rules.Count) { $problems.Add('has a rule whose effect is not deny or ask (Kiro rejects the whole file)') }
          }
        }
      }
    }
    try {
      if (Test-UsersDeny $PolicyFile) { $facts.Add('Users DENY ACE present') } else { $problems.Add('has no DENY ACE for BUILTIN\Users') }
    } catch { $problems.Add("its ACL cannot be read: $($_.Exception.Message)") }
    if (-not $IsAdmin) {
      # Opening for write changes nothing; it only shows whether this account could write.
      $writable = $false
      try { $fs = [System.IO.File]::Open($PolicyFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite); $fs.Dispose(); $writable = $true } catch { }
      if ($writable) { $problems.Add('this account, which is not elevated, can open the file for writing') } else { $facts.Add('not writable by this account') }
    }
    $facts.Add("sha256=$(Get-FileSha256 $PolicyFile)")
    $tail = 'whether Kiro enforces it is manual (W2.5, W2.6)'
    if ($problems.Count -eq 0) { Check $id 'PASS' "$([string]::Join('; ', $facts.ToArray())); $tail" }
    else { Check $id 'FAIL' "$PolicyFile $([string]::Join('; ', $problems.ToArray())); also: $([string]::Join('; ', $facts.ToArray())); $tail" }
  }
}

# ------------------------------------------------------------------------------------------------
# W2.10 Intune wrappers
# ------------------------------------------------------------------------------------------------
# Runs one script in a child PowerShell of its own bitness and writes <Prefix>.out, .err and .rc.
$TaskRunnerText = @'
param([string]$Target, [string]$Prefix, [int]$TimeoutSec = 600)
# w2-task-runner.ps1 - written by Invoke-W2Checks.ps1; started as SYSTEM by a one-shot scheduled task.
$rc = -998; $out = ''; $err = ''
try {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = Join-Path $PSHOME 'powershell.exe'
  $psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $Target + '"'
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  try { $p.StandardInput.Close() } catch { }
  $outTask = $p.StandardOutput.ReadToEndAsync()
  $errTask = $p.StandardError.ReadToEndAsync()
  if ($p.WaitForExit($TimeoutSec * 1000)) { $rc = [int]$p.ExitCode } else { $rc = -999; try { $p.Kill() } catch { } }
  try { if ($outTask.Wait(5000)) { $out = [string]$outTask.Result } } catch { }
  try { if ($errTask.Wait(5000)) { $err = [string]$errTask.Result } } catch { }
} catch { $err = 'w2-task-runner: ' + $_.Exception.Message }
$enc = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText("$Prefix.out", $out, $enc)
[System.IO.File]::WriteAllText("$Prefix.err", $err, $enc)
[System.IO.File]::WriteAllText("$Prefix.rc.tmp", [string]$rc, $enc)
[System.IO.File]::Move("$Prefix.rc.tmp", "$Prefix.rc")
'@

# '' when <OutDir>\wrappers is ready, else the reason. It holds scripts that run as SYSTEM.
function Initialize-WrapperDir {
  if (Test-ReparsePoint $WrapDir) { return "$WrapDir is a junction or symbolic link" }
  if (-not $IsAdmin) {
    if (-not (Test-Path -LiteralPath $WrapDir -PathType Container)) { $null = New-Item -ItemType Directory -Path $WrapDir -Force }
    return ''
  }
  if ($St.OutDirProblem) { return "refusing to run scripts as SYSTEM from ${OutDir}: $($St.OutDirProblem). Use an -OutDir that does not exist yet, or one that only administrators control" }
  $isNew = $false
  if (Test-Path -LiteralPath $WrapDir -PathType Container) {
    $why = Test-AdminControlled $WrapDir
    if ($why) { return "refusing to run scripts as SYSTEM from ${WrapDir}: $why. Remove the folder as an administrator" }
  } else {
    $null = New-Item -ItemType Directory -Path $WrapDir
    $isNew = $true
  }
  $why = Lock-AdminDir $WrapDir
  if ($why) { return "cannot lock ${WrapDir}: $why" }
  if ($isNew -and (@([System.IO.Directory]::GetFileSystemEntries($WrapDir)).Count -ne 0)) { return "something was placed in the new folder $WrapDir before it was locked. Remove the folder as an administrator" }
  return ''
}

# Copies a wrapper to <OutDir>\wrappers with its $Options line set (as New-Wrapper in windows-suite.ps1).
function New-WrapperCopy([string]$Name) {
  $src = Join-Path $RepoDir "mdm\intune\$Name"
  $t = [System.IO.File]::ReadAllText($src)
  $rx = New-Object System.Text.RegularExpressions.Regex('(?m)^\$Options = .*$')
  if (-not $rx.IsMatch($t)) { throw "no `$Options line in $src" }
  $line = '$Options = @(' + (($WrapperOptions | ForEach-Object { "'$_'" }) -join ', ') + ')'
  $t = $rx.Replace($t, $line.Replace('$', '$$'), 1)
  # The wrapper logs stay in -OutDir, not in the Intune Management Extension log folder of the device.
  $logRx = New-Object System.Text.RegularExpressions.Regex('(?m)^\$LogFile = .*$')
  if (-not $logRx.IsMatch($t)) { throw "no `$LogFile line in $src" }
  $logLine = '$LogFile = ' + "'" + ((Join-Path $WrapDir ([System.IO.Path]::GetFileNameWithoutExtension($Name) + '.log')) -replace "'", "''") + "'"
  $t = $logRx.Replace($t, $logLine.Replace('$', '$$'), 1)
  $dest = Join-Path $WrapDir $Name
  Write-NewFile $dest ($Utf8NoBom.GetBytes($t))
  return $dest
}

# Runs one script as SYSTEM through a one-shot scheduled task and returns the same shape as Invoke-Child.
function Invoke-AsSystemTask([string]$Context, [string]$ScriptPath, [int]$TimeoutSec) {
  $r = @{ Code = $null; Out = ''; Err = ''; TimedOut = $false; Seconds = 0; Error = '' }
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  # The Task Scheduler service is 64-bit: System32 is the 64-bit PowerShell there.
  $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  if ($Context -eq 'system32') { $exe = $PsExe32 }
  $prefix = Join-Path $WrapDir ('run-' + [guid]::NewGuid().ToString('N'))
  $name = 'KiroW2-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
  $argString = ConvertTo-ArgString @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $St.Runner, '-Target', $ScriptPath, '-Prefix', $prefix, '-TimeoutSec', "$TimeoutSec")
  $registered = $false
  try {
    $action = New-ScheduledTaskAction -Execute $exe -Argument $argString -ErrorAction Stop
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Seconds ($TimeoutSec + 120)) -ErrorAction Stop
    # The SID is locale-independent; the account name is the fallback.
    $problem = $null
    foreach ($account in $SidSystem, 'SYSTEM') {
      try {
        $principal = New-ScheduledTaskPrincipal -UserId $account -LogonType ServiceAccount -RunLevel Highest -ErrorAction Stop
        $null = Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -Force -ErrorAction Stop
        $registered = $true
        break
      } catch { $problem = $_ }
    }
    if (-not $registered) { throw $problem }
    Start-ScheduledTask -TaskName $name -ErrorAction Stop
    $started = Get-Date
    $deadline = $started.AddSeconds($TimeoutSec + 60)
    $ended = $false
    while ((-not (Test-Path -LiteralPath "$prefix.rc")) -and ((Get-Date) -lt $deadline)) {
      Start-Sleep -Milliseconds 500
      # A task that is neither queued nor running and left no result did not run the script.
      if (((Get-Date) - $started).TotalSeconds -gt 20) {
        $state = ''
        try { $state = [string](Get-ScheduledTask -TaskName $name -ErrorAction Stop).State } catch { }
        if ($state -and ($state -ne 'Running') -and ($state -ne 'Queued')) { Start-Sleep -Seconds 2; $ended = $true; break }
      }
    }
    if (Test-Path -LiteralPath "$prefix.rc") {
      $code = 0
      $rcText = ([System.IO.File]::ReadAllText("$prefix.rc")).Trim()
      if (-not [int]::TryParse($rcText, [ref]$code)) { $r.Error = "the task wrote an exit code that is not a number: [$rcText]" }
      elseif ($code -eq -999) { $r.TimedOut = $true }
      else { $r.Code = $code }
      try { $r.Out = [System.IO.File]::ReadAllText("$prefix.out") } catch { }
      try { $r.Err = [System.IO.File]::ReadAllText("$prefix.err") } catch { }
      if (($code -eq -998) -and -not $r.Error) { $r.Code = $null; $r.Error = "the task could not start the script: $(Get-FirstLine $r.Err)" }
    } elseif ($ended) {
      $last = ''
      try { $last = [string](Get-ScheduledTaskInfo -TaskName $name -ErrorAction Stop).LastTaskResult } catch { }
      $r.Error = "the scheduled task ended without a result (LastTaskResult=$last)"
    } else {
      $r.TimedOut = $true
      try { Stop-ScheduledTask -TaskName $name -ErrorAction Stop } catch { }
    }
  } catch {
    $r.Error = "scheduled task: $($_.Exception.Message)"
  } finally {
    if ($registered) { try { Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop } catch { } }
    foreach ($ext in '.out', '.err', '.rc', '.rc.tmp') { try { [System.IO.File]::Delete($prefix + $ext) } catch { } }
  }
  $sw.Stop()
  $r.Seconds = [int]$sw.Elapsed.TotalSeconds
  return $r
}

function Invoke-Wrapper([string]$Context, [string]$ScriptPath) {
  if (($Context -eq 'user') -or $IsSystem) {
    $exe = $PsExe64
    if ($Context -eq 'system32') { $exe = $PsExe32 }
    return (Invoke-Child $exe (ConvertTo-ArgString @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath)) $ChildTimeoutSec)
  }
  return (Invoke-AsSystemTask $Context $ScriptPath $ChildTimeoutSec)
}

# Intune reads a Win32 detection script as "detected" only on exit 0 with STDOUT and no STDERR.
function Test-Win32Detected($R) {
  return (($R.Code -eq 0) -and (([string]$R.Out).Trim() -ne '') -and (([string]$R.Err).Length -eq 0))
}

function Test-WrapperContext([string]$Ctx) {
  $p = "W2.10.$Ctx"
  if (($Ctx -eq 'system32') -and (-not $PsExe32 -or -not (Test-Path -LiteralPath $PsExe32 -PathType Leaf))) {
    Check "$p.detect-compliant" 'SKIP' 'no 32-bit Windows PowerShell on this device (SysWOW64)'
    return
  }
  $compliant = $false
  try {
    $r = Invoke-Wrapper $Ctx $St.Detect
    if (($r.Code -eq 0) -and (([string]$r.Out).Trim() -like 'COMPLIANT*')) { $compliant = $true; Check "$p.detect-compliant" 'PASS' "exit=0; $(Get-FirstLine $r.Out)" }
    else { Check "$p.detect-compliant" 'FAIL' "$(Get-RunText $r) (expected exit 0 and COMPLIANT; deploy the policy first with -InstallPolicy)" }
  } catch { Check "$p.detect-compliant" 'FAIL' "the check stopped with an error: $($_.Exception.Message)" }
  try {
    $r = Invoke-Wrapper $Ctx $St.Win32
    if (Test-Win32Detected $r) { Check "$p.win32-detected" 'PASS' "exit=0; stdout=[$(Get-FirstLine $r.Out)]; stderr is empty" }
    else { Check "$p.win32-detected" 'FAIL' "$(Get-RunText $r); stderr length=$(([string]$r.Err).Length) (expected exit 0, text on STDOUT, nothing on STDERR)" }
  } catch { Check "$p.win32-detected" 'FAIL' "the check stopped with an error: $($_.Exception.Message)" }

  if (-not $TamperTest) { return }
  if (-not $compliant) { Check "$p.detect-drift" 'SKIP' 'tamper test not run: the device was not compliant before it (see detect-compliant)'; return }
  $before = Get-FileSha256 $PolicyFile
  # One try owns the restore: a tamper step that fails half-way (the DENY entry removed, the append
  # refused) is undone as well.
  try {
    $tampered = $false
    try {
      Write-Action "about to tamper with $PolicyFile for context ${Ctx}: remove the Users DENY entry and append one space; the remediation wrapper then restores the file"
      $r = Invoke-Child $Icacls (ConvertTo-ArgString @($PolicyFile, '/remove:d', "*$SidUsers")) 60
      if ($r.Code -ne 0) { throw "icacls /remove:d failed: $(Get-RunText $r)" }
      [System.IO.File]::AppendAllText($PolicyFile, ' ', $Utf8NoBom)
      $tampered = $true
    } catch {
      Check "$p.detect-drift" 'FAIL' "the tamper step failed, so the tamper test was not run: $($_.Exception.Message)"
    }
    if ($tampered) {
      try {
        $r = Invoke-Wrapper $Ctx $St.Detect
        if (($r.Code -eq 1) -and (([string]$r.Out).Trim() -like 'NON-COMPLIANT*')) { Check "$p.detect-drift" 'PASS' "exit=1; $(Get-FirstLine $r.Out)" }
        else { Check "$p.detect-drift" 'FAIL' "$(Get-RunText $r) (expected exit 1 and NON-COMPLIANT)" }
      } catch { Check "$p.detect-drift" 'FAIL' "the check stopped with an error: $($_.Exception.Message)" }
      try {
        $r = Invoke-Wrapper $Ctx $St.Win32
        if (($null -ne $r.Code) -and ($r.Code -ne 0) -and (([string]$r.Out).Trim() -eq '') -and (([string]$r.Err).Length -eq 0)) { Check "$p.win32-not-detected" 'PASS' "exit=$($r.Code); nothing on STDOUT or STDERR" }
        else { Check "$p.win32-not-detected" 'FAIL' "$(Get-RunText $r) (expected a non-zero exit and no output)" }
      } catch { Check "$p.win32-not-detected" 'FAIL' "the check stopped with an error: $($_.Exception.Message)" }
      try {
        $r = Invoke-Wrapper $Ctx $St.Remediate
        if (($r.Code -eq 0) -and (([string]$r.Out).Trim() -like 'REMEDIATED*')) { Check "$p.remediate" 'PASS' "exit=0; $(Get-FirstLine $r.Out)" }
        else { Check "$p.remediate" 'FAIL' "$(Get-RunText $r) (expected exit 0 and REMEDIATED)" }
      } catch { Check "$p.remediate" 'FAIL' "the check stopped with an error: $($_.Exception.Message)" }
      try {
        $r = Invoke-Wrapper $Ctx $St.Detect
        $after = Get-FileSha256 $PolicyFile
        if (($r.Code -eq 0) -and ($after -eq $before)) { Check "$p.detect-after-remediate" 'PASS' "exit=0; $(Get-FirstLine $r.Out); the policy file has the hash it had before the tamper" }
        else { Check "$p.detect-after-remediate" 'FAIL' "$(Get-RunText $r); policy sha256 before=$before after=$after" }
      } catch { Check "$p.detect-after-remediate" 'FAIL' "the check stopped with an error: $($_.Exception.Message)" }
    }
  } finally {
    # Whatever happened above (a failed tamper step or wrapper, a timeout, Ctrl+C), the policy must end as it began.
    $restored = ((Get-FileSha256 $PolicyFile) -eq $before) -and (Test-UsersDeny $PolicyFile)
    if (-not $restored) {
      Write-Action "the tamper test left $PolicyFile changed; restoring it with the staged lockdown-windows.ps1"
      try {
        $argv = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $StagedLockdown) + $WrapperOptions
        $null = Invoke-Child $PsExe64 (ConvertTo-ArgString $argv) $ChildTimeoutSec
      } catch { }
      $restored = ((Get-FileSha256 $PolicyFile) -eq $before) -and (Test-UsersDeny $PolicyFile)
      if ($restored) { Write-Note "$PolicyFile was restored after the tamper test" }
      else { Check "$p.detect-after-remediate" 'FAIL' "$PolicyFile is NOT as it was before the tamper test (content or the Users DENY entry). Run this script with -InstallPolicy as an administrator to restore it" }
    }
  }
}

function Test-UserWrappers {
  $p = 'W2.10.user'
  if ($IsAdmin) { Check "$p.detect" 'SKIP' 'this session is elevated or SYSTEM; run -UserContext -Wrappers as the logged-on standard user'; return }
  if (-not (Test-Path -LiteralPath $StagedLockdown -PathType Leaf)) { Check "$p.detect" 'SKIP' "staged script not found ($StagedLockdown); run -InstallPolicy as SYSTEM or elevated first"; return }
  try {
    $r = Invoke-Wrapper 'user' $St.Detect
    if ($r.Error -or $r.TimedOut) { Check "$p.detect" 'FAIL' (Get-RunText $r) }
    else { Check "$p.detect" 'INFO' "detection wrapper as the logged-on user: exit=$($r.Code); first output line: $(Get-FirstLine $r.Out)" }
  } catch { Check "$p.detect" 'FAIL' "the check stopped with an error: $($_.Exception.Message)" }
  try {
    $before = Get-FileSha256 $PolicyFile
    if (-not $before) { Check "$p.remediate-refused" 'SKIP' "the policy file $PolicyFile is missing or not readable, so there is nothing to compare"; return }
    $r = Invoke-Wrapper 'user' $St.Remediate
    $after = Get-FileSha256 $PolicyFile
    if (($r.Code -eq 1) -and ($after -eq $before)) { Check "$p.remediate-refused" 'PASS' "exit=1; the policy file is unchanged; $(Get-FirstLine $r.Out)" }
    else { Check "$p.remediate-refused" 'FAIL' "$(Get-RunText $r); policy sha256 before=$before after=$after (expected exit 1 and an unchanged file)" }
  } catch { Check "$p.remediate-refused" 'FAIL' "the check stopped with an error: $($_.Exception.Message)" }
}

function Test-Wrappers {
  $first = 'W2.10.system64.detect-compliant'
  if ($UserContext) { $first = 'W2.10.user.detect' }
  if (-not $UserContext -and -not $IsAdmin) {
    Check 'W2.10.system64.detect-compliant' 'SKIP' 'not elevated: the SYSTEM contexts need an elevated or SYSTEM session'
    Check 'W2.10.system32.detect-compliant' 'SKIP' 'not elevated: the SYSTEM contexts need an elevated or SYSTEM session'
    Check 'W2.10.user.detect' 'SKIP' 'context user runs only with -UserContext'
    if ($TamperTest) { Check 'W2.10.system64.detect-drift' 'SKIP' 'refused: -TamperTest needs an elevated or SYSTEM session, and this session is neither' }
    return
  }
  if ($UserContext -and $TamperTest) { Check 'W2.10.user.detect-drift' 'SKIP' 'refused: -TamperTest is not run with -UserContext; it needs an elevated or SYSTEM session' }
  if ($UserContext -and $IsAdmin) { Test-UserWrappers; return }
  try {
    foreach ($n in 'Detect-KiroPolicy.ps1', 'Remediate-KiroPolicy.ps1', 'Detect-KiroPolicy-Win32.ps1') {
      $src = Join-Path $RepoDir "mdm\intune\$n"
      if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { throw "not found: $src (check -RepoDir)" }
    }
    $why = Initialize-WrapperDir
    if ($why) { throw $why }
    $St.Detect = New-WrapperCopy 'Detect-KiroPolicy.ps1'
    $St.Remediate = New-WrapperCopy 'Remediate-KiroPolicy.ps1'
    $St.Win32 = New-WrapperCopy 'Detect-KiroPolicy-Win32.ps1'
    if ($IsAdmin -and -not $IsSystem) {
      $St.Runner = Join-Path $WrapDir 'w2-task-runner.ps1'
      Write-NewFile $St.Runner ($Utf8NoBom.GetBytes($TaskRunnerText))
      Write-Action 'about to register one-shot scheduled tasks named KiroW2-<id> that run the wrappers as SYSTEM; each task is removed after its run'
    }
  } catch {
    Check $first 'FAIL' "the wrappers could not be prepared: $($_.Exception.Message)"
    return
  }
  if ($UserContext) { Test-UserWrappers; return }
  foreach ($ctx in 'system64', 'system32') { Test-WrapperContext $ctx }
  Check 'W2.10.user.detect' 'SKIP' 'context user: run this script with -UserContext -Wrappers as the logged-on standard user'
}

# ------------------------------------------------------------------------------------------------
# W2.7, W2.8, W2.9 probes (current user's profile)
# ------------------------------------------------------------------------------------------------
function Get-ProbePaths {
  if (-not $env:LOCALAPPDATA -or -not $env:USERPROFILE) { throw 'LOCALAPPDATA or USERPROFILE is not set for this account' }
  $kiro = Join-Path $env:USERPROFILE '.kiro'
  $probeDir = Join-Path $env:LOCALAPPDATA 'KiroW2'
  return @{
    ProbeDir = $probeDir
    Probe = (Join-Path $probeDir 'hook-probe.ps1')
    Log = (Join-Path $probeDir 'hook-probe.log')
    Kiro = $kiro
    HooksDir = (Join-Path $kiro 'hooks')
    SteeringDir = (Join-Path $kiro 'steering')
    HookFile = (Join-Path (Join-Path $kiro 'hooks') 'w2-probe.json')
    SteeringFile = (Join-Path (Join-Path $kiro 'steering') 'w2-steering-probe.md')
  }
}

# '' or the first folder that is a junction or symbolic link.
function Get-ProbeLink($P) {
  foreach ($d in @($P.ProbeDir, $P.Kiro, $P.HooksDir, $P.SteeringDir)) { if (Test-ReparsePoint $d) { return $d } }
  return ''
}

# 'absent', 'kit' (holds the w2-probe marker) or 'foreign'.
function Get-KitFileState([string]$Path) {
  if (Test-ReparsePoint $Path) { return 'foreign' }
  if (Test-Path -LiteralPath $Path -PathType Container) { return 'foreign' }
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'absent' }
  if ((Get-Item -LiteralPath $Path -Force).Length -gt 1048576) { return 'foreign' }
  if ([System.IO.File]::ReadAllText($Path) -match 'w2-probe') { return 'kit' }
  return 'foreign'
}

function Get-SteeringMarker([string]$Path) {
  try {
    if ((Get-KitFileState $Path) -eq 'kit') {
      $m = [regex]::Match([System.IO.File]::ReadAllText($Path), 'W2-STEERING-[0-9a-f]{8}')
      if ($m.Success) { return $m.Value }
    }
  } catch { }
  return ''
}

function Format-ProbeTime($Value) {
  if ($Value -is [DateTime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture) }
  return [string]$Value
}

function Install-Probes {
  if ($IsSystem) { Check 'W2.7.probe' 'SKIP' 'refused: SYSTEM has no Kiro session; run -InstallProbes as the logged-on user'; return }
  Invoke-Check 'W2.7.probe' {
    $P = Get-ProbePaths
    $src = Join-Path $PSScriptRoot 'hook-probe.ps1'
    if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { Check 'W2.7.probe' 'FAIL' "not found: $src"; return }
    $link = Get-ProbeLink $P
    if ($link) { Check 'W2.7.probe' 'SKIP' "refused: $link is a junction or symbolic link; nothing was written"; return }
    foreach ($f in @($P.Probe, $P.HookFile, $P.SteeringFile)) {
      if ((Get-KitFileState $f) -eq 'foreign') { Check 'W2.7.probe' 'SKIP' "refused: $f exists and was not created by this kit (no w2-probe marker); nothing was written"; return }
    }
    Write-Action "about to write in the profile of the account that runs this script: $($P.Probe), $($P.HookFile) and $($P.SteeringFile). Kiro then starts the probe for every tool call of this user until -RemoveProbes"
    foreach ($d in @($P.ProbeDir, $P.Kiro, $P.HooksDir, $P.SteeringDir)) {
      if (-not (Test-Path -LiteralPath $d -PathType Container)) { $null = New-Item -ItemType Directory -Path $d -Force }
    }
    $link = Get-ProbeLink $P
    if ($link) { Check 'W2.7.probe' 'SKIP' "refused: $link is a junction or symbolic link"; return }
    $marker = Get-SteeringMarker $P.SteeringFile
    if (-not $marker) { $marker = 'W2-STEERING-' + [guid]::NewGuid().ToString('N').Substring(0, 8) }

    Write-NewFile $P.Probe ([System.IO.File]::ReadAllBytes($src))
    $probePath = $P.Probe.Replace('\', '/')
    if ($probePath -match '\s') { $probePath = '"' + $probePath + '"' }
    $command = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + $probePath
    $commandJson = $command.Replace('\', '\\').Replace('"', '\"')
    $hook = @(
      '{',
      '  "version": "v1",',
      '  "hooks": [',
      '    {',
      '      "name": "W2 hook probe (w2-probe)",',
      '      "description": "w2-probe: records that a hook was called and by which process chain. Created by Invoke-W2Checks.ps1 -InstallProbes; remove with -RemoveProbes",',
      '      "trigger": "PreToolUse",',
      '      "matcher": "*",',
      ('      "action": { "type": "command", "command": "' + $commandJson + '" },'),
      '      "timeout": 10,',
      '      "enabled": true',
      '    }',
      '  ]',
      '}',
      ''
    )
    Write-NewFile $P.HookFile ($Utf8NoBom.GetBytes(($hook -join "`n")))
    $steering = @(
      '# W2 steering probe (w2-probe)',
      '',
      'This file was created by security-tests/windows-client/Invoke-W2Checks.ps1 -InstallProbes on a test device. Remove it with -RemoveProbes.',
      '',
      "If asked for the W2 steering marker, answer exactly: $marker",
      ''
    )
    Write-NewFile $P.SteeringFile ($Utf8NoBom.GetBytes(($steering -join "`n")))

    Check 'W2.7.probe' 'INFO' "installed: $($P.HookFile) starts $($P.Probe) before every tool call. Restart Kiro, make tool calls in Kiro IDE and in kiro-cli, then run -ReadProbes"
    Check 'W2.8.probe' 'INFO' 'block test: ask Kiro to run a shell command that contains W2-BLOCK-TEST (for example: echo W2-BLOCK-TEST). The probe then exits 2; record in the checklist whether Kiro blocked the call'
    Check 'W2.9.probe' 'INFO' "steering marker: $marker in $($P.SteeringFile). In a new Kiro chat ask: What is the W2 steering marker? The answer must be checked in the Kiro chat by hand"
  }
}

function Read-Probes {
  $P = $null
  try { $P = Get-ProbePaths } catch { Check 'W2.7.probe' 'FAIL' $_.Exception.Message; return }
  $records = New-Object System.Collections.Generic.List[object]
  $bad = 0
  Invoke-Check 'W2.7.probe' {
    if (-not (Test-Path -LiteralPath $P.Log -PathType Leaf)) { Check 'W2.7.probe' 'INFO' "no hook call recorded (no $($P.Log))"; return }
    # The probe may be appending while this reads.
    $fs = New-Object System.IO.FileStream($P.Log, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try { $text = (New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)).ReadToEnd() } finally { $fs.Dispose() }
    foreach ($l in ($text -split "`r?`n")) {
      if (-not $l.Trim()) { continue }
      $o = $null
      try { $o = $l | ConvertFrom-Json } catch { }
      if (($null -eq $o) -or ($o -isnot [System.Management.Automation.PSCustomObject])) { $bad++; continue }
      $records.Add($o)
    }
    if ($records.Count -eq 0) { Check 'W2.7.probe' 'INFO' "no hook call recorded ($($P.Log) has no readable line)"; return }
    $clients = @{}; $events = @{}; $unknown = 0; $blocks = 0
    foreach ($o in $records) {
      $client = ''
      if ($null -ne $o.parents) {
        foreach ($n in @($o.parents)) {
          $name = [string]$n
          if ($name -match 'kiro[-_ ]?cli') { $client = "kiro-cli [$name]"; break }
          if ($name -match '^kiro') { $client = "Kiro IDE [$name]"; break }
        }
      }
      if ($client) { $clients[$client] = 1 + [int]$clients[$client] } else { $unknown++ }
      $ev = [string]$o.hook_event_name
      if (-not $ev) { $ev = "(input: $([string]$o.input))" }
      $events[$ev] = 1 + [int]$events[$ev]
      if ($o.block_test -eq $true) { $blocks++ }
    }
    $evText = (@($events.Keys | Sort-Object) | ForEach-Object { "$_=$($events[$_])" }) -join ', '
    $firstRec = $records[0]
    $lastRec = $records[$records.Count - 1]
    $span = "first=$(Format-ProbeTime $firstRec.time_utc); last=$(Format-ProbeTime $lastRec.time_utc)"
    $more = "events: $evText; W2-BLOCK-TEST calls answered with exit 2: $blocks; unreadable lines: $bad; $span"
    if ($clients.Count -gt 0) {
      $clText = (@($clients.Keys | Sort-Object) | ForEach-Object { "$_=$($clients[$_])" }) -join ', '
      Check 'W2.7.probe' 'PASS' "hook calls per client: $clText; calls from other parents: $unknown; $more. The client names are read from process names (verify against the chains in W2.8.probe)"
    } else {
      Check 'W2.7.probe' 'INFO' "$($records.Count) hook call(s) recorded, but no parent process looks like Kiro IDE or kiro-cli (see the chains in W2.8.probe); $more"
    }
  }
  Invoke-Check 'W2.8.probe' {
    if ($records.Count -eq 0) { Check 'W2.8.probe' 'INFO' 'no hook call recorded, so the shell that runs hook commands is not known yet'; return }
    $chains = @{}; $shells = @{}
    foreach ($o in $records) {
      $names = @()
      if ($null -ne $o.parents) { $names = @($o.parents | ForEach-Object { [string]$_ }) }
      $chain = '(no parent recorded)'
      if ($names.Count -gt 0) { $chain = $names -join ' < ' }
      $chains[$chain] = 1 + [int]$chains[$chain]
      $shell = "$([string]$o.ps_edition) $([string]$o.ps_version) $([string]$o.ps_bitness)-bit"
      $shells[$shell] = 1 + [int]$shells[$shell]
    }
    $top = @($chains.Keys | Sort-Object -Property @{ Expression = { $chains[$_] }; Descending = $true } | Select-Object -First 8)
    $chText = ($top | ForEach-Object { "$($chains[$_])x [$_]" }) -join '; '
    $shText = (@($shells.Keys | Sort-Object) | ForEach-Object { "$_ ($($shells[$_])x)" }) -join ', '
    Check 'W2.8.probe' 'INFO' "parent chains of the probe, nearest first ($($chains.Count) distinct): $chText. The first name is the process that started the hook command (the shell, or Kiro itself). Probe ran in: $shText. Whether exit 2 blocked a call must be seen in the Kiro window"
  }
  Invoke-Check 'W2.9.probe' {
    $marker = Get-SteeringMarker $P.SteeringFile
    if ($marker) { Check 'W2.9.probe' 'INFO' "steering marker: $marker in $($P.SteeringFile). Whether Kiro answers with it must be checked in the Kiro chat by hand" }
    else { Check 'W2.9.probe' 'SKIP' "no steering probe found at $($P.SteeringFile); run -InstallProbes first" }
  }
}

function Remove-Probes {
  Invoke-Check 'W2.7.probe' {
    $P = Get-ProbePaths
    $link = Get-ProbeLink $P
    if ($link) { Check 'W2.7.probe' 'SKIP' "refused: $link is a junction or symbolic link; nothing was deleted"; return }
    Write-Action "about to delete the probe files this kit created: $($P.HookFile), $($P.SteeringFile) and $($P.Probe)"
    $removed = New-Object System.Collections.Generic.List[string]
    $kept = New-Object System.Collections.Generic.List[string]
    foreach ($f in @($P.HookFile, $P.SteeringFile, $P.Probe)) {
      $state = Get-KitFileState $f
      if ($state -eq 'kit') { [System.IO.File]::Delete($f); $removed.Add($f) }
      elseif ($state -eq 'foreign') { $kept.Add($f) }
    }
    $d = 'removed: none (no kit file found)'
    if ($removed.Count -gt 0) { $d = "removed: $([string]::Join(', ', $removed.ToArray()))" }
    if ($kept.Count -gt 0) { $d = "$d; left in place because the kit did not create it: $([string]::Join(', ', $kept.ToArray()))" }
    Check 'W2.7.probe' 'INFO' "$d; the log $($P.Log) is kept as evidence. Restart Kiro"
  }
}

# ------------------------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------------------------
if (-not $RepoDir) { $RepoDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
# The sanitizer comes first: the lines about the output folder below name accounts and paths too.
$ProfilesRoot = Get-ProfilesRoot
$script:SanSkipped = $false
try { Initialize-Sanitizer } catch {
  [Console]::Out.WriteLine('CHECK W2.0.context FAIL cannot build the sanitizer; nothing was collected')
  [Console]::Out.WriteLine('PHASE W2 RESULT pass=0 fail=1 skip=0 info=0')
  exit 1
}
if (-not $OutDir) {
  if ($IsAdmin) { $OutDir = Join-Path $env:ProgramData 'KiroW2' }
  elseif ($env:LOCALAPPDATA) { $OutDir = Join-Path $env:LOCALAPPDATA 'KiroW2' }
  else { $OutDir = Join-Path ([System.IO.Path]::GetTempPath()) 'KiroW2' }
}
try {
  if (-not [System.IO.Path]::IsPathRooted($OutDir)) { $OutDir = Join-Path (Get-Location).ProviderPath $OutDir }
  $OutDir = [System.IO.Path]::GetFullPath($OutDir)
  if ($OutDir.Length -gt 3) { $OutDir = $OutDir.TrimEnd('\') }
  if (-not [System.IO.Path]::IsPathRooted($RepoDir)) { $RepoDir = Join-Path (Get-Location).ProviderPath $RepoDir }
  $RepoDir = [System.IO.Path]::GetFullPath($RepoDir)
  if ($RepoDir.Length -gt 3) { $RepoDir = $RepoDir.TrimEnd('\') }
  if (Test-ReparsePoint $OutDir) { throw "$OutDir is a junction or symbolic link" }
  if (Test-Path -LiteralPath $OutDir -PathType Container) {
    if ($IsAdmin) { $St.OutDirProblem = Test-AdminControlled $OutDir }
  } else {
    $null = New-Item -ItemType Directory -Path $OutDir -Force
    # A new folder of an elevated run is locked at once: it will hold scripts that run as SYSTEM.
    if ($IsAdmin) {
      $St.OutDirProblem = Lock-AdminDir $OutDir
      if (-not $St.OutDirProblem -and (@([System.IO.Directory]::GetFileSystemEntries($OutDir)).Count -ne 0)) { $St.OutDirProblem = 'something was placed in the new folder before it was locked' }
    }
  }
} catch {
  [Console]::Out.WriteLine('CHECK W2.0.context FAIL ' + (Format-Detail "cannot use the output folder: $($_.Exception.Message)"))
  [Console]::Out.WriteLine('PHASE W2 RESULT pass=0 fail=1 skip=0 info=0')
  exit 1
}
# An elevated or SYSTEM run writes its results and the installer log there, and runs scripts from it.
if ($IsAdmin -and $St.OutDirProblem) {
  [Console]::Out.WriteLine('CHECK W2.0.context FAIL ' + (Format-Detail "refusing to use the output folder: $($St.OutDirProblem). Use an -OutDir that does not exist yet, or remove the folder as an administrator"))
  [Console]::Out.WriteLine('PHASE W2 RESULT pass=0 fail=1 skip=0 info=0')
  exit 1
}
if ($IsAdmin) {
  $lockWhy = Lock-AdminDir $OutDir
  if ($lockWhy) {
    [Console]::Out.WriteLine('CHECK W2.0.context FAIL ' + (Format-Detail "cannot lock the output folder: $lockWhy"))
    [Console]::Out.WriteLine('PHASE W2 RESULT pass=0 fail=1 skip=0 info=0')
    exit 1
  }
}
$WrapDir = Join-Path $OutDir 'wrappers'
# Unsanitized lines never go into the file that is meant to be published.
$resultsName = 'w2-results.txt'
if ($NoSanitize) { $resultsName = 'w2-results-UNSANITIZED.txt' }
$script:ResultsFile = Join-Path $OutDir $resultsName
if ($InstallerPath) { try { $InstallerPath = (Resolve-Path -LiteralPath $InstallerPath).ProviderPath } catch { } }
if (-not $InstallerArgs) { $InstallerArgs = '/VERYSILENT /SP- /SUPPRESSMSGBOXES /NORESTART /MERGETASKS=!runcode /LOG="' + (Join-Path $OutDir 'kiro-install.log') + '"' }
if ($InstallTimeoutMinutes -lt 1) { $InstallTimeoutMinutes = 15 }

$given = New-Object System.Collections.Generic.List[string]
foreach ($name in 'Install', 'InstallPolicy', 'Wrappers', 'TamperTest', 'UserContext', 'InstallProbes', 'ReadProbes', 'RemoveProbes', 'NoSanitize') {
  if ((Get-Variable -Name $name -ValueOnly)) { $given.Add("-$name") }
}
if ($InstallerPath) { $given.Add('-InstallerPath') }
$probeOnly = (($InstallProbes -or $ReadProbes -or $RemoveProbes) -and -not ($Install -or $InstallerPath -or $InstallPolicy -or $Wrappers -or $TamperTest -or $UserContext))

$fatal = $null
try {
  $switchText = '(none: read-only inventory)'
  if ($given.Count -gt 0) { $switchText = [string]::Join(' ', $given.ToArray()) }
  Write-Note "W2 run $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)); switches: $switchText; output folder: $OutDir; sanitized=$(-not $NoSanitize)"
  if ($script:SanSkipped) { Write-Note 'the computer name is an ordinary word of this output and was NOT replaced; remove it by hand before publishing' }
  Test-Environment
  if (-not $probeOnly) {
    if ($InstallerPath) { Test-Installer }
    if ($Install) { Invoke-Install }
    if ($InstallPolicy) { Invoke-InstallPolicy }
    Test-Inventory
    Test-UpdateMode
    Test-PolicyFile
    if ($Wrappers) { Test-Wrappers }
    elseif ($TamperTest) { Check 'W2.10.system64.detect-drift' 'SKIP' 'refused: -TamperTest only runs together with -Wrappers' }
  }
  if ($InstallProbes) { Install-Probes }
  if ($ReadProbes) { Read-Probes }
  if ($RemoveProbes) { Remove-Probes }
} catch { $fatal = $_ }
if ($null -ne $fatal) { Check 'W2.0.context' 'FAIL' "the script stopped early: $($fatal.Exception.Message)" }

Write-Raw "PHASE W2 RESULT pass=$($script:Pass) fail=$($script:Fail) skip=$($script:Skip) info=$($script:Info)"
if ($script:Fail -gt 0) { exit 1 }
exit 0
