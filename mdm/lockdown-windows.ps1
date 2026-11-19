<#
lockdown-windows.ps1 - Reference MDM job (Intune Win32 app + Remediations, SCCM, GPO startup script)
for Windows Kiro clients (Kiro IDE 1.x, Kiro CLI 2.25+ and 3.x). Run as SYSTEM or an elevated
Administrator. MAS TRM 9.1 (access), 11.1 (data), 11.3 (system security). Last verified against
kiro.dev docs: 2026-11-19. Intune runbook: kiro-docs/intune-deployment.md.

PRIMARY CONTROL (always):
  Deploys the admin policy file to the OFFICIAL Kiro path C:\ProgramData\Kiro\managed-settings.json,
  written as UTF-8 WITHOUT BOM from the bytes of UTF8Encoding($false)
  (Windows PowerShell Out-File / Set-Content write UTF-16 or add a BOM, which Kiro rejects). The
  JSON is validated first (ConvertFrom-Json plus the documented schema rules) and any rule with
  effect "allow" is refused, because Kiro would reject the whole file and deny every tool call.
  ACL: owner BUILTIN\Administrators, inheritance removed, every other explicit ACE removed (a
  standard user can pre-create folders under C:\ProgramData and plant ACEs), SYSTEM and
  Administrators Full Control, Users Read (+Execute on the directory), plus an explicit DENY for
  Users on Delete / Write / Append / Write-attributes on each file. Administrators are also members
  of BUILTIN\Users, so the deny also blocks an administrator's direct edits until it is removed;
  this script removes it before each update and puts it back afterwards. Nothing that existed
  before is trusted: a file is written as a new file in an administrators-only work folder
  (C:\ProgramData\Kiro\.staging) and renamed over the old one, never written in place; a folder is
  created under a random name, locked and renamed into place; and an existing folder that a
  non-administrator owns or can re-permission is moved aside to <name>.untrusted-<id> (a handle
  opened before the lockdown would otherwise stay usable after it). That is a speed bump, not
  a control against administrators: Kiro enforcement is client-side and a local administrator can
  change or remove the file, so developers must not be local admins.

OPTIONAL:
  -DeployHooks     verify agent-hooks\SHA256SUMS (abort on any mismatch) and copy the listed hook
                   scripts to C:\ProgramData\Kiro\hooks with the same ACL: the PowerShell guards
                   (agent-hooks\windows\*.ps1) and the bash scripts (*.sh, for Git Bash or WSL).
  -InstallUser     (implies -DeployHooks) write the v1 hook file banking-guards.windows.json, which
                   runs the PowerShell guards, to .kiro\hooks\ in every local user profile and in the
                   Default profile (new users). The script sets no owner or ACL on these copies:
                   they inherit the profile's permissions, so the user can edit or delete them.
                   Drift is reported and restored on the next run, not prevented. Kiro documents global hooks in
                   ~/.kiro/hooks for CLI V3; whether the IDE loads them is a pilot item.
  -DisableUpdates  set HKLM\SOFTWARE\Policies\Kiro UpdateMode (REG_SZ) = none (Kiro managed
                   updates) in the 64-bit registry view, for system-wide installs that IT updates.
  -StageSources    copy this script, the policy and (with -DeployHooks) every file listed in
                   SHA256SUMS to C:\ProgramData\Kiro\deploy\ (repo layout, same ACL) so that the
                   Intune wrappers in mdm\intune\ can run -Check and repair on the device.
  -RemoveSources   remove C:\ProgramData\Kiro\deploy\ (Win32 app uninstall). The policy, hooks, user
                   files and registry value are left in place; remove them deliberately.

Order of work: everything is validated first (policy JSON, SHA256SUMS, user hook file); only then is
anything written, so a refusal (exit 2) leaves the machine unchanged. Re-runnable (idempotent).
-DryRun validates and plans without changes (no admin needed); -Check reports content, ACL and
registry drift (exit 3). Intune Remediations and Win32 detection do NOT use these exit codes
directly: use the wrappers in mdm\intune\ (Remediations needs exit 1 for an issue; Win32 detection
needs exit 0 plus STDOUT). No network calls are made.

Exit codes: 0 ok | 1 usage/environment error | 2 validation refused | 3 drift (-Check)
#>
[CmdletBinding()]
param(
  [switch]$DryRun,
  [switch]$Check,
  [string]$SettingsPath,
  [switch]$OptionB,
  [switch]$DeployHooks,
  [string]$HooksSource,
  [string]$ManifestSha256,
  [switch]$InstallUser,
  [switch]$DisableUpdates,
  [switch]$StageSources,
  [switch]$RemoveSources,
  [switch]$NoAclLock,
  [switch]$Strict,
  [string]$Prefix        # TEST ONLY: relocate C:\ProgramData, C:\Users and the policy registry key
)

$ErrorActionPreference = 'Stop'
$Self = 'lockdown-windows'
$SelfPath = $MyInvocation.MyCommand.Path
$RepoDir = Split-Path -Parent (Split-Path -Parent $SelfPath)

# Environment equivalents (parameters win).
if (-not $SettingsPath) { $SettingsPath = $env:KIRO_MANAGED_SETTINGS_SRC }
if (-not $SettingsPath) {
  $name = 'managed-settings.banking.json'
  if ($OptionB) { $name = 'managed-settings.option-b.json' }
  $SettingsPath = Join-Path (Join-Path $RepoDir 'managed-settings') $name
}
if (-not $HooksSource) { $HooksSource = $env:KIRO_HOOKS_SRC }
if (-not $HooksSource) { $HooksSource = Join-Path $RepoDir 'agent-hooks' }
if (-not $ManifestSha256) { $ManifestSha256 = $env:KIRO_HOOKS_MANIFEST_SHA256 }
if ($env:KIRO_DEPLOY_HOOKS -eq '1') { $DeployHooks = $true }
if ($env:KIRO_DRY_RUN -eq '1') { $DryRun = $true }
if ($env:KIRO_STRICT -eq '1') { $Strict = $true }
if (-not $Prefix) { $Prefix = $env:KIRO_ROOT_PREFIX }
if ($Prefix -and -not [System.IO.Path]::IsPathRooted($Prefix)) { $Prefix = Join-Path (Get-Location).ProviderPath $Prefix }

$ProgramData = 'C:\ProgramData'
if ($Prefix) { $ProgramData = Join-Path $Prefix 'ProgramData' }
$KiroDir      = Join-Path $ProgramData 'Kiro'
$SettingsDest = Join-Path $KiroDir 'managed-settings.json'
$HooksDest    = Join-Path $KiroDir 'hooks'
$DeployDir    = Join-Path $KiroDir 'deploy'
$StagingDir   = Join-Path $KiroDir '.staging'   # administrators-only work folder (same volume)
$UserHookName = 'banking-guards.windows.json'
$UserHookSrc  = 'hooks/banking-guards.windows.json'   # its path inside SHA256SUMS
$ShippedHooksDir = 'C:/ProgramData/Kiro/hooks/'        # hook directory named in the shipped file
if ($InstallUser) { $DeployHooks = $true }             # user files are useless without the scripts

# HKLM\SOFTWARE\Policies is a shared key under WOW64; the 64-bit view is still opened explicitly.
# Test mode uses HKCU so that the default tests need no administrator rights.
$RegHive = [Microsoft.Win32.RegistryHive]::LocalMachine
$RegPath = 'SOFTWARE\Policies\Kiro'
$RegName = 'HKLM\SOFTWARE\Policies\Kiro'
if ($Prefix) { $RegHive = [Microsoft.Win32.RegistryHive]::CurrentUser; $RegPath = 'SOFTWARE\KiroLockdownTest\Policies\Kiro'; $RegName = "HKCU\$RegPath" }

# Well-known SIDs (locale-independent): SYSTEM, BUILTIN\Administrators, BUILTIN\Users.
$SidSystem = '*S-1-5-18'; $SidAdmins = '*S-1-5-32-544'; $SidUsers = '*S-1-5-32-545'
$DenyUsers = "$($SidUsers):(DE,DC,WD,AD,WA,WEA)"
$AllowedSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-32-545')

$script:Warnings = 0
$script:StagingReady = $false
$script:Drift = 0
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false

# Log through the console, not the pipeline, so function return values are not polluted.
function Write-Log([string]$m)  { [Console]::Out.WriteLine("[$Self] $m") }
function Write-Warn([string]$m) { [Console]::Out.WriteLine("[$Self] WARNING: $m"); $script:Warnings++ }
function Write-Drift([string]$m) { [Console]::Out.WriteLine("[$Self] DRIFT: $m"); $script:Drift++ }
function Stop-Kiro([int]$Code, [string]$m) { [Console]::Error.WriteLine("[$Self] ERROR: $m"); exit $Code }
function Get-Sha256([string]$p) { (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLowerInvariant() }
function Get-BytesSha256([byte[]]$Bytes) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { return ([System.BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
}
function Get-TextSha256([string]$Text) { return (Get-BytesSha256 ($Utf8NoBom.GetBytes($Text))) }

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Windows PowerShell 5.1 turns native stderr into terminating errors under 'Stop'; relax it here.
function Invoke-Icacls {
  param([string[]]$IcaclsArgs, [switch]$AllowFail)
  $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try { $out = & icacls.exe @IcaclsArgs 2>&1; $rc = $LASTEXITCODE } finally { $ErrorActionPreference = $old }
  if ($rc -ne 0 -and -not $AllowFail) { Stop-Kiro 1 "icacls $($IcaclsArgs -join ' ') failed: $out" }
}

# ------------------------------------------------------------------------------------------------
# Validation (same rules as lockdown-linux.sh / lockdown-macos.sh)
# ------------------------------------------------------------------------------------------------
$KnownCaps = @('fs_read','fs_write','shell','web_fetch','web_search','mcp','subagent','skill','power',
               'context','diagnostics','sandbox_network','all','builtin','filesystem','signin_method')
$SigninValues = @('*','idc','external_idp','builder_id','google','github','social')
$SettingKeys = @('idc_start_url','idc_region','external_idp_domain','external_idp_start_url',
                 'external_idp_region','signin_help_url','auth_portal_url')

function Test-StringArray($v) {
  if ($null -eq $v -or -not ($v -is [System.Array])) { return $false }
  foreach ($x in $v) { if (-not ($x -is [string])) { return $false } }
  return $true
}

# Returns the validated UTF-8 text (no BOM). Exits 2 on any error.
function Test-ManagedSettings([string]$Path, [string]$Name) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Stop-Kiro 2 "managed-settings source not found: $Name" }
  $bytes = [System.IO.File]::ReadAllBytes($Path)
  if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    Stop-Kiro 2 "$Name starts with a UTF-8 BOM; Kiro requires UTF-8 without BOM" }
  if ($bytes.Length -ge 2 -and (($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) -or ($bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF))) {
    Stop-Kiro 2 "$Name is UTF-16; Kiro requires UTF-8 without BOM (do not save it with Out-File)" }
  try { $text = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes) }
  catch { Stop-Kiro 2 "$Name is not valid UTF-8" }
  # PowerShell 7 tolerates // and /* */ comments; Kiro's JSON parser is not documented to.
  if ($text -match '(?m)^\s*(//|/\*)') { Stop-Kiro 2 "$Name contains comments; JSON does not allow comments" }
  try { $obj = $text | ConvertFrom-Json -ErrorAction Stop }
  catch { Stop-Kiro 2 "$Name is not valid JSON (Kiro would reject it and deny every tool call): $($_.Exception.Message)" }

  $errs = New-Object System.Collections.Generic.List[string]
  $warns = New-Object System.Collections.Generic.List[string]
  if (-not ($obj -is [System.Management.Automation.PSCustomObject])) {
    $errs.Add('top level must be a JSON object')
  } else {
    $top = @($obj.PSObject.Properties | ForEach-Object { $_.Name })
    foreach ($k in $top) { if ($k -cnotin @('rules','settings')) { $errs.Add("unknown top-level field `"$k`" (Kiro rejects the whole file)") } }
    if ($top -cnotcontains 'rules') {
      $errs.Add('"rules" is required (use [] when only settings are set)')
    } elseif (-not ($obj.rules -is [System.Array])) {
      $errs.Add('"rules" must be an array')
    } else {
      $i = 0
      foreach ($r in $obj.rules) {
        if (-not ($r -is [System.Management.Automation.PSCustomObject])) { $errs.Add("rules[$i] must be an object"); $i++; continue }
        $rk = @($r.PSObject.Properties | ForEach-Object { $_.Name })
        foreach ($k in $rk) { if ($k -cnotin @('capability','match','exclude','effect')) { $errs.Add("rules[$i]: unknown field `"$k`" (Kiro rejects the whole file)") } }
        if (-not ($r.capability -is [string])) { $errs.Add("rules[$i]: `"capability`" (string) is required") }
        elseif ($KnownCaps -cnotcontains $r.capability) { $warns.Add("rules[$i]: unknown capability `"$($r.capability)`" (Kiro skips it)") }
        if (-not ($r.effect -is [string])) { $errs.Add("rules[$i]: `"effect`" is required") }
        elseif ($r.effect -ceq 'allow') { $errs.Add("rules[$i]: effect `"allow`" is not permitted in managed-settings (Kiro rejects the whole file and denies all tool calls)") }
        elseif (@('deny','ask') -cnotcontains $r.effect) { $errs.Add("rules[$i]: effect must be deny or ask, got `"$($r.effect)`"") }
        foreach ($k in @('match','exclude')) {
          if (($rk -ccontains $k) -and -not (Test-StringArray $r.$k)) { $errs.Add("rules[$i]: `"$k`" must be an array of strings") }
        }
        if ($r.capability -ceq 'signin_method') {
          if ($r.effect -cne 'deny') { $warns.Add("rules[$i]: signin_method rules must use deny (Kiro ignores others)") }
          $vals = @(); if ($r.match) { $vals += @($r.match) }; if ($r.exclude) { $vals += @($r.exclude) }
          if ($vals.Count -gt 16) { $errs.Add("rules[$i]: signin_method allows at most 16 entries across match and exclude") }
          foreach ($v in $vals) { if ($SigninValues -cnotcontains $v) { $warns.Add("rules[$i]: unknown signin_method value `"$v`" (values are case-sensitive)") } }
        }
        $i++
      }
    }
    if ($top -ccontains 'settings') {
      if (-not ($obj.settings -is [System.Management.Automation.PSCustomObject])) { $errs.Add('"settings" must be an object') }
      else {
        $placeholder = $false
        foreach ($p in $obj.settings.PSObject.Properties) {
          if ($SettingKeys -cnotcontains $p.Name) { $warns.Add("settings.$($p.Name): not a settings key this script knows (Kiro ignores keys it does not know)"); continue }
          if (-not ($p.Value -is [string])) { $errs.Add("settings.$($p.Name) must be a string"); continue }
          if ($p.Name -eq 'signin_help_url' -and -not $p.Value.StartsWith('https://')) { $errs.Add('settings.signin_help_url must be an https:// URL') }
          elseif ($p.Name -eq 'signin_help_url' -and $Utf8NoBom.GetByteCount($p.Value) -gt 2048) { $errs.Add('settings.signin_help_url exceeds 2048 bytes') }
          elseif ($p.Name -eq 'auth_portal_url' -and $p.Value -cnotmatch '^https://[^/?#@]+(/[^?#]*)?$') { $errs.Add('settings.auth_portal_url must be an https:// URL without credentials, query or fragment (Kiro CLI 3.5.0+ sends users to the default portal on an invalid value)') }
          elseif ($p.Name -eq 'auth_portal_url' -and ($Utf8NoBom.GetByteCount($p.Value) -gt 2048 -or $p.Value -match '[\x00-\x1f\x7f]')) { $errs.Add('settings.auth_portal_url exceeds 2048 bytes or contains control characters') }
          elseif ($p.Name -like '*_url' -and -not $p.Value.StartsWith('https://')) { $warns.Add("settings.$($p.Name) is not an https:// URL") }
          if ($p.Value -match 'REPLACE|CHANGE-?ME|xxxx|example\.|my-org|[<>]') { $placeholder = $true }
        }
        if ($placeholder) { $warns.Add('settings contain placeholder values; set your organisation values before production') }
      }
    }
  }
  foreach ($w in $warns) { Write-Warn $w; if ($Strict) { $errs.Add("(strict) $w") } }
  if ($errs.Count -gt 0) {
    foreach ($e in $errs) { [Console]::Error.WriteLine("[$Self] ERROR: $e") }
    Stop-Kiro 2 "refusing to deploy ${Name}: $($errs.Count) problem(s) found"
  }
  Write-Log "validated ${Name}: $(@($obj.rules).Count) rule(s), no allow effects"
  return $text
}

# Copies SHA256SUMS and the files it lists into a private stage directory and verifies the copies.
# Returns the deployable scripts (top-level *.sh and windows/*.ps1, as manifest names); every listed
# name is also kept in $script:ManifestNames for -StageSources.
$script:ManifestNames = New-Object System.Collections.Generic.List[string]
function Get-VerifiedHooks([string]$Stage) {
  $man = Join-Path $HooksSource 'SHA256SUMS'
  if (-not (Test-Path -LiteralPath $man -PathType Leaf)) { Stop-Kiro 2 "hook manifest not found: $man (hooks are never deployed without it)" }
  $hs = Join-Path $Stage 'hooks'
  New-Item -ItemType Directory -Force -Path $hs | Out-Null
  $stagedMan = Join-Path $hs 'SHA256SUMS'
  Copy-Item -LiteralPath $man -Destination $stagedMan -Force
  if ($ManifestSha256) {
    $h = Get-Sha256 $stagedMan
    if ($h -ne $ManifestSha256.ToLowerInvariant()) { Stop-Kiro 2 "SHA256SUMS hash $h does not match the pinned value $ManifestSha256" }
    Write-Log 'SHA256SUMS matches the pinned hash'
  } else {
    Write-Warn 'no -ManifestSha256 pin: SHA256SUMS is trusted as delivered (protect the source package)'
  }
  $scripts = New-Object System.Collections.Generic.List[string]
  foreach ($line in [System.IO.File]::ReadAllLines($stagedMan)) {
    if ($line -eq '') { continue }
    $m = [regex]::Match($line, '^([0-9a-f]{64}) [ *]([A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)?)$')
    if (-not $m.Success) { Stop-Kiro 2 "malformed SHA256SUMS line: $line" }
    $want = $m.Groups[1].Value; $name = $m.Groups[2].Value
    if ($name.Contains('..') -or $name.StartsWith('.')) { Stop-Kiro 2 "unsafe file name in SHA256SUMS: $name" }
    $src = Join-Path $HooksSource ($name -replace '/', '\')
    if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { Stop-Kiro 2 "file listed in SHA256SUMS is missing: $name" }
    $dst = Join-Path $hs ($name -replace '/', '\')
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
    Copy-Item -LiteralPath $src -Destination $dst -Force
    $have = Get-Sha256 $dst
    if ($have -ne $want) { Stop-Kiro 2 "hook hash verification FAILED for $name (sha256 $have, expected $want) - aborting, nothing deployed" }
    Write-Log "${name}: OK"
    $script:ManifestNames.Add($name)
    if (-not $name.Contains('/') -and $name.EndsWith('.sh')) { $scripts.Add($name) }
    elseif ($name -cmatch '^windows/[A-Za-z0-9._-]+\.ps1$') { $scripts.Add($name) }
  }
  if ($scripts.Count -eq 0) { Stop-Kiro 2 'SHA256SUMS lists no hook scripts (*.sh or windows/*.ps1)' }
  Write-Log "hook hashes verified: $($scripts.Count) script(s)"
  return ,$scripts
}

# ------------------------------------------------------------------------------------------------
# Deployment primitives
# ------------------------------------------------------------------------------------------------
function Get-AceSid($Ace) {
  try { return $Ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
  catch { return [string]$Ace.IdentityReference.Value }
}

# Removes explicit ACEs for every SID other than SYSTEM, Administrators and Users, and every explicit
# Deny ACE. A user who pre-created the folder (allowed under C:\ProgramData) could have planted
# either: an extra grant keeps write access, a deny on Read would stop Kiro reading the policy.
function Clear-ForeignAces([string]$Path) {
  $acl = $null
  try { $acl = Get-Acl -LiteralPath $Path } catch { Stop-Kiro 1 "cannot read the ACL of ${Path}: $($_.Exception.Message)" }
  foreach ($ace in @($acl.Access)) {
    if ($ace.IsInherited) { continue }
    $sid = Get-AceSid $ace
    if ($AllowedSids -notcontains $sid) { Invoke-Icacls @($Path, '/remove', "*$sid") -AllowFail }
  }
  foreach ($sid in $AllowedSids) { Invoke-Icacls @($Path, '/remove:d', "*$sid") -AllowFail }
}

# $Private: no access for Users at all (the work folder); otherwise Users get Read and Execute.
function Set-KiroDirAcl([string]$Dir, [bool]$Private = $false) {
  if ($NoAclLock) { Write-Warn "-NoAclLock: ACL not applied to $Dir"; return }
  # Take ownership and rebuild the ACL on every run.
  Invoke-Icacls @($Dir, '/setowner', $SidAdmins)
  Invoke-Icacls @($Dir, '/inheritance:r')
  Clear-ForeignAces $Dir
  if ($Private) {
    Invoke-Icacls @($Dir, '/remove', $SidUsers) -AllowFail
    Invoke-Icacls @($Dir, '/grant:r', "$($SidSystem):(OI)(CI)F", "$($SidAdmins):(OI)(CI)F")
  } else {
    Invoke-Icacls @($Dir, '/grant:r', "$($SidSystem):(OI)(CI)F", "$($SidAdmins):(OI)(CI)F", "$($SidUsers):(OI)(CI)RX")
  }
  # Clear-ForeignAces ignores icacls failures, so confirm the result instead of assuming it.
  $left = Get-AclProblems $Dir $false
  if ($left.Count -gt 0) { Stop-Kiro 1 "cannot secure ${Dir}: $($left -join '; ')" }
}

# Returns the ACL problems of a deployed directory or file (empty list = compliant): owner must be
# Administrators; nobody except SYSTEM and Administrators may hold write-type rights; files need
# the Users deny ACE.
function Get-AclProblems([string]$Path, [bool]$IsFile) {
  $p = New-Object System.Collections.Generic.List[string]
  $acl = $null
  try { $acl = Get-Acl -LiteralPath $Path } catch { $p.Add("cannot read the ACL of $Path"); return ,$p }
  $owner = $acl.Owner
  try { $owner = (New-Object System.Security.Principal.NTAccount($acl.Owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { }
  if ($owner -ne 'S-1-5-32-544') { $p.Add("$Path owner is $($acl.Owner), expected BUILTIN\Administrators") }
  $write = [int64][System.Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
  $genericWriteOrAll = [int64]0x50000000
  $hasDeny = $false
  foreach ($ace in @($acl.Access)) {
    $sid = Get-AceSid $ace
    if ($ace.AccessControlType -eq 'Deny') { if ($sid -eq 'S-1-5-32-545') { $hasDeny = $true }; continue }
    if (@('S-1-5-18', 'S-1-5-32-544') -contains $sid) { continue }
    $raw = [int64]$ace.FileSystemRights
    if ((($raw -band $write) -ne 0) -or (($raw -band $genericWriteOrAll) -ne 0)) {
      $p.Add("$Path grants write-type rights to $($ace.IdentityReference)")
    }
  }
  if ($IsFile -and -not $hasDeny) { $p.Add("$Path has no deny ACE for BUILTIN\Users") }
  return ,$p
}

function Lock-KiroFile([string]$Path, [string]$Read) {
  if ($NoAclLock) { return }
  Invoke-Icacls @($Path, '/setowner', $SidAdmins)
  Invoke-Icacls @($Path, '/inheritance:r')
  Clear-ForeignAces $Path
  Invoke-Icacls @($Path, '/grant:r', "$($SidSystem):F", "$($SidAdmins):F", "$($SidUsers):$Read")
  Invoke-Icacls @($Path, '/deny', $DenyUsers)
}

function Unlock-KiroFile([string]$Path) {
  if ($NoAclLock -or -not (Test-Path -LiteralPath $Path)) { return }
  Invoke-Icacls @($Path, '/remove:d', $SidUsers) -AllowFail
}

# True for junctions and symbolic links, including dangling ones (Test-Path reports those as
# missing). A standard user can create a junction under C:\ProgramData before the first run, or in
# their own profile, and point it at a folder they control.
function Test-ReparsePoint([string]$Path) {
  try { $a = [System.IO.File]::GetAttributes($Path) } catch { return $false }
  return [bool]($a -band [System.IO.FileAttributes]::ReparsePoint)
}

function Initialize-KiroDir([string]$Dir, [bool]$Private = $false) {
  if (Test-ReparsePoint $Dir) {
    if ($Check) { Write-Drift "$Dir is a junction or symbolic link"; return }
    Stop-Kiro 1 "refusing to use ${Dir}: it is a junction or symbolic link (it may have been planted by a user); remove it as an administrator and re-run"
  }
  if ($Check) {
    if (-not (Test-Path -LiteralPath $Dir -PathType Container)) { Write-Drift "missing directory $Dir"; return }
    if (-not $NoAclLock) { foreach ($m in (Get-AclProblems $Dir $false)) { Write-Drift $m } }
    return
  }
  if ($DryRun) { Write-Log "[dry-run] would ensure directory $Dir (owner Administrators; SYSTEM/Admins Full, Users Read+Execute)"; return }
  if (Test-Path -LiteralPath $Dir -PathType Leaf) { Stop-Kiro 1 "refusing to use ${Dir}: a file exists at that path; remove it as an administrator and re-run" }
  if ($NoAclLock) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null; Set-KiroDirAcl $Dir $Private; return }
  if ((Test-Path -LiteralPath $Dir -PathType Container) -and (Test-TrustedObject $Dir)) { Set-KiroDirAcl $Dir $Private; return }
  New-TrustedDir $Dir $Private
}

# Creates $Dir as a NEW object: built under a random name, locked, checked to be empty and only
# then renamed into place. The rename fails if the name exists, so a folder that a user creates in
# the meantime is never adopted (New-Item -Force would adopt it): it is moved aside and the rename
# is tried again.
function New-TrustedDir([string]$Dir, [bool]$Private) {
  $parent = Split-Path -Parent $Dir
  if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
  $new = "$Dir.new-" + [guid]::NewGuid().ToString('N').Substring(0, 12)
  try { New-Item -ItemType Directory -Path $new -ErrorAction Stop | Out-Null }
  catch { Stop-Kiro 1 "cannot create ${new}: $($_.Exception.Message)" }
  Set-KiroDirAcl $new $Private
  if (@([System.IO.Directory]::GetFileSystemEntries($new)).Count -ne 0) {
    Stop-Kiro 1 "refusing to use ${Dir}: something was placed in the new folder $new before it was locked; remove it as an administrator and re-run"
  }
  $last = ''
  for ($attempt = 0; $attempt -lt 3; $attempt++) {
    if (Test-ReparsePoint $Dir) { $last = 'a junction or symbolic link appeared at that path'; break }
    if (Test-Path -LiteralPath $Dir -PathType Leaf) { $last = 'a file appeared at that path'; break }
    if (Test-Path -LiteralPath $Dir -PathType Container) { Move-Untrusted $Dir }
    try { [System.IO.Directory]::Move($new, $Dir); return } catch { $last = $_.Exception.Message }
  }
  try { [System.IO.Directory]::Delete($new, $false) } catch { }
  Stop-Kiro 1 "cannot create ${Dir}: $last; remove whatever is at that path as an administrator and re-run"
}

# True when nobody except SYSTEM, Administrators and TrustedInstaller owns the object or may change
# its permissions or owner. An owner can re-open a handle with WRITE_DAC at any time, and a handle
# opened before the lockdown stays valid after it, so the ACL of such an object cannot be trusted
# even after this script rewrites it.
function Test-TrustedObject([string]$Path) {
  $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
  try { $acl = Get-Acl -LiteralPath $Path } catch { return $false }
  $owner = $acl.Owner
  try { $owner = (New-Object System.Security.Principal.NTAccount($acl.Owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { }
  if ($trusted -notcontains $owner) { return $false }
  $control = [int64][System.Security.AccessControl.FileSystemRights]'ChangePermissions, TakeOwnership'
  foreach ($ace in @($acl.Access)) {
    if ($ace.AccessControlType -eq 'Deny') { continue }
    if ($trusted -contains (Get-AceSid $ace)) { continue }
    # Inherit-only entries (CREATOR OWNER under C:\ProgramData) do not apply to the object itself.
    if ($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
    $raw = [int64]$ace.FileSystemRights
    if ((($raw -band $control) -ne 0) -or (($raw -band [int64]0x10000000) -ne 0)) { return $false }
  }
  return $true
}

# Renames an untrusted folder out of the way, so that a fresh one can be created. Handles a user
# may hold stay with the renamed folder. Nothing in it is deleted.
function Move-Untrusted([string]$Path) {
  $aside = "$Path.untrusted-" + [guid]::NewGuid().ToString('N').Substring(0, 8)
  try { [System.IO.Directory]::Move($Path, $aside) }
  catch { Stop-Kiro 1 "refusing to use ${Path}: it is owned or controlled by a non-administrator and cannot be moved aside ($($_.Exception.Message)); remove it as an administrator and re-run" }
  Write-Warn "$Path was owned or controlled by a non-administrator (it may have been planted); moved aside to $aside and recreated. Review and delete the old folder as an administrator"
}

# Removes a link itself, never its target (Remove-Item on a junction is unreliable in Windows PowerShell 5.1).
function Remove-Link([string]$Path) {
  if ([System.IO.File]::GetAttributes($Path) -band [System.IO.FileAttributes]::Directory) { [System.IO.Directory]::Delete($Path, $false) }
  else { [System.IO.File]::Delete($Path) }
}

# Replaces $Dest with a NEW file object. The bytes are written to a new file in the work folder,
# which standard users cannot open; the old file is moved into the work folder, the new one is
# renamed into place and locked, and the old one is deleted. If the rename fails, the old file is
# put back, so the device is not left without the file. An existing file is never written in place,
# so a handle or mapped view opened on it earlier is left behind.
function Install-KiroFile([byte[]]$Bytes, [string]$Dest, [string]$Read) {
  $work = Split-Path -Parent $Dest
  if (-not $NoAclLock) {
    if (-not $script:StagingReady) { Initialize-KiroDir $StagingDir $true; $script:StagingReady = $true }
    $work = $StagingDir
  }
  $id = [guid]::NewGuid().ToString('N')
  $tmp = Join-Path $work ".kiro-$id.tmp"
  $old = Join-Path $work ".kiro-$id.old"
  $moved = $false
  try {
    $fs = [System.IO.File]::Open($tmp, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $fs.Write($Bytes, 0, $Bytes.Length) } finally { $fs.Dispose() }
    if (Test-Path -LiteralPath $Dest -PathType Leaf) {
      Unlock-KiroFile $Dest
      [System.IO.File]::SetAttributes($Dest, [System.IO.FileAttributes]::Normal)
      [System.IO.File]::Move($Dest, $old)
      $moved = $true
    }
    [System.IO.File]::Move($tmp, $Dest)
  } catch {
    $msg = $_.Exception.Message
    if ($moved -and -not (Test-Path -LiteralPath $Dest)) {
      try { [System.IO.File]::Move($old, $Dest); $msg += ' (the previous file was put back)' }
      catch { $msg += " (the previous file could NOT be put back and is at $old)" }
    }
    try { if (Test-Path -LiteralPath $tmp) { [System.IO.File]::Delete($tmp) } } catch { }
    if ($moved -and (Test-Path -LiteralPath $Dest -PathType Leaf)) { Lock-KiroFile $Dest $Read }
    Stop-Kiro 1 "cannot install ${Dest}: $msg"
  }
  Lock-KiroFile $Dest $Read
  if ($moved) {
    try { [System.IO.File]::Delete($old) }
    catch { Write-Warn "the replaced file could not be deleted (it may still be open in another process): $old" }
  }
}

# Shared by the policy, the hook scripts and the staged sources. $Label is used in the dry-run line.
function Deploy-KiroFile([byte[]]$Bytes, [string]$Want, [string]$Dest, [string]$Read, [string]$Label) {
  $have = ''
  if (Test-ReparsePoint $Dest) {
    if ($Check) { Write-Drift "$Dest is a symbolic link or junction"; return }
    if ($DryRun) { Write-Warn "$Dest is a symbolic link or junction; a real run removes the link" }
    else { Write-Warn "$Dest is a symbolic link or junction; removing the link"; Remove-Link $Dest }
  }
  elseif (Test-Path -LiteralPath $Dest -PathType Container) {
    if ($Check) { Write-Drift "$Dest is a directory, expected a file"; return }
    if ($DryRun) { Write-Warn "$Dest is a directory, expected a file; a real run stops here"; return }
    Stop-Kiro 1 "refusing to write ${Dest}: a directory exists at that path (it may have been planted); remove it as an administrator and re-run"
  }
  elseif (Test-Path -LiteralPath $Dest -PathType Leaf) { $have = Get-Sha256 $Dest }
  if ($Check) {
    if (-not $have) { Write-Drift "missing $Dest"; return }
    if ($have -ne $want) { Write-Drift "$Dest content differs (sha256 $have, expected $want)" }
    if (-not $NoAclLock) { foreach ($m in (Get-AclProblems $Dest $true)) { Write-Drift $m } }
    return
  }
  $compliant = $NoAclLock -or (($have -ne '') -and ((Get-AclProblems $Dest $true).Count -eq 0) -and (Test-TrustedObject $Dest))
  if ($have -eq $want -and $compliant) { Write-Log "unchanged: $Dest (sha256=$want)"; return }
  if ($DryRun) { Write-Log "[dry-run] would write $Label to $Dest (sha256=$want), then lock the ACL"; return }
  if ($have -eq $want) { Write-Log "replacing ${Dest}: same content, but its owner or ACL was not set by this script" }
  Install-KiroFile $Bytes $Dest $Read
  if ((Get-Sha256 $Dest) -ne $want) { Stop-Kiro 1 "$Dest does not have the expected content after the write" }
  Write-Log "installed: $Dest (sha256=$want)"
}

# Deploy-SettingsFile: writes the validated text as UTF-8 without BOM.
function Deploy-SettingsFile([string]$Text, [string]$Dest) {
  $bytes = $Utf8NoBom.GetBytes($Text)
  if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { Stop-Kiro 1 "refusing to write ${Dest}: the text starts with a BOM" }
  Deploy-KiroFile $bytes (Get-TextSha256 $Text) $Dest 'R' 'the policy as UTF-8 without BOM'
}

function Deploy-HookFile([string]$Src, [string]$Dest) {
  Deploy-KiroFile ([System.IO.File]::ReadAllBytes($Src)) (Get-Sha256 $Src) $Dest 'RX' (Split-Path -Leaf $Src)
}

# Validates the staged Windows v1 hook file and returns its text with the hook directory rewritten
# to $HooksDest. Every command must run a deployed PowerShell guard. Exits 2 on any error.
function Get-UserHookText([string]$Stage, [string[]]$Scripts) {
  if ($script:ManifestNames -cnotcontains $UserHookSrc) { Stop-Kiro 2 "-InstallUser needs $UserHookSrc to be listed in SHA256SUMS" }
  $path = Join-Path (Join-Path $Stage 'hooks') ($UserHookSrc -replace '/', '\')
  try { $text = (New-Object System.Text.UTF8Encoding($false, $true)).GetString([System.IO.File]::ReadAllBytes($path)) }
  catch { Stop-Kiro 2 "$UserHookSrc is not valid UTF-8" }
  try { $obj = $text | ConvertFrom-Json -ErrorAction Stop }
  catch { Stop-Kiro 2 "$UserHookSrc is not valid JSON: $($_.Exception.Message)" }
  if ($obj.version -cne 'v1' -or -not ($obj.hooks -is [System.Array]) -or @($obj.hooks).Count -eq 0) {
    Stop-Kiro 2 "$UserHookSrc must be a v1 hook file with a non-empty hooks array" }
  $ps1 = @($Scripts | Where-Object { $_ -clike 'windows/*.ps1' } | ForEach-Object { $_.Substring(8) })
  $cmdRe = '^powershell\.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + [regex]::Escape($ShippedHooksDir) + '([A-Za-z0-9._-]+\.ps1)$'
  foreach ($h in $obj.hooks) {
    if ($h.action.type -cne 'command') { continue }
    $m = [regex]::Match([string]$h.action.command, $cmdRe)
    if (-not $m.Success) { Stop-Kiro 2 "${UserHookSrc}: a hook command must be 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ShippedHooksDir<guard>.ps1', got: $($h.action.command)" }
    if ($ps1 -cnotcontains $m.Groups[1].Value) { Stop-Kiro 2 "${UserHookSrc}: hook command references $($m.Groups[1].Value), which is not a windows/*.ps1 script in SHA256SUMS" }
  }
  Write-Log "validated ${UserHookSrc}: $(@($obj.hooks).Count) hook(s), commands run deployed guards only"
  return $text.Replace($ShippedHooksDir, (($HooksDest -replace '\\', '/') + '/'))
}

# Local user profiles (not system profiles) plus the Default profile, which seeds new users.
function Get-TargetProfiles {
  $list = New-Object System.Collections.Generic.List[string]
  if ($Prefix) {
    $root = Join-Path $Prefix 'Users'
    if (Test-Path -LiteralPath $root -PathType Container) {
      foreach ($d in @(Get-ChildItem -LiteralPath $root -Directory -Force)) { $list.Add($d.FullName) }
    }
    return ,$list
  }
  try { $all = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop) }
  catch { Stop-Kiro 1 "cannot list user profiles: $($_.Exception.Message)" }
  foreach ($p in $all) {
    if ($p.Special -or -not $p.LocalPath) { continue }
    if (Test-Path -LiteralPath $p.LocalPath -PathType Container) { $list.Add([string]$p.LocalPath) }
  }
  $default = $null
  try { $default = [Environment]::ExpandEnvironmentVariables((Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name Default -ErrorAction Stop).Default) } catch { }
  if (-not $default) { $default = Join-Path $env:SystemDrive 'Users\Default' }
  if ((Test-Path -LiteralPath $default -PathType Container) -and ($list -notcontains $default)) { $list.Add($default) }
  return ,$list
}

# Writes the hook file into a user-controlled profile, so links are never followed: a junction or
# symbolic link at .kiro, .kiro\hooks or the file skips that profile (drift in -Check), and an
# existing file is deleted before the new one is created (a hard link is replaced, not written
# through). No owner or ACL is set: the file inherits the profile's permissions.
function Deploy-UserHookFile([string]$ProfileDir, [string]$Text) {
  $kiro = Join-Path $ProfileDir '.kiro'
  $dir  = Join-Path $kiro 'hooks'
  $dest = Join-Path $dir $UserHookName
  foreach ($p in @($kiro, $dir, $dest)) {
    if (Test-ReparsePoint $p) {
      if ($Check) { Write-Drift "$p is a junction or symbolic link" } else { Write-Warn "skipping ${ProfileDir}: $p is a junction or symbolic link (not followed)" }
      return
    }
  }
  $odd = $null
  if (Test-Path -LiteralPath $kiro -PathType Leaf) { $odd = "$kiro is a file, expected a directory" }
  elseif (Test-Path -LiteralPath $dir -PathType Leaf) { $odd = "$dir is a file, expected a directory" }
  elseif (Test-Path -LiteralPath $dest -PathType Container) { $odd = "$dest is a directory, expected a file" }
  if ($odd) { if ($Check) { Write-Drift $odd } else { Write-Warn "skipping ${ProfileDir}: $odd" }; return }
  $want = Get-TextSha256 $Text
  $have = ''
  if (Test-Path -LiteralPath $dest -PathType Leaf) { $have = Get-Sha256 $dest }
  if ($Check) {
    if (-not $have) { Write-Drift "missing $dest" } elseif ($have -ne $want) { Write-Drift "$dest content differs (user-owned file; restored on the next run)" }
    return
  }
  if ($have -eq $want) { Write-Log "unchanged: $dest"; return }
  if ($DryRun) { Write-Log "[dry-run] would write $dest (user-owned copy of $UserHookName)"; return }
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  if ((Test-ReparsePoint $kiro) -or (Test-ReparsePoint $dir)) { Write-Warn "skipping ${ProfileDir}: a link appeared under .kiro while writing"; return }
  if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force }
  [System.IO.File]::WriteAllText($dest, $Text, $Utf8NoBom)
  Write-Log "installed: $dest"
}

function Open-PolicyKey([bool]$Write) {
  $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($RegHive, [Microsoft.Win32.RegistryView]::Registry64)
  try {
    if ($Write) { return $base.CreateSubKey($RegPath) }
    return $base.OpenSubKey($RegPath)
  } finally { $base.Dispose() }
}

# Kiro managed updates: UpdateMode (REG_SZ) = none disables update checks for every user.
function Deploy-UpdateMode {
  $have = $null; $kind = $null
  $k = Open-PolicyKey $false
  if ($k) {
    try {
      $have = $k.GetValue('UpdateMode', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
      if ($null -ne $have) { $kind = $k.GetValueKind('UpdateMode') }
    } finally { $k.Dispose() }
  }
  $ok = ($kind -eq [Microsoft.Win32.RegistryValueKind]::String) -and ($have -ceq 'none')
  if ($Check) { if (-not $ok) { Write-Drift "$RegName UpdateMode is not REG_SZ 'none' (found: $have)" }; return }
  if ($ok) { Write-Log "unchanged: $RegName UpdateMode = none"; return }
  if ($DryRun) { Write-Log "[dry-run] would set $RegName UpdateMode (REG_SZ) = none"; return }
  $k = Open-PolicyKey $true
  try { $k.SetValue('UpdateMode', 'none', [Microsoft.Win32.RegistryValueKind]::String) } finally { $k.Dispose() }
  Write-Log "set: $RegName UpdateMode (REG_SZ) = none (restart Kiro to apply)"
}

# Copies the validated sources to $DeployDir in the repository layout, so the staged copy of this
# script resolves them exactly as it does in the repository.
function Deploy-StagedSources([string]$Stage, [string]$PolicyText) {
  Initialize-KiroDir $DeployDir
  $dirs = New-Object System.Collections.Generic.List[string]
  $dirs.Add('mdm'); $dirs.Add('managed-settings')
  if ($DeployHooks) {
    $dirs.Add('agent-hooks')
    foreach ($n in $script:ManifestNames) {
      if ($n.Contains('/')) { $d = 'agent-hooks\' + $n.Substring(0, $n.IndexOf('/')); if ($dirs -notcontains $d) { $dirs.Add($d) } }
    }
  }
  foreach ($d in $dirs) { Initialize-KiroDir (Join-Path $DeployDir $d) }
  # The bytes were read during validation: if C:\ProgramData\Kiro had to be moved aside while this
  # script runs from the staged copy, the file at $SelfPath is no longer there.
  Deploy-KiroFile $script:SelfBytes (Get-BytesSha256 $script:SelfBytes) (Join-Path $DeployDir 'mdm\lockdown-windows.ps1') 'RX' 'lockdown-windows.ps1'
  Deploy-SettingsFile $PolicyText (Join-Path $DeployDir ('managed-settings\' + (Split-Path -Leaf $SettingsPath)))
  if ($DeployHooks) {
    $hs = Join-Path $Stage 'hooks'
    Deploy-HookFile (Join-Path $hs 'SHA256SUMS') (Join-Path $DeployDir 'agent-hooks\SHA256SUMS')
    foreach ($n in $script:ManifestNames) {
      $rel = $n -replace '/', '\'
      Deploy-HookFile (Join-Path $hs $rel) (Join-Path $DeployDir "agent-hooks\$rel")
    }
  }
}

# Deletes a tree without following links: a junction or symbolic link is removed as a link.
function Remove-KiroTree([string]$Path) {
  $a = [System.IO.File]::GetAttributes($Path)
  if ($a -band [System.IO.FileAttributes]::ReparsePoint) { Remove-Link $Path; return }
  if ($a -band [System.IO.FileAttributes]::Directory) {
    foreach ($e in [System.IO.Directory]::GetFileSystemEntries($Path)) { Remove-KiroTree $e }
    [System.IO.Directory]::Delete($Path, $false)
    return
  }
  Unlock-KiroFile $Path
  [System.IO.File]::SetAttributes($Path, [System.IO.FileAttributes]::Normal)
  [System.IO.File]::Delete($Path)
}

function Remove-StagedSources {
  foreach ($d in @($KiroDir, $DeployDir)) {
    if (Test-ReparsePoint $d) { Stop-Kiro 1 "refusing to remove ${DeployDir}: $d is a junction or symbolic link; remove it as an administrator" }
  }
  if (-not (Test-Path -LiteralPath $DeployDir -PathType Container)) { Write-Log "nothing to remove: $DeployDir does not exist"; return }
  if ($DryRun) { Write-Log "[dry-run] would remove $DeployDir"; return }
  try { Remove-KiroTree $DeployDir } catch { Stop-Kiro 1 "cannot remove ${DeployDir}: $($_.Exception.Message)" }
  Write-Log "removed: $DeployDir (the policy, hooks, user hook files and UpdateMode are unchanged)"
}

# ------------------------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------------------------
if ($RemoveSources -and ($Check -or $StageSources)) { Stop-Kiro 1 '-RemoveSources cannot be combined with -Check or -StageSources' }
if ($DryRun) { Write-Log 'DRY RUN - validation and planning only; no system changes' }
elseif ($Check) { Write-Log 'CHECK - comparing deployed files with sources; no changes' }
elseif (-not (Test-IsAdmin) -and -not ($Prefix -and $NoAclLock)) {
  Stop-Kiro 1 'must run as SYSTEM or an elevated Administrator (use -DryRun for a non-admin validation)'
}
if ($Prefix) { Write-Warn "TEST MODE: C:\ProgramData is relocated to $ProgramData, profiles to $(Join-Path $Prefix 'Users'), the policy key to $RegName" }

if ($RemoveSources) {
  Remove-StagedSources
  exit 0
}

$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("kiro-mdm-" + [guid]::NewGuid().ToString('N').Substring(0, 12))
New-Item -ItemType Directory -Force -Path $stage | Out-Null
try {
  # Phase 1 - validate everything. Nothing is written until all checks pass.
  $stagedSettings = Join-Path $stage 'managed-settings.json'
  if (-not (Test-Path -LiteralPath $SettingsPath -PathType Leaf)) { Stop-Kiro 2 "managed-settings source not found: $SettingsPath" }
  Copy-Item -LiteralPath $SettingsPath -Destination $stagedSettings -Force
  $text = Test-ManagedSettings $stagedSettings $SettingsPath
  $scripts = @()
  if ($DeployHooks) { $scripts = Get-VerifiedHooks $stage }
  $userText = $null
  if ($InstallUser) { $userText = Get-UserHookText $stage $scripts }
  $script:SelfBytes = $null
  if ($StageSources) { $script:SelfBytes = [System.IO.File]::ReadAllBytes($SelfPath) }
  Write-Log 'all validation passed'

  # Phase 2 - apply.
  # 1. Admin policy (primary control).
  Initialize-KiroDir $KiroDir
  Deploy-SettingsFile $text $SettingsDest
  if (-not $DryRun -and -not $Check) { Write-Log 'restart Kiro (IDE and CLI) to apply the new policy' }

  # 2. Hook scripts (optional): windows/*.ps1 are deployed without the folder prefix.
  if ($DeployHooks) {
    Initialize-KiroDir $HooksDest
    foreach ($s in $scripts) {
      Deploy-HookFile (Join-Path (Join-Path $stage 'hooks') ($s -replace '/', '\')) (Join-Path $HooksDest $s.Substring($s.LastIndexOf('/') + 1))
    }
    if (-not $InstallUser) { Write-Log 'note: hook scripts deployed but not wired into Kiro; add -InstallUser (per-user hook files) after a pilot. managed-settings remains the primary control.' }
  }

  # 3. Managed updates.
  if ($DisableUpdates) { Deploy-UpdateMode }

  # 4. Sources for the on-device Intune wrappers.
  if ($StageSources) { Deploy-StagedSources $stage $text }

  # 5. Per-user hook files (editable by the user; defense in depth only). Last, and one profile at
  #    a time, so that a problem in one profile cannot stop the machine-level steps or other profiles.
  if ($InstallUser) {
    $profiles = Get-TargetProfiles
    if ($profiles.Count -eq 0) { Write-Warn 'no user profiles found for -InstallUser' }
    foreach ($p in $profiles) {
      try { Deploy-UserHookFile $p $userText }
      catch {
        if ($Check) { Write-Drift "cannot check the user hook file in ${p}: $($_.Exception.Message)" }
        else { Write-Warn "skipping ${p}: cannot write the user hook file: $($_.Exception.Message)" }
      }
    }
  }
}
finally {
  Remove-Item -Recurse -Force -LiteralPath $stage -ErrorAction SilentlyContinue
}

if ($Check) {
  if ($script:Drift -eq 0) { Write-Log 'compliant: no drift'; exit 0 }
  Write-Log "drift detected: $($script:Drift) item(s); re-run without -Check to restore"
  exit 3
}
Write-Log "done ($($script:Warnings) warning(s)). Managed settings: $SettingsDest"
exit 0
