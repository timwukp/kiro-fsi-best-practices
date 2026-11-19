<#
test-lockdown-windows.ps1 - tests for mdm\lockdown-windows.ps1.

DEFAULT MODE (no admin, no system changes, safe in CI):
  - DRY-RUN validation of the shipped managed-settings files and refusal of bad input
    (effect "allow", malformed JSON, unknown fields, comments, UTF-8 BOM, UTF-16).
  - Hook manifest: a fixture with a tampered script is refused before anything is planned.
  - A junction planted where C:\ProgramData\Kiro would be is refused.
  - UTF-8 WITHOUT BOM writer: a real run into a temporary -Prefix with -NoAclLock (test-only;
    writes only under %TEMP%) and a byte-level check of the written file.
  - Intune: -StageSources, and the exit-code mapping of the wrappers in mdm\intune\ (Remediations:
    only exit 1 means an issue; Win32 detection: exit 0 + STDOUT and no STDERR only when
    compliant), driven by the real staged script and by stubs that exit 0, 1, 2, 3 and 5.
  - -DisableUpdates (test key under HKCU\SOFTWARE\KiroLockdownTest in test mode), -InstallUser
    (fake profiles under the temporary prefix, junction refusal, hook file validation) and
    -RemoveSources.

ADMIN MODE (opt-in, never run by default):
  $env:KIRO_MDM_ADMIN_TESTS = '1'; powershell -ExecutionPolicy Bypass -File mdm\tests\test-lockdown-windows.ps1
  Elevated, on a disposable Windows host. Deploys into a temporary -Prefix (never the real
  C:\ProgramData) and checks the owner, the Users deny ACE (by SID), removal of an ACE planted in
  a pre-created folder, drift detection and self-heal, the ACL of the staged sources and their
  removal.
#>
$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0; $skip = 0
# Write-Host, not Write-Output: these run inside functions whose return values are captured.
function Ok($m)   { Write-Host "  PASS: $m"; $script:pass++ }
function Ng($m)   { Write-Host "  FAIL: $m"; $script:fail++ }
function Skip($m) { Write-Host "  SKIP: $m"; $script:skip++ }

$mdm    = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$repo   = Split-Path -Parent $mdm
$lockScript = Join-Path $mdm 'lockdown-windows.ps1'
$host_exe = (Get-Process -Id $PID).Path            # powershell.exe or pwsh.exe
$w = Join-Path ([System.IO.Path]::GetTempPath()) ('kiro-win-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $w | Out-Null
foreach ($v in 'KIRO_MANAGED_SETTINGS_SRC','KIRO_HOOKS_SRC','KIRO_HOOKS_MANIFEST_SHA256','KIRO_DEPLOY_HOOKS','KIRO_DRY_RUN','KIRO_STRICT','KIRO_ROOT_PREFIX') {
  Remove-Item "Env:$v" -ErrorAction SilentlyContinue
}

function Invoke-Lockdown([string[]]$LockArgs) {
  $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try {
    $out = & $host_exe -NoProfile -ExecutionPolicy Bypass -File $lockScript @LockArgs 2>&1
    $rc = $LASTEXITCODE
  } finally { $ErrorActionPreference = $old }
  return @{ rc = $rc; out = ($out | Out-String) }
}
function Expect([int]$Want, [string]$Desc, [string[]]$LockArgs) {
  $r = Invoke-Lockdown $LockArgs
  if ($r.rc -eq $Want) { Ok "$Desc (rc=$($r.rc))" } else { Ng "$Desc (rc=$($r.rc), expected $Want)"; Write-Host $r.out }
  return $r
}
$utf8 = New-Object System.Text.UTF8Encoding $false
function Write-Fixture([string]$Path, [string]$Text) { [System.IO.File]::WriteAllText($Path, $Text, $utf8) }
$testKey = 'HKCU:\SOFTWARE\KiroLockdownTest'

# Runs a script with STDOUT and STDERR captured separately (Win32 detection fails on any STDERR).
function Invoke-Captured([string]$File) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $host_exe
  $psi.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$File`""
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  $errTask = $p.StandardError.ReadToEndAsync()
  $out = $p.StandardOutput.ReadToEnd()
  $p.WaitForExit()
  return @{ rc = $p.ExitCode; out = $out.Trim(); err = $errTask.Result.Trim() }
}

# Copies an Intune wrapper and rewrites its configuration block, as an administrator would.
function New-WrapperCopy([string]$Name, [string]$Deploy, [string[]]$Opts, [string]$Log, [string]$Policy = '', [string]$Expected = '') {
  $q = { param($s) "'" + ($s -replace "'", "''") + "'" }
  $text = [System.IO.File]::ReadAllText((Join-Path $mdm "intune\$Name"))
  $set = [ordered]@{
    '(?m)^\$DeployDir = .*$' = '$DeployDir = ' + (& $q $Deploy)
    '(?m)^\$Options = .*$'   = '$Options = @(' + ((@($Opts) | ForEach-Object { & $q $_ }) -join ', ') + ')'
    '(?m)^\$LogFile = .*$'   = '$LogFile = ' + (& $q $Log)
  }
  if ($Policy) { $set['(?m)^\$PolicyFile = .*$'] = '$PolicyFile = ' + (& $q $Policy) }
  if ($Expected) { $set['(?m)^\$ExpectedPolicySha256 = .*$'] = '$ExpectedPolicySha256 = ' + (& $q $Expected) }
  foreach ($k in $set.Keys) {
    if (-not [regex]::IsMatch($text, $k)) { throw "configuration line $k not found in $Name" }
    $text = [regex]::Replace($text, $k, $set[$k].Replace('$', '$$'))
  }
  $dir = Join-Path $w 'wrappers'; New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $dest = Join-Path $dir ("{0}-{1}" -f ([guid]::NewGuid().ToString('N').Substring(0, 6)), $Name)
  Write-Fixture $dest $text
  return $dest
}

function Expect-Wrapper([string]$File, [int]$Want, [string]$Desc, [string]$StartsWith) {
  $r = Invoke-Captured $File
  $lines = @($r.out -split "`r?`n" | Where-Object { $_ -ne '' })
  $okOut = ($lines.Count -eq 1) -and ($r.out.Length -le 2048) -and ((-not $StartsWith) -or $r.out.StartsWith($StartsWith))
  if ($r.rc -eq $Want -and $okOut) { Ok "$Desc (rc=$($r.rc): $($r.out))" } else { Ng "$Desc (rc=$($r.rc), expected $Want; out=[$($r.out)] err=[$($r.err)])" }
  return $r
}

function Expect-Win32([string]$File, [bool]$Detected, [string]$Desc) {
  $r = Invoke-Captured $File
  $isDetected = ($r.rc -eq 0) -and ($r.out -ne '') -and ($r.err -eq '')
  $silent = ($r.out -eq '') -and ($r.err -eq '')
  if (($Detected -and $isDetected) -or (-not $Detected -and $r.rc -ne 0 -and $silent)) { Ok "$Desc (rc=$($r.rc))" }
  else { Ng "$Desc (rc=$($r.rc); out=[$($r.out)] err=[$($r.err)])" }
}

try {
  Write-Output '== DRY RUN: shipped managed-settings =='
  $bank = Join-Path $repo 'managed-settings\managed-settings.banking.json'
  if (Test-Path $bank) {
    $r = Expect 0 'Option A policy validates' @('-DryRun')
    if ($r.out -match [regex]::Escape('C:\ProgramData\Kiro\managed-settings.json')) { Ok 'plans the official Windows path' } else { Ng 'official path not in plan' }
    $null = Expect 0 'Option B policy validates' @('-DryRun', '-OptionB')
    $null = Expect 2 '-Strict refuses the shipped placeholders' @('-DryRun', '-Strict')
  } else { Skip 'managed-settings.banking.json not present' }

  Write-Output '== DRY RUN: invalid policies are refused =='
  $cases = [ordered]@{
    'effect "allow" refused'          = '{"rules":[{"capability":"shell","match":["git *"],"effect":"allow"}]}'
    'malformed JSON refused'          = '{"rules":[{"capability":"shell","effect":"deny"}'
    'unknown top-level field refused' = '{"rules":[],"comment":"x"}'
    'unknown rule field refused'      = '{"rules":[{"capability":"shell","match":["sudo *"],"effect":"deny","note":"x"}]}'
    'missing rules refused'           = '{"settings":{"idc_region":"us-east-1"}}'
    'comments refused'                = "{`n// comment`n""rules"":[]}"
    'http auth_portal_url refused'    = '{"rules":[],"settings":{"auth_portal_url":"http://signin.bank.test"}}'
    'auth_portal_url with a query refused' = '{"rules":[],"settings":{"auth_portal_url":"https://signin.bank.test/kiro?tenant=1"}}'
    'auth_portal_url with credentials refused' = '{"rules":[],"settings":{"auth_portal_url":"https://user@signin.bank.test"}}'
  }
  $n = 0
  foreach ($k in $cases.Keys) {
    $n++; $f = Join-Path $w "bad$n.json"; Write-Fixture $f $cases[$k]
    $null = Expect 2 $k @('-DryRun', '-SettingsPath', $f)
  }
  $portal = Join-Path $w 'portal-ok.json'
  Write-Fixture $portal '{"rules":[],"settings":{"auth_portal_url":"https://signin.bank.test/kiro"}}'
  $null = Expect 0 '-Strict accepts a valid auth_portal_url (a documented key since Kiro CLI 3.5.0)' @('-DryRun', '-Strict', '-SettingsPath', $portal)
  $bom = Join-Path $w 'bom.json'
  [System.IO.File]::WriteAllText($bom, '{"rules":[]}', (New-Object System.Text.UTF8Encoding $true))
  $null = Expect 2 'UTF-8 BOM refused' @('-DryRun', '-SettingsPath', $bom)
  $u16 = Join-Path $w 'utf16.json'
  [System.IO.File]::WriteAllText($u16, '{"rules":[]}', [System.Text.Encoding]::Unicode)
  $null = Expect 2 'UTF-16 refused (what Out-File writes by default in Windows PowerShell)' @('-DryRun', '-SettingsPath', $u16)

  Write-Output '== DRY RUN: hook manifest =='
  $fx = Join-Path $w 'fixture'; New-Item -ItemType Directory -Force -Path $fx | Out-Null
  $lines = @()
  foreach ($s in Get-ChildItem -Path (Join-Path $repo 'agent-hooks') -Filter '*.sh' -File) {
    Copy-Item $s.FullName (Join-Path $fx $s.Name)
    $lines += ('{0}  {1}' -f (Get-FileHash -Algorithm SHA256 (Join-Path $fx $s.Name)).Hash.ToLowerInvariant(), $s.Name)
  }
  [System.IO.File]::WriteAllText((Join-Path $fx 'SHA256SUMS'), (($lines -join "`n") + "`n"), $utf8)
  $null = Expect 0 'fixture hooks verify' @('-DryRun', '-DeployHooks', '-HooksSource', $fx)
  $first = ($lines[0] -split '  ')[1]
  Add-Content -LiteralPath (Join-Path $fx $first) -Value 'exit 0'
  $r = Expect 2 'tampered hook refused' @('-DryRun', '-DeployHooks', '-HooksSource', $fx)
  if ($r.out -notmatch 'would write') { Ok 'validate-before-apply: no write planned after the refusal' } else { Ng 'a write was planned despite the refusal' }

  Write-Output '== DRY RUN: planted junction is refused =='
  $jroot = Join-Path $w 'prefix-junction'
  $jpd = Join-Path $jroot 'ProgramData'
  $elsewhere = Join-Path $w 'user-controlled'
  New-Item -ItemType Directory -Force -Path $jpd, $elsewhere | Out-Null
  try {
    New-Item -ItemType Junction -Path (Join-Path $jpd 'Kiro') -Target $elsewhere | Out-Null
    $null = Expect 1 'junction at ProgramData\Kiro refused' @('-DryRun', '-Prefix', $jroot)
  } catch { Skip "cannot create a junction here: $($_.Exception.Message)" }

  Write-Output '== UTF-8 without BOM writer (temp prefix, no ACL changes) =='
  $src = Join-Path $w 'ok.json'
  Write-Fixture $src '{"rules":[{"capability":"web_fetch","effect":"deny"}],"settings":{"signin_help_url":"https://it.bank.test/kiro"}}'
  $pre = Join-Path $w 'prefix'
  $null = Expect 0 'deploy into a temporary prefix' @('-SettingsPath', $src, '-Prefix', $pre, '-NoAclLock')
  $dest = Join-Path $pre 'ProgramData\Kiro\managed-settings.json'
  if (Test-Path $dest) {
    $b = [System.IO.File]::ReadAllBytes($dest)
    if (-not ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)) { Ok 'written without a UTF-8 BOM' } else { Ng 'file starts with a BOM' }
    if ($b[0] -eq 0x7B) { Ok 'first byte is "{" (not UTF-16)' } else { Ng "unexpected first byte $($b[0])" }
    if ([System.IO.File]::ReadAllText($src) -eq [System.IO.File]::ReadAllText($dest)) { Ok 'content identical to the source' } else { Ng 'content differs' }
  } else { Ng "managed-settings not written to $dest" }
  $r = Expect 0 'second run is idempotent' @('-SettingsPath', $src, '-Prefix', $pre, '-NoAclLock')
  if ($r.out -match 'unchanged') { Ok 'reports unchanged' } else { Ng 'did not report unchanged' }
  $null = Expect 0 '-Check is clean' @('-Check', '-SettingsPath', $src, '-Prefix', $pre, '-NoAclLock')
  Add-Content -LiteralPath $dest -Value ' '
  $null = Expect 3 '-Check detects drift' @('-Check', '-SettingsPath', $src, '-Prefix', $pre, '-NoAclLock')

  Write-Output '== Intune: -StageSources and the wrapper exit-code mapping (temp prefix, no ACL changes) =='
  $pre4 = Join-Path $w 'prefix-intune'
  $null = Expect 0 'deploy with -StageSources' @('-SettingsPath', $src, '-Prefix', $pre4, '-NoAclLock', '-StageSources')
  $deploy = Join-Path $pre4 'ProgramData\Kiro\deploy'
  $stagedScript = Join-Path $deploy 'mdm\lockdown-windows.ps1'
  $stagedPolicy = Join-Path $deploy 'managed-settings\ok.json'
  $dest4 = Join-Path $pre4 'ProgramData\Kiro\managed-settings.json'
  if ((Test-Path $stagedScript) -and (Test-Path $stagedPolicy)) { Ok 'script and policy staged in the repository layout' } else { Ng 'staged files missing' }
  if ((Test-Path $stagedScript) -and (Get-FileHash $stagedScript).Hash -eq (Get-FileHash $lockScript).Hash) { Ok 'staged script is identical to the source' } else { Ng 'staged script differs from the source' }
  $null = Expect 0 '-Check against the staged policy is clean' @('-Check', '-SettingsPath', $stagedPolicy, '-Prefix', $pre4, '-NoAclLock')
  $logs = Join-Path $w 'ime-logs'; New-Item -ItemType Directory -Force -Path $logs | Out-Null
  $wopts = @('-SettingsPath', $stagedPolicy, '-Prefix', $pre4, '-NoAclLock')
  $detect = New-WrapperCopy 'Detect-KiroPolicy.ps1' $deploy $wopts (Join-Path $logs 'detect.log')
  $remed  = New-WrapperCopy 'Remediate-KiroPolicy.ps1' $deploy $wopts (Join-Path $logs 'remediate.log')
  $win32  = New-WrapperCopy 'Detect-KiroPolicy-Win32.ps1' $deploy $wopts (Join-Path $logs 'win32.log')
  $null = Expect-Wrapper $detect 0 'Remediations detection: compliant -> exit 0' 'COMPLIANT'
  Expect-Win32 $win32 $true 'Win32 detection: compliant -> exit 0 with STDOUT and empty STDERR'
  if (Test-Path (Join-Path $logs 'detect.log')) { Ok 'full -Check output written to the log file' } else { Ng 'detection log not written' }
  Add-Content -LiteralPath $dest4 -Value ' '
  $null = Expect-Wrapper $detect 1 'Remediations detection: drift (lockdown exit 3) -> exit 1' 'NON-COMPLIANT: drift'
  Expect-Win32 $win32 $false 'Win32 detection: drift -> not detected, no output'
  $null = Expect-Wrapper $remed 0 'remediation restores the policy' 'REMEDIATED'
  $null = Expect-Wrapper $detect 0 'Remediations detection: compliant after remediation' 'COMPLIANT'
  Move-Item -LiteralPath $stagedPolicy -Destination "$stagedPolicy.bak"
  $r = Expect-Wrapper $detect 1 'Remediations detection: staged policy missing (lockdown exit 2) -> exit 1' 'NON-COMPLIANT'
  if ($r.out -match 'exited 2') { Ok 'summary names the lockdown exit code' } else { Ng "summary lacks the exit code: $($r.out)" }
  Expect-Win32 $win32 $false 'Win32 detection: staged policy missing -> not detected'
  $null = Expect-Wrapper $remed 1 'remediation fails visibly when the source is missing' 'FAILED'
  Move-Item -LiteralPath "$stagedPolicy.bak" -Destination $stagedPolicy

  # A new package version: the expected policy hash decides, not the device's own staged copy.
  $curHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $dest4).Hash
  $eDetect = New-WrapperCopy 'Detect-KiroPolicy.ps1' $deploy $wopts (Join-Path $logs 'e-detect.log') $dest4 $curHash
  $eWin32  = New-WrapperCopy 'Detect-KiroPolicy-Win32.ps1' $deploy $wopts (Join-Path $logs 'e-win32.log') $dest4 $curHash
  $null = Expect-Wrapper $eDetect 0 'expected policy hash matches -> compliant' 'COMPLIANT'
  Expect-Win32 $eWin32 $true 'expected policy hash matches -> detected'
  $newHash = '0' * 64
  $nDetect = New-WrapperCopy 'Detect-KiroPolicy.ps1' $deploy $wopts (Join-Path $logs 'n-detect.log') $dest4 $newHash
  $nWin32  = New-WrapperCopy 'Detect-KiroPolicy-Win32.ps1' $deploy $wopts (Join-Path $logs 'n-win32.log') $dest4 $newHash
  $nRemed  = New-WrapperCopy 'Remediate-KiroPolicy.ps1' $deploy $wopts (Join-Path $logs 'n-remed.log') $dest4 $newHash
  $r = Expect-Wrapper $nDetect 1 'device still on an older package (other expected hash) -> exit 1' 'NON-COMPLIANT'
  if ($r.out -match 'not the version of the current package') { Ok 'summary says the package is not current' } else { Ng "unexpected summary: $($r.out)" }
  Expect-Win32 $nWin32 $false 'older package -> Win32 app not detected, so Intune installs the new package'
  $null = Expect-Wrapper $nRemed 1 'remediation cannot replace an older package and says so' 'FAILED'
  $before = (Get-Item -LiteralPath (Join-Path $logs 'detect.log')).Length
  $null = Invoke-Captured $detect
  if ((Get-Item -LiteralPath (Join-Path $logs 'detect.log')).Length -gt $before) { Ok 'the log is appended, not overwritten' } else { Ng 'the log was overwritten' }

  $stub = Join-Path $w 'stub-deploy'; New-Item -ItemType Directory -Force -Path (Join-Path $stub 'mdm') | Out-Null
  $sDetect = New-WrapperCopy 'Detect-KiroPolicy.ps1' $stub @() (Join-Path $logs 'stub.log')
  $sWin32  = New-WrapperCopy 'Detect-KiroPolicy-Win32.ps1' $stub @() (Join-Path $logs 'stub-win32.log')
  foreach ($code in 0, 1, 2, 3, 5) {
    Write-Fixture (Join-Path $stub 'mdm\lockdown-windows.ps1') "[Console]::Error.WriteLine('[lockdown-windows] ERROR: stub'); exit $code"
    if ($code -eq 0) { Write-Fixture (Join-Path $stub 'mdm\lockdown-windows.ps1') 'exit 0' }
    $want = 1; if ($code -eq 0) { $want = 0 }
    $null = Expect-Wrapper $sDetect $want "Remediations detection maps lockdown exit $code to exit $want" ''
    Expect-Win32 $sWin32 ($code -eq 0) "Win32 detection maps lockdown exit $code to detected=$($code -eq 0)"
  }
  $none = Join-Path $w 'no-deploy'
  $null = Expect-Wrapper (New-WrapperCopy 'Detect-KiroPolicy.ps1' $none @() (Join-Path $logs 'n.log')) 1 'Remediations detection: no staged script -> exit 1' 'NON-COMPLIANT: staged script not found'
  Expect-Win32 (New-WrapperCopy 'Detect-KiroPolicy-Win32.ps1' $none @() (Join-Path $logs 'n2.log')) $false 'Win32 detection: no staged script -> not detected'
  $null = Expect-Wrapper (New-WrapperCopy 'Remediate-KiroPolicy.ps1' $none @() (Join-Path $logs 'n3.log')) 1 'remediation: no staged script -> exit 1' 'FAILED'

  $null = Expect 0 '-RemoveSources removes the staged folder' @('-Prefix', $pre4, '-NoAclLock', '-RemoveSources')
  if (-not (Test-Path $deploy)) { Ok 'staged folder removed' } else { Ng 'staged folder still present' }
  if (Test-Path $dest4) { Ok '-RemoveSources leaves the policy in place' } else { Ng 'policy removed by -RemoveSources' }
  $null = Expect 1 '-RemoveSources with -Check is a usage error' @('-Prefix', $pre4, '-NoAclLock', '-RemoveSources', '-Check')

  Write-Output '== -DisableUpdates (test key under HKCU in test mode) =='
  Remove-Item -LiteralPath $testKey -Recurse -Force -ErrorAction SilentlyContinue
  $pre5 = Join-Path $w 'prefix-updates'
  $null = Expect 0 'set UpdateMode = none' @('-SettingsPath', $src, '-Prefix', $pre5, '-NoAclLock', '-DisableUpdates')
  $polKey = "$testKey\Policies\Kiro"
  $v = (Get-ItemProperty -LiteralPath $polKey -Name UpdateMode -ErrorAction SilentlyContinue).UpdateMode
  if ($v -ceq 'none') { Ok 'UpdateMode is none' } else { Ng "UpdateMode is [$v]" }
  if ((Test-Path $polKey) -and (Get-Item -LiteralPath $polKey).GetValueKind('UpdateMode') -eq 'String') { Ok 'UpdateMode is REG_SZ' } else { Ng 'UpdateMode is not REG_SZ' }
  $null = Expect 0 '-Check is clean' @('-Check', '-SettingsPath', $src, '-Prefix', $pre5, '-NoAclLock', '-DisableUpdates')
  Set-ItemProperty -LiteralPath $polKey -Name UpdateMode -Value 'default'
  $null = Expect 3 '-Check detects a changed UpdateMode' @('-Check', '-SettingsPath', $src, '-Prefix', $pre5, '-NoAclLock', '-DisableUpdates')
  Remove-ItemProperty -LiteralPath $polKey -Name UpdateMode
  $null = Expect 3 '-Check detects a deleted UpdateMode' @('-Check', '-SettingsPath', $src, '-Prefix', $pre5, '-NoAclLock', '-DisableUpdates')
  $null = Expect 0 're-run restores UpdateMode' @('-SettingsPath', $src, '-Prefix', $pre5, '-NoAclLock', '-DisableUpdates')
  $null = Expect 0 '-Check is clean after the restore' @('-Check', '-SettingsPath', $src, '-Prefix', $pre5, '-NoAclLock', '-DisableUpdates')

  Write-Output '== -InstallUser (fake profiles under the temp prefix) =='
  $pre6 = Join-Path $w 'prefix-users'
  foreach ($u in 'alice', 'Default') { New-Item -ItemType Directory -Force -Path (Join-Path $pre6 "Users\$u") | Out-Null }
  $hooksRepo = Join-Path $repo 'agent-hooks'
  $uargs = @('-SettingsPath', $src, '-Prefix', $pre6, '-NoAclLock', '-InstallUser', '-HooksSource', $hooksRepo)
  $null = Expect 0 'deploy hooks and per-user hook files' $uargs
  $hd = Join-Path $pre6 'ProgramData\Kiro\hooks'
  foreach ($g in 'pii-guard.ps1', 'git-guard.ps1', 'destructive-fs-guard.ps1', 'pii-guard.sh') {
    if (Test-Path (Join-Path $hd $g)) { Ok "deployed $g" } else { Ng "$g not deployed to $hd" }
  }
  $fwd = ($hd -replace '\\', '/') + '/'
  foreach ($u in 'alice', 'Default') {
    $f = Join-Path $pre6 "Users\$u\.kiro\hooks\banking-guards.windows.json"
    if (-not (Test-Path $f)) { Ng "hook file missing for $u"; continue }
    $cmds = @((Get-Content -LiteralPath $f -Raw | ConvertFrom-Json).hooks | ForEach-Object { $_.action.command })
    $bad = @($cmds | Where-Object { -not $_.Contains($fwd) })
    if ($cmds.Count -gt 0 -and $bad.Count -eq 0) { Ok "hook file for $u points at the deployed guards" } else { Ng "hook file for ${u}: $($bad -join '; ')" }
  }
  $null = Expect 0 '-Check is clean' (@('-Check') + $uargs)
  $af = Join-Path $pre6 'Users\alice\.kiro\hooks\banking-guards.windows.json'
  Write-Fixture $af '{"version":"v1","hooks":[]}'
  $null = Expect 3 '-Check reports an edited user hook file' (@('-Check') + $uargs)
  $null = Expect 0 're-run restores the user hook file' $uargs
  $null = Expect 0 '-Check is clean after the restore' (@('-Check') + $uargs)

  $badHooks = Join-Path $w 'hooks-bad'
  Copy-Item -Recurse -LiteralPath $hooksRepo -Destination $badHooks
  $bj = Join-Path $badHooks 'hooks\banking-guards.windows.json'
  Write-Fixture $bj ((Get-Content -LiteralPath $bj -Raw).Replace('C:/ProgramData/Kiro/hooks/pii-guard.ps1', 'C:/Temp/evil.ps1'))
  $newHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $bj).Hash.ToLowerInvariant()
  $man = Join-Path $badHooks 'SHA256SUMS'
  $manText = (@([System.IO.File]::ReadAllLines($man) | ForEach-Object { if ($_ -match ' [ *]hooks/banking-guards\.windows\.json$') { "$newHash  hooks/banking-guards.windows.json" } else { $_ } }) -join "`n") + "`n"
  Write-Fixture $man $manText
  $null = Expect 2 'a user hook file with a command outside the hook directory is refused' @('-DryRun', '-SettingsPath', $src, '-Prefix', $pre6, '-InstallUser', '-HooksSource', $badHooks)

  $bob = Join-Path $pre6 'Users\bob'; $bobTarget = Join-Path $w 'bob-elsewhere'
  New-Item -ItemType Directory -Force -Path $bob, $bobTarget | Out-Null
  try {
    New-Item -ItemType Junction -Path (Join-Path $bob '.kiro') -Target $bobTarget | Out-Null
    $r = Expect 0 'a junction at a profile .kiro is skipped, not followed' $uargs
    if ($r.out -match 'skipping') { Ok 'warns about the skipped profile' } else { Ng 'no warning for the skipped profile' }
    if (-not (Test-Path (Join-Path $bobTarget 'hooks'))) { Ok 'nothing written through the junction' } else { Ng 'wrote through the junction' }
    $null = Expect 3 '-Check reports the junction' (@('-Check') + $uargs)
  } catch { Skip "cannot create a junction here: $($_.Exception.Message)" }

  Write-Output '== -InstallUser: one broken profile does not stop the others =='
  $pre9 = Join-Path $w 'prefix-odd-profiles'
  foreach ($u in 'carol', 'dave', 'erin') { New-Item -ItemType Directory -Force -Path (Join-Path $pre9 "Users\$u") | Out-Null }
  Write-Fixture (Join-Path $pre9 'Users\carol\.kiro') 'not a directory'
  New-Item -ItemType Directory -Force -Path (Join-Path $pre9 'Users\dave\.kiro\hooks\banking-guards.windows.json\x') | Out-Null
  $oargs = @('-SettingsPath', $src, '-Prefix', $pre9, '-NoAclLock', '-InstallUser', '-DisableUpdates', '-StageSources', '-HooksSource', $hooksRepo)
  $r = Expect 0 'deploy with a file at .kiro and a directory at the hook file path' $oargs
  if (@([regex]::Matches($r.out, 'skipping ')).Count -ge 2) { Ok 'both odd profiles are skipped with a warning' } else { Ng 'odd profiles were not reported' }
  if (Test-Path (Join-Path $pre9 'Users\erin\.kiro\hooks\banking-guards.windows.json')) { Ok 'the healthy profile still gets its hook file' } else { Ng 'the healthy profile was not written' }
  if (Test-Path (Join-Path $pre9 'ProgramData\Kiro\deploy\mdm\lockdown-windows.ps1')) { Ok 'staging still ran' } else { Ng 'staging did not run' }
  $null = Expect 3 '-Check reports the odd profiles as drift' (@('-Check') + $oargs)

  Write-Output '== -RemoveSources does not follow a junction inside the staged tree =='
  $outside = Join-Path $w 'outside-target'; New-Item -ItemType Directory -Force -Path $outside | Out-Null
  Write-Fixture (Join-Path $outside 'keep.txt') 'must survive'
  try {
    New-Item -ItemType Junction -Path (Join-Path $pre9 'ProgramData\Kiro\deploy\planted') -Target $outside | Out-Null
    $null = Expect 0 '-RemoveSources with a planted junction' @('-Prefix', $pre9, '-NoAclLock', '-RemoveSources')
    if (Test-Path (Join-Path $outside 'keep.txt')) { Ok 'the junction target is untouched' } else { Ng 'the junction target was deleted' }
    if (-not (Test-Path (Join-Path $pre9 'ProgramData\Kiro\deploy'))) { Ok 'the staged tree is removed' } else { Ng 'the staged tree is still present' }
  } catch { Skip "cannot create a junction here: $($_.Exception.Message)" }

  Write-Output '== a directory at a destination file path is refused =='
  $pre10 = Join-Path $w 'prefix-dir-at-file'
  New-Item -ItemType Directory -Force -Path (Join-Path $pre10 'ProgramData\Kiro\managed-settings.json') | Out-Null
  $r = Expect 1 'deploy refuses a directory at the policy path' @('-SettingsPath', $src, '-Prefix', $pre10, '-NoAclLock')
  # Windows PowerShell 5.1 wraps stderr text at the console width, so compare without white space.
  if (($r.out -replace '\s', '') -match 'adirectoryexistsatthatpath') { Ok 'the refusal names the cause' } else { Ng 'unclear refusal message' }
  $null = Expect 3 '-Check reports it as drift' @('-Check', '-SettingsPath', $src, '-Prefix', $pre10, '-NoAclLock')

  if ($env:KIRO_MDM_ADMIN_TESTS -ne '1') {
    Write-Output ''
    Write-Output '(admin tests not run: set KIRO_MDM_ADMIN_TESTS=1 and run elevated on a disposable host)'
  } else {
    Write-Output '== ADMIN: ACL lockdown in a temporary prefix =='
    $pre2 = Join-Path $w 'prefix-acl'
    $null = Expect 0 'deploy with ACL lock' @('-SettingsPath', $src, '-Prefix', $pre2)
    $d2 = Join-Path $pre2 'ProgramData\Kiro\managed-settings.json'
    $acl = Get-Acl -LiteralPath $d2
    $deny = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-545' })
    if ($deny.Count -gt 0) { Ok 'deny ACE for BUILTIN\Users (S-1-5-32-545) present' } else { Ng 'no deny ACE for Users' }
    $rights = ($deny | ForEach-Object { $_.FileSystemRights.ToString() }) -join ','
    if ($rights -match 'Delete') { Ok "Users denied Delete ($rights)" } else { Ng "Delete not denied: $rights" }
    if ($rights -match 'WriteData|Write') { Ok 'Users denied Write' } else { Ng "Write not denied: $rights" }
    $owner = (New-Object System.Security.Principal.NTAccount($acl.Owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($owner -eq 'S-1-5-32-544') { Ok 'owner is BUILTIN\Administrators' } else { Ng "owner is $($acl.Owner)" }

    # A folder pre-created with an extra grant (what a standard user could do before the first run).
    $pre3 = Join-Path $w 'prefix-planted'
    $planted = Join-Path $pre3 'ProgramData\Kiro'
    New-Item -ItemType Directory -Force -Path $planted | Out-Null
    & icacls.exe $planted /grant '*S-1-1-0:(OI)(CI)F' | Out-Null
    $r = Expect 0 'deploy over a pre-created folder with a planted Everyone:F grant' @('-SettingsPath', $src, '-Prefix', $pre3)
    if ($r.out -match 'moved aside') { Ok 'the folder that Everyone could re-permission is moved aside, not adopted' } else { Ng 'the planted folder was adopted' }
    $everyone = @((Get-Acl -LiteralPath $planted).Access | Where-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0' })
    if ($everyone.Count -eq 0) { Ok 'planted Everyone ACE removed' } else { Ng 'planted Everyone ACE still present' }
    $null = Expect 0 '-Check clean after the planted ACE was removed' @('-Check', '-SettingsPath', $src, '-Prefix', $pre3)
    & icacls.exe $d2 /remove:d '*S-1-5-32-545' | Out-Null
    Remove-Item -Force -LiteralPath $d2
    $null = Expect 3 '-Check detects the deleted file' @('-Check', '-SettingsPath', $src, '-Prefix', $pre2)
    $null = Expect 0 're-run restores it (self-heal)' @('-SettingsPath', $src, '-Prefix', $pre2)
    if (Test-Path $d2) { Ok 'file restored' } else { Ng 'file not restored' }
    $null = Expect 0 '-Check clean after self-heal' @('-Check', '-SettingsPath', $src, '-Prefix', $pre2)

    # The staged sources get the policy's ACL, so a standard user cannot plant a source that a
    # later remediation would deploy.
    $pre7 = Join-Path $w 'prefix-stage-acl'
    $null = Expect 0 'stage sources with ACL lock' @('-SettingsPath', $src, '-Prefix', $pre7, '-StageSources')
    foreach ($sf in 'mdm\lockdown-windows.ps1', 'managed-settings\ok.json') {
      $sp = Join-Path $pre7 "ProgramData\Kiro\deploy\$sf"
      $sdeny = @((Get-Acl -LiteralPath $sp).Access | Where-Object { $_.AccessControlType -eq 'Deny' -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-545' })
      if ($sdeny.Count -gt 0) { Ok "staged $sf carries the Users deny ACE" } else { Ng "staged $sf has no Users deny ACE" }
    }
    $null = Expect 0 '-Check clean including the staged copies' @('-Check', '-SettingsPath', $src, '-Prefix', $pre7, '-StageSources')
    # A folder owned by a non-administrator is never adopted: its owner could re-permission it later.
    $pre11 = Join-Path $w 'prefix-untrusted-dir'
    $ud = Join-Path $pre11 'ProgramData\Kiro'
    New-Item -ItemType Directory -Force -Path $ud | Out-Null
    Write-Fixture (Join-Path $ud 'managed-settings.json') '{"rules":[]}'
    & icacls.exe $ud /setowner '*S-1-5-32-545' | Out-Null
    $r = Expect 0 'deploy over a folder owned by BUILTIN\Users' @('-SettingsPath', $src, '-Prefix', $pre11)
    if ($r.out -match 'moved aside') { Ok 'the untrusted folder is moved aside' } else { Ng 'the untrusted folder was adopted' }
    if (@(Get-ChildItem -LiteralPath (Join-Path $pre11 'ProgramData') -Directory -Filter 'Kiro.untrusted-*').Count -eq 1) { Ok 'the old folder is kept for review' } else { Ng 'no Kiro.untrusted-* folder found' }
    $uowner = (New-Object System.Security.Principal.NTAccount((Get-Acl -LiteralPath $ud).Owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($uowner -eq 'S-1-5-32-544') { Ok 'the new folder is owned by Administrators' } else { Ng "new folder owner is $uowner" }
    $null = Expect 0 '-Check clean after the folder was replaced' @('-Check', '-SettingsPath', $src, '-Prefix', $pre11)

    # A file with the right content but an owner this script did not set is replaced, not re-locked.
    $uf = Join-Path $ud 'managed-settings.json'
    & icacls.exe $uf /remove:d '*S-1-5-32-545' | Out-Null
    & icacls.exe $uf /setowner '*S-1-5-32-545' | Out-Null
    $null = Expect 3 '-Check reports a file owned by BUILTIN\Users' @('-Check', '-SettingsPath', $src, '-Prefix', $pre11)
    $r = Expect 0 'deploy replaces the file although its content matches' @('-SettingsPath', $src, '-Prefix', $pre11)
    if ($r.out -match 'replacing ') { Ok 'the file object is replaced' } else { Ng 'the file was kept in place' }
    $null = Expect 0 '-Check clean after the file was replaced' @('-Check', '-SettingsPath', $src, '-Prefix', $pre11)
    $r = Expect 0 'a further run changes nothing' @('-SettingsPath', $src, '-Prefix', $pre11)
    if ($r.out -match 'unchanged') { Ok 'reports unchanged' } else { Ng 'did not report unchanged' }
    if (@(Get-ChildItem -LiteralPath (Join-Path $pre11 'ProgramData') -Directory -Filter 'Kiro.untrusted-*').Count -eq 1) { Ok 'no further folder is moved aside on later runs' } else { Ng 'a later run moved a folder aside again' }
    if (@(Get-ChildItem -LiteralPath (Join-Path $pre11 'ProgramData') -Directory -Filter 'Kiro.new-*').Count -eq 0) { Ok 'no temporary folder is left behind' } else { Ng 'a Kiro.new-* folder was left behind' }
    $stg = Join-Path $ud '.staging'
    if ((Test-Path $stg) -and @(Get-ChildItem -LiteralPath $stg -Force).Count -eq 0) { Ok 'the work folder is empty after the run' } else { Ng 'the work folder is missing or not empty' }
    $sacl = @((Get-Acl -LiteralPath $stg).Access | Where-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-545' })
    if ($sacl.Count -eq 0) { Ok 'standard users have no access to the work folder' } else { Ng 'BUILTIN\Users has an entry on the work folder' }

    $null = Expect 0 '-RemoveSources removes locked staged files' @('-Prefix', $pre7, '-RemoveSources')
    if (-not (Test-Path (Join-Path $pre7 'ProgramData\Kiro\deploy'))) { Ok 'locked staged folder removed' } else { Ng 'locked staged folder still present' }
  }
}
finally {
  Remove-Item -LiteralPath $testKey -Recurse -Force -ErrorAction SilentlyContinue
  if (Test-Path $w) {
    & icacls.exe $w /reset /T /C /Q 2>&1 | Out-Null
    Remove-Item -Recurse -Force -LiteralPath $w -ErrorAction SilentlyContinue
  }
}

Write-Output ''
Write-Output "RESULT: PASS=$pass FAIL=$fail SKIP=$skip"
if ($fail -ne 0) { exit 1 }
