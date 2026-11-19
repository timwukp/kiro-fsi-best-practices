<#
windows-suite.ps1 - runs on a DISPOSABLE Windows Server test instance (as SYSTEM, via SSM).

  powershell -NoProfile -ExecutionPolicy Bypass -File windows-suite.ps1 -RepoDir C:\kiro-test\repo

W1 checks:
  - mdm\tests\test-lockdown-windows.ps1 in default (non-admin) mode and with KIRO_MDM_ADMIN_TESTS=1,
    under Windows PowerShell 5.1 and PowerShell 7 (installed from the official Microsoft package)
  - a real mdm\lockdown-windows.ps1 deploy: C:\ProgramData\Kiro\managed-settings.json exists, is
    UTF-8 WITHOUT a BOM, parses as JSON, matches the source, carries the Users DENY ACE;
    -Check passes; a tamper is detected as drift (exit 3); re-applying restores (exit 0)
W3 checks: agent-hooks\tests\run-tests.ps1 (PowerShell hook guards) under 5.1 and 7.
(W2 is reserved for the Windows client validation tracked in issue #43; it is not part of this suite.)
W4 checks (real paths, SYSTEM): the Intune Win32 install command started from 32-bit PowerShell,
  UpdateMode in the 64-bit view, a 32-bit write to HKLM\SOFTWARE\Policies seen in the 64-bit view,
  the ACL of the staged sources and guards, the Default-profile hook file, the Remediations and Win32
  detection wrappers before and after a tamper, remediation, and the uninstall (-RemoveSources).

Output: "CHECK <id> PASS|FAIL|SKIP <detail>" lines and "PHASE W1,W3,W4 RESULT pass=<n> fail=<n> skip=<n>".
#>
param([Parameter(Mandatory = $true)][string]$RepoDir)

$ErrorActionPreference = 'Continue'
$script:Pass = 0; $script:Fail = 0; $script:Skip = 0
function Check([string]$Id, [string]$Status, [string]$Detail = '') {
  [Console]::Out.WriteLine("CHECK $Id $Status $Detail")
  switch ($Status) { 'PASS' { $script:Pass++ } 'FAIL' { $script:Fail++ } default { $script:Skip++ } }
}
function Invoke-Test([string]$Id, [string]$Shell, [string]$Script, [hashtable]$Env = @{}) {
  foreach ($k in $Env.Keys) { Set-Item -Path "Env:$k" -Value $Env[$k] }
  $out = & $Shell -NoProfile -ExecutionPolicy Bypass -File $Script 2>&1 | Out-String
  $rc = $LASTEXITCODE
  foreach ($k in $Env.Keys) { Remove-Item -Path "Env:$k" -ErrorAction SilentlyContinue }
  [Console]::Out.WriteLine("---- $Id (rc=$rc)"); [Console]::Out.WriteLine(($out -split "`n" | Select-Object -Last 25) -join "`n")
  $result = ($out -split "`n" | Where-Object { $_ -match '^RESULT: PASS=' } | Select-Object -Last 1)
  if ($rc -eq 0 -and $result -match 'FAIL=0') { Check $Id 'PASS' $result.Trim() } else { Check $Id 'FAIL' "rc=$rc $result" }
}

Set-Location -LiteralPath $RepoDir
$test = Join-Path $RepoDir 'mdm\tests\test-lockdown-windows.ps1'
$lock = Join-Path $RepoDir 'mdm\lockdown-windows.ps1'

# --- Windows PowerShell 5.1
Invoke-Test 'W1.ps51-default' 'powershell.exe' $test
Invoke-Test 'W1.ps51-admin' 'powershell.exe' $test @{ KIRO_MDM_ADMIN_TESTS = '1' }

# --- PowerShell 7 (official MSI via Microsoft's install script)
$pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
if (-not $pwsh) {
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $installer = Join-Path $env:TEMP 'install-powershell.ps1'
    Invoke-WebRequest -UseBasicParsing -Uri 'https://aka.ms/install-powershell.ps1' -OutFile $installer
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer -UseMSI -Quiet | Out-Null
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    if (-not $pwsh -and (Test-Path 'C:\Program Files\PowerShell\7\pwsh.exe')) { $pwsh = Get-Item 'C:\Program Files\PowerShell\7\pwsh.exe' }
  } catch { [Console]::Out.WriteLine("pwsh install error: $($_.Exception.Message)") }
}
if ($pwsh) {
  $pwshPath = if ($pwsh.Source) { $pwsh.Source } else { $pwsh.FullName }
  Check 'W1.pwsh7-installed' 'PASS' ((& $pwshPath -NoProfile -Command '$PSVersionTable.PSVersion.ToString()') | Out-String).Trim()
  Invoke-Test 'W1.pwsh7-default' $pwshPath $test
  Invoke-Test 'W1.pwsh7-admin' $pwshPath $test @{ KIRO_MDM_ADMIN_TESTS = '1' }
} else {
  Check 'W1.pwsh7-installed' 'FAIL' 'PowerShell 7 could not be installed'
}

# --- Real deployment to C:\ProgramData\Kiro (SYSTEM)
$target = 'C:\ProgramData\Kiro\managed-settings.json'
$source = Join-Path $RepoDir 'managed-settings\managed-settings.banking.json'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $lock | Out-String | Write-Output
if ($LASTEXITCODE -eq 0) { Check 'W1.lockdown' 'PASS' } else { Check 'W1.lockdown' 'FAIL' "rc=$LASTEXITCODE" }
if (Test-Path -LiteralPath $target) {
  Check 'W1.policy-present' 'PASS'
  $bytes = [System.IO.File]::ReadAllBytes($target)
  if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { Check 'W1.no-bom' 'FAIL' 'file starts with a UTF-8 BOM' } else { Check 'W1.no-bom' 'PASS' }
  try { Get-Content -LiteralPath $target -Raw | ConvertFrom-Json | Out-Null; Check 'W1.json' 'PASS' } catch { Check 'W1.json' 'FAIL' $_.Exception.Message }
  $same = ((Get-FileHash -LiteralPath $target).Hash -eq (Get-FileHash -LiteralPath $source).Hash)
  if ($same) { Check 'W1.content' 'PASS' } else { Check 'W1.content' 'FAIL' 'deployed file differs from source' }
  $deny = (Get-Acl -LiteralPath $target).Access | Where-Object { $_.AccessControlType -eq 'Deny' -and $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-545' }
  if ($deny) { Check 'W1.users-deny-ace' 'PASS' } else { Check 'W1.users-deny-ace' 'FAIL' 'no DENY ACE for BUILTIN\Users' }
} else {
  Check 'W1.policy-present' 'FAIL' "$target missing"
}
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $lock -Check | Out-Null
if ($LASTEXITCODE -eq 0) { Check 'W1.check-clean' 'PASS' } else { Check 'W1.check-clean' 'FAIL' "rc=$LASTEXITCODE" }
# Tamper as an administrator: drop the explicit DENY ACEs, then change the content.
icacls.exe $target /remove:d '*S-1-5-32-545' | Out-Null
Add-Content -LiteralPath $target -Value ' '
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $lock -Check | Out-Null
if ($LASTEXITCODE -eq 3) { Check 'W1.check-detects-drift' 'PASS' 'rc=3' } else { Check 'W1.check-detects-drift' 'FAIL' "rc=$LASTEXITCODE want=3" }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $lock | Out-Null
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $lock -Check | Out-Null
if ($LASTEXITCODE -eq 0) { Check 'W1.check-after-restore' 'PASS' } else { Check 'W1.check-after-restore' 'FAIL' "rc=$LASTEXITCODE" }

# --- W3: PowerShell hook guards under Windows PowerShell 5.1 and PowerShell 7
$hookTests = Join-Path $RepoDir 'agent-hooks\tests\run-tests.ps1'
Invoke-Test 'W3.hooks-ps51' 'powershell.exe' $hookTests
if ($pwsh) { Invoke-Test 'W3.hooks-pwsh7' $pwshPath $hookTests } else { Check 'W3.hooks-pwsh7' 'SKIP' 'no PowerShell 7' }

# Latency of one guard call, as Kiro pays it for every tool call (process start included). Kiro's
# hook timeout in the shipped hook file is 5 seconds, and a timeout is not a block.
$evt = '{"hook_event_name":"preToolUse","cwd":"C:/repo","session_id":"t","tool_name":"execute_pwsh","tool_input":{"command":"git status; Remove-Item -Recurse -Force .\\build; npm run build"}}'
$evtFile = Join-Path $env:TEMP 'kiro-guard-event.json'
[System.IO.File]::WriteAllText($evtFile, $evt, (New-Object System.Text.UTF8Encoding $false))
foreach ($g in 'pii-guard.ps1', 'git-guard.ps1', 'destructive-fs-guard.ps1') {
  $gp = Join-Path $RepoDir "agent-hooks\windows\$g"
  $times = @()
  foreach ($n in 1..3) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', "`"$gp`"") -RedirectStandardInput $evtFile -RedirectStandardError (Join-Path $env:TEMP 'kiro-guard-err.txt') -NoNewWindow -Wait -PassThru
    $sw.Stop(); $times += [int]$sw.ElapsedMilliseconds
  }
  $worst = ($times | Measure-Object -Maximum).Maximum
  if ($p.ExitCode -eq 0 -and $worst -lt 3000) { Check "W3.guard-latency:$g" 'PASS' "worst of 3 runs: $worst ms (hook timeout 5000 ms)" } else { Check "W3.guard-latency:$g" 'FAIL' "exit=$($p.ExitCode) times=$($times -join ',') ms" }
}

# --- W4: Intune flow on the real paths (SYSTEM): Win32 install command, wrappers, uninstall
$ps32 = Join-Path $env:SystemRoot 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
$ps64 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$opts = @('-DeployHooks', '-InstallUser', '-DisableUpdates')
$deployDir = 'C:\ProgramData\Kiro\deploy'
function Invoke-Separate([string]$Exe, [string[]]$Argv) {
  $o = Join-Path $env:TEMP ('kiro-o-' + [guid]::NewGuid().ToString('N') + '.txt'); $e = "$o.err"
  $quoted = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass') + @($Argv | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } })
  $p = Start-Process -FilePath $Exe -ArgumentList $quoted -RedirectStandardOutput $o -RedirectStandardError $e -NoNewWindow -Wait -PassThru
  $res = @{ rc = $p.ExitCode; out = ([System.IO.File]::ReadAllText($o)).Trim(); err = ([System.IO.File]::ReadAllText($e)).Trim() }
  Remove-Item -LiteralPath $o, $e -Force -ErrorAction SilentlyContinue
  return $res
}
function Get-Policy64([string]$Name) {
  $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
  try { $k = $base.OpenSubKey('SOFTWARE\Policies\Kiro'); if ($k) { try { return @{ v = $k.GetValue($Name); kind = "$($k.GetValueKind($Name))" } } finally { $k.Dispose() } } } catch { } finally { $base.Dispose() }
  return @{ v = $null; kind = '' }
}
function Test-UsersDeny([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return $false }
  return [bool](@((Get-Acl -LiteralPath $Path).Access | Where-Object { $_.AccessControlType -eq 'Deny' -and $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-545' }).Count)
}
$wdir = 'C:\kiro-test\wrappers'
New-Item -ItemType Directory -Force -Path $wdir | Out-Null
function New-Wrapper([string]$Name) {
  $t = [System.IO.File]::ReadAllText((Join-Path $RepoDir "mdm\intune\$Name"))
  $t = [regex]::Replace($t, '(?m)^\$Options = .*$', ('$Options = @(' + (($opts | ForEach-Object { "'$_'" }) -join ', ') + ')').Replace('$', '$$'))
  $d = Join-Path $wdir $Name
  [System.IO.File]::WriteAllText($d, $t, (New-Object System.Text.UTF8Encoding $false))
  return $d
}
# The wrappers log only when the Intune Management Extension log folder exists (disposable runner).
$imeLogs = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs'
New-Item -ItemType Directory -Force -Path $imeLogs | Out-Null
$detect = New-Wrapper 'Detect-KiroPolicy.ps1'
$remed = New-Wrapper 'Remediate-KiroPolicy.ps1'
$win32 = New-Wrapper 'Detect-KiroPolicy-Win32.ps1'

# Microsoft: powershell.exe in a Win32 install or uninstall command starts 32-bit PowerShell. Run it that way.
$r = Invoke-Separate $ps32 (@('-File', $lock, '-StageSources') + $opts)
if ($r.rc -eq 0) { Check 'W4.win32-install-32bit-host' 'PASS' } else { Check 'W4.win32-install-32bit-host' 'FAIL' "rc=$($r.rc) $($r.err)" }
$um = Get-Policy64 'UpdateMode'
if ($um.v -ceq 'none' -and $um.kind -eq 'String') { Check 'W4.updatemode-64bit-view' 'PASS' 'REG_SZ none' } else { Check 'W4.updatemode-64bit-view' 'FAIL' "value=[$($um.v)] kind=[$($um.kind)]" }
# Open question: does a plain 32-bit write to HKLM\SOFTWARE\Policies land in the 64-bit view?
& $ps32 -NoProfile -Command "New-Item -Path 'HKLM:\SOFTWARE\Policies\KiroWow64Probe' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\KiroWow64Probe' -Name Probe -Value 'x'" | Out-Null
$probe = $null
$b64 = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
try { $pk = $b64.OpenSubKey('SOFTWARE\Policies\KiroWow64Probe'); if ($pk) { $probe = $pk.GetValue('Probe'); $pk.Dispose() } } finally { $b64.Dispose() }
Remove-Item -Path 'HKLM:\SOFTWARE\Policies\KiroWow64Probe' -Recurse -Force -ErrorAction SilentlyContinue
if ($probe -eq 'x') { Check 'W4.wow64-policies-shared' 'PASS' 'a 32-bit write to HKLM\SOFTWARE\Policies is visible in the 64-bit view' } else { Check 'W4.wow64-policies-shared' 'FAIL' 'a 32-bit write did not reach the 64-bit view' }
foreach ($sf in 'mdm\lockdown-windows.ps1', 'managed-settings\managed-settings.banking.json', 'agent-hooks\SHA256SUMS', 'agent-hooks\windows\pii-guard.ps1') {
  if (Test-UsersDeny (Join-Path $deployDir $sf)) { Check "W4.staged-acl:$sf" 'PASS' } else { Check "W4.staged-acl:$sf" 'FAIL' 'missing or no Users DENY ACE' }
}
foreach ($g in 'pii-guard.ps1', 'git-guard.ps1', 'destructive-fs-guard.ps1') {
  if (Test-UsersDeny (Join-Path 'C:\ProgramData\Kiro\hooks' $g)) { Check "W4.hook:$g" 'PASS' } else { Check "W4.hook:$g" 'FAIL' 'missing or no Users DENY ACE' }
}
$defaultHook = 'C:\Users\Default\.kiro\hooks\banking-guards.windows.json'
if ((Test-Path -LiteralPath $defaultHook) -and ((Get-Content -LiteralPath $defaultHook -Raw) -match 'C:/ProgramData/Kiro/hooks/pii-guard\.ps1')) { Check 'W4.default-profile-hook-file' 'PASS' } else { Check 'W4.default-profile-hook-file' 'FAIL' "$defaultHook missing or wrong" }

$r = Invoke-Separate $ps64 @('-File', $detect)
if ($r.rc -eq 0 -and $r.out -like 'COMPLIANT*') { Check 'W4.detect-compliant' 'PASS' $r.out } else { Check 'W4.detect-compliant' 'FAIL' "rc=$($r.rc) $($r.out) $($r.err)" }
$r = Invoke-Separate $ps32 @('-File', $detect)
if ($r.rc -eq 0 -and $r.out -like 'COMPLIANT*') { Check 'W4.detect-from-32bit-host' 'PASS' 'Sysnative path' } else { Check 'W4.detect-from-32bit-host' 'FAIL' "rc=$($r.rc) $($r.out) $($r.err)" }
$r = Invoke-Separate $ps64 @('-File', $win32)
if ($r.rc -eq 0 -and $r.out -ne '' -and $r.err -eq '') { Check 'W4.win32-detected' 'PASS' } else { Check 'W4.win32-detected' 'FAIL' "rc=$($r.rc) out=[$($r.out)] err=[$($r.err)]" }
$r = Invoke-Separate $ps32 @('-File', $win32)
if ($r.rc -eq 0 -and $r.out -ne '' -and $r.err -eq '') { Check 'W4.win32-detected-from-32bit-host' 'PASS' } else { Check 'W4.win32-detected-from-32bit-host' 'FAIL' "rc=$($r.rc) out=[$($r.out)] err=[$($r.err)]" }

# Tamper as an administrator would: policy content, a user hook file and UpdateMode. The detection
# log is appended, so start a new one: the checks below must see this run only.
Remove-Item -LiteralPath (Join-Path $imeLogs 'KiroPolicy-Detect.log') -Force -ErrorAction SilentlyContinue
icacls.exe $target /remove:d '*S-1-5-32-545' | Out-Null
Add-Content -LiteralPath $target -Value ' '
Remove-Item -LiteralPath $defaultHook -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Kiro' -Name UpdateMode -Value 'default'
$r = Invoke-Separate $ps64 @('-File', $detect)
$driftCount = 0; if ($r.out -match 'drift in (\d+) item') { $driftCount = [int]$Matches[1] }
if ($r.rc -eq 1 -and $r.out -like 'NON-COMPLIANT: drift*' -and $r.out.Length -le 2048 -and $driftCount -ge 3) { Check 'W4.detect-drift' 'PASS' $r.out } else { Check 'W4.detect-drift' 'FAIL' "rc=$($r.rc) drift=$driftCount $($r.out)" }
# Each of the three tampers must be named in the full log, not only one of them.
$dlog = ''; try { $dlog = [System.IO.File]::ReadAllText((Join-Path $imeLogs 'KiroPolicy-Detect.log')) } catch { }
foreach ($t in @(@('policy', 'managed-settings\.json content differs'), @('user-hook-file', 'missing .*banking-guards\.windows\.json'), @('updatemode', 'UpdateMode is not REG_SZ'))) {
  if ($dlog -match ('DRIFT: .*' + $t[1])) { Check "W4.detect-drift-names:$($t[0])" 'PASS' } else { Check "W4.detect-drift-names:$($t[0])" 'FAIL' 'not reported in KiroPolicy-Detect.log' }
}
$r = Invoke-Separate $ps64 @('-File', $win32)
if ($r.rc -ne 0 -and $r.out -eq '' -and $r.err -eq '') { Check 'W4.win32-not-detected' 'PASS' } else { Check 'W4.win32-not-detected' 'FAIL' "rc=$($r.rc) out=[$($r.out)] err=[$($r.err)]" }
$r = Invoke-Separate $ps32 @('-File', $detect)
if ($r.rc -eq 1 -and $r.out -like 'NON-COMPLIANT: drift*') { Check 'W4.detect-drift-from-32bit-host' 'PASS' } else { Check 'W4.detect-drift-from-32bit-host' 'FAIL' "rc=$($r.rc) $($r.out)" }
$r = Invoke-Separate $ps32 @('-File', $win32)
if ($r.rc -ne 0 -and $r.out -eq '' -and $r.err -eq '') { Check 'W4.win32-not-detected-from-32bit-host' 'PASS' } else { Check 'W4.win32-not-detected-from-32bit-host' 'FAIL' "rc=$($r.rc) out=[$($r.out)] err=[$($r.err)]" }
$r = Invoke-Separate $ps64 @('-File', $remed)
if ($r.rc -eq 0 -and $r.out -like 'REMEDIATED*') { Check 'W4.remediate' 'PASS' $r.out } else { Check 'W4.remediate' 'FAIL' "rc=$($r.rc) $($r.out)" }
$r = Invoke-Separate $ps64 @('-File', $detect)
if ($r.rc -eq 0) { Check 'W4.detect-after-remediate' 'PASS' } else { Check 'W4.detect-after-remediate' 'FAIL' "rc=$($r.rc) $($r.out)" }
if ((Get-Policy64 'UpdateMode').v -ceq 'none') { Check 'W4.updatemode-restored' 'PASS' } else { Check 'W4.updatemode-restored' 'FAIL' }
# The same repair when Intune runs the remediation script in 32-bit PowerShell.
icacls.exe $target /remove:d '*S-1-5-32-545' | Out-Null
Add-Content -LiteralPath $target -Value ' '
$r = Invoke-Separate $ps32 @('-File', $remed)
if ($r.rc -eq 0 -and $r.out -like 'REMEDIATED*') { Check 'W4.remediate-from-32bit-host' 'PASS' $r.out } else { Check 'W4.remediate-from-32bit-host' 'FAIL' "rc=$($r.rc) $($r.out)" }
$r = Invoke-Separate $ps64 @('-File', $detect)
if ($r.rc -eq 0) { Check 'W4.detect-after-32bit-remediate' 'PASS' } else { Check 'W4.detect-after-32bit-remediate' 'FAIL' "rc=$($r.rc) $($r.out)" }

# Win32 app uninstall command: removes only the staged sources.
$r = Invoke-Separate $ps32 @('-File', $lock, '-RemoveSources')
if ($r.rc -eq 0 -and -not (Test-Path -LiteralPath $deployDir)) { Check 'W4.uninstall-removes-staged' 'PASS' } else { Check 'W4.uninstall-removes-staged' 'FAIL' "rc=$($r.rc) $($r.err)" }
if (Test-Path -LiteralPath $target) { Check 'W4.uninstall-keeps-policy' 'PASS' } else { Check 'W4.uninstall-keeps-policy' 'FAIL' 'policy removed' }
$r = Invoke-Separate $ps64 @('-File', $detect)
if ($r.rc -eq 1 -and $r.out -like '*staged script not found*') { Check 'W4.detect-after-uninstall' 'PASS' } else { Check 'W4.detect-after-uninstall' 'FAIL' "rc=$($r.rc) $($r.out)" }

[Console]::Out.WriteLine("PHASE W1,W3,W4 RESULT pass=$script:Pass fail=$script:Fail skip=$script:Skip")
if ($script:Fail -ne 0) { exit 1 } else { exit 0 }
