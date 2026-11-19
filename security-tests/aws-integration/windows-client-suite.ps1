<#
windows-client-suite.ps1 - runs on a DISPOSABLE Windows Server test instance (as SYSTEM, via SSM).

  powershell -NoProfile -ExecutionPolicy Bypass -File windows-client-suite.ps1 -RepoDir C:\kiro-test\repo

Opt-in stage "client" of run-integration.sh; never part of "all". It downloads the current Kiro IDE
system-wide installer and runs the automatable part of the W2 kit (security-tests\windows-client).
The runner is Windows Server 2022, which is outside Kiro's listed operating systems (Windows 10/11),
and no Kiro window is opened or signed in: the results show installer mechanics only.

WC checks:
  - WC.manifest, WC.download: installer URL from Kiro's update manifest (the URL must be on
    prod.download.desktop.kiro.dev; redirects issued by that host are followed), download with a
    20-minute limit; version, size and SHA-256
  - WC.signature-gate: the installer is run only when its Authenticode status is Valid and its signer
    subject starts with the subject measured for release 1.4.236 (see $SignerPin below). Kiro
    publishes no signer name (verify): when Kiro changes its certificate, compare and update the pin
  - the kit: Invoke-W2Checks.ps1 -InstallerPath -InstallPolicy -Wrappers -TamperTest, plus -Install and
    -ExpectedSignerSubject only when WC.signature-gate passed (its CHECK lines are passed through
    unchanged and counted); WC.kit says whether the kit ran to its end
  - WC.kit-pwsh7: the kit's read-only inventory (with the same signer check) again under PowerShell 7,
    when it is installed
  - WC.install-folder-entries: top-level names in the install folder
  - WC.uninstall-command:<hklm64|hklm32>: the UninstallString with the silent switches (plain
    WC.uninstall-command SKIP when there is no entry). It is run only when the environment variable
    KIRO_WC_UNINSTALL is 1 (WC.uninstall:<view>, WC.uninstall-leftovers:<view>)
  - WC.stop-kiro:before-install and :before-uninstall-<view> (INFO): only when KIRO_WC_STOP_KIRO is 1.
    Kiro.exe processes that run from the install folder are stopped first; the installer and the
    uninstaller end with exit code 1 while Kiro runs

KIRO_WC_INSTALLER_ARGS, when set, is passed to the kit as -InstallerArgs and replaces ALL default
installer switches, including /LOG.

Output: "CHECK <id> PASS|FAIL|SKIP|INFO <detail>" lines and "PHASE WC RESULT pass=<n> fail=<n> skip=<n> info=<n>".
#>
param([Parameter(Mandatory = $true)][string]$RepoDir)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$script:Pass = 0; $script:Fail = 0; $script:Skip = 0; $script:Info = 0
function Add-Count([string]$Status) {
  switch ($Status) { 'PASS' { $script:Pass++ } 'FAIL' { $script:Fail++ } 'INFO' { $script:Info++ } default { $script:Skip++ } }
}
function Check([string]$Id, [string]$Status, [string]$Detail = '') {
  [Console]::Out.WriteLine("CHECK $Id $Status " + ($Detail -replace '[\r\n]+', ' '))
  Add-Count $Status
}
function Finish {
  [Console]::Out.WriteLine("PHASE WC RESULT pass=$script:Pass fail=$script:Fail skip=$script:Skip info=$script:Info")
  if ($script:Fail -ne 0) { exit 1 } else { exit 0 }
}
# '' when the task finished in time, otherwise the reason.
function Wait-Task($Task, [int]$Seconds) {
  try {
    if (-not $Task.Wait($Seconds * 1000)) { return "not finished within $Seconds seconds" }
  } catch {
    $e = $_.Exception
    while ($e.InnerException) { $e = $e.InnerException }
    return $e.Message
  }
  return ''
}

[Console]::Out.WriteLine("NOTE WC runs on Windows Server 2022, outside Kiro's listed operating systems (Windows 10/11): installer mechanics only, no signed-in Kiro client")

$kit = Join-Path $RepoDir 'security-tests\windows-client\Invoke-W2Checks.ps1'
if (-not (Test-Path -LiteralPath $kit -PathType Leaf)) { Check 'WC.kit' 'FAIL' "kit script not found: $kit"; Finish }

# --- Installer: URL from Kiro's update manifest, then the download
$hostPrefix = 'https://prod.download.desktop.kiro.dev/'
$manifestUrl = $hostPrefix + 'stable/metadata-win32-x64-system-stable.json'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$version = ''; $url = ''; $problem = ''
$wc = New-Object System.Net.WebClient
try {
  $wc.Encoding = [System.Text.Encoding]::UTF8
  $task = $wc.DownloadStringTaskAsync($manifestUrl)
  $problem = Wait-Task $task 60
  if (-not $problem) {
    $m = $task.Result | ConvertFrom-Json
    $version = "$($m.currentRelease)"
    $rel = @($m.releases)[0]
    if ($rel -and $rel.updateTo) { $url = "$($rel.updateTo.url)" }
  }
} catch { $problem = $_.Exception.Message } finally { $wc.Dispose() }
if (-not $problem -and $version -notmatch '^[0-9A-Za-z.+-]{1,40}$') { $problem = 'currentRelease is missing or not a version string' }
if (-not $problem -and -not $url.StartsWith($hostPrefix, [System.StringComparison]::Ordinal)) { $problem = "releases[0].updateTo.url does not start with $hostPrefix" }
if (-not $problem -and ($url -notmatch '^https://[A-Za-z0-9._/-]+\.exe$' -or $url -match '\.\.')) { $problem = 'releases[0].updateTo.url is not a plain path to an .exe file' }
if ($problem) { Check 'WC.manifest' 'FAIL' "$manifestUrl - $problem"; Finish }
Check 'WC.manifest' 'PASS' "currentRelease=$version url=$url"

$dir = 'C:\kiro-test\installer'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$exe = Join-Path $dir ($url.Substring($url.LastIndexOf('/') + 1))
Remove-Item -LiteralPath $exe -Force -ErrorAction SilentlyContinue
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$wc = New-Object System.Net.WebClient
try {
  $task = $wc.DownloadFileTaskAsync($url, $exe)
  $problem = Wait-Task $task 1200
  if ($problem) { $wc.CancelAsync() }
} catch { $problem = $_.Exception.Message } finally { $wc.Dispose() }
$sw.Stop()
$size = 0
if (-not $problem) {
  if (Test-Path -LiteralPath $exe -PathType Leaf) { $size = (Get-Item -LiteralPath $exe).Length }
  $head = New-Object byte[] 2
  if ($size -ge 2) {
    $fs = [System.IO.File]::OpenRead($exe)
    try { $fs.Read($head, 0, 2) | Out-Null } finally { $fs.Dispose() }
  }
  # 0x4D 0x5A = "MZ": an error page saved as .exe must not reach the install step.
  if ($size -lt 1048576 -or $head[0] -ne 0x4D -or $head[1] -ne 0x5A) { $problem = "the downloaded file is not a Windows executable (bytes=$size)" }
}
if ($problem) {
  Remove-Item -LiteralPath $exe -Force -ErrorAction SilentlyContinue
  Check 'WC.download' 'FAIL' "$url - $problem"
  Finish
}
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash.ToLowerInvariant()
Check 'WC.download' 'PASS' "version=$version bytes=$size sha256=$sha seconds=$([int]$sw.Elapsed.TotalSeconds) file=$exe"

# Optional (KIRO_WC_STOP_KIRO=1): stop Kiro processes that run from the install folder. Without
# /MERGETASKS=!runcode a silent install starts Kiro, and the installer and the uninstaller both end
# with exit code 1 while it runs.
function Stop-KiroProcesses([string]$When) {
  if ($env:KIRO_WC_STOP_KIRO -ne '1') { return }
  $root = 'C:\Program Files\Kiro\'
  $procs = @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'Kiro.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase) })
  # The owner is read before the stop: a process that is gone has none.
  $who = @($procs | ForEach-Object {
      try {
        $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop
        if ($o.User) { [string]$o.User } else { "not read (GetOwner returned $($o.ReturnValue))" }
      } catch { 'not read (error)' }
    } | Sort-Object -Unique) -join ','
  if (-not $who) { $who = 'none' }
  foreach ($p in $procs) { try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop } catch { } }
  Start-Sleep -Seconds 3
  $left = @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'Kiro.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase) }).Count
  Check "WC.stop-kiro:$When" 'INFO' "Kiro.exe processes found running from ${root}: $($procs.Count) (owner: $who; session: $(@($procs | ForEach-Object { $_.SessionId } | Sort-Object -Unique) -join ',')); still running after the stop: $left"
}
Stop-KiroProcesses 'before-install'

# The suite runs the installer as SYSTEM, so it requires a valid signature and the known signer first.
# The pin is the start of the signer subject measured for release 1.4.236 (2026-11-19).
$SignerPin = 'CN="Amazon.com, Inc.", OU=AWS Kiro, O="Amazon.com, Inc.",'
$sigStatus = 'unknown'; $signer = ''
try {
  $sig = Get-AuthenticodeSignature -LiteralPath $exe
  $sigStatus = "$($sig.Status)"
  if ($null -ne $sig.SignerCertificate) { $signer = [string]$sig.SignerCertificate.Subject }
} catch { $sigStatus = "error: $($_.Exception.Message)" }
$kitArgs = @('-RepoDir', $RepoDir, '-OutDir', 'C:\kiro-test\w2', '-InstallerPath', $exe)
$signerArgs = @()
if (($sigStatus -eq 'Valid') -and $signer.StartsWith($SignerPin, [System.StringComparison]::Ordinal)) {
  Check 'WC.signature-gate' 'PASS' "Authenticode status Valid and the signer subject starts with [$SignerPin]; the kit runs the installer"
  # The kit ignores double quotes in this comparison; without them the value survives the command line.
  $signerArgs = @('-ExpectedSignerSubject', ($signer -replace '"', ''))
  $kitArgs += @('-Install') + $signerArgs
} else {
  Check 'WC.signature-gate' 'FAIL' "Authenticode status is $sigStatus and the signer subject is [$signer]; expected Valid and a subject that starts with [$SignerPin]. The installer is NOT run (the kit still records W2.2)"
}
# Optional: replace the kit's default installer switches (for example without /MERGETASKS=!runcode,
# to see the installer start Kiro).
if ($env:KIRO_WC_INSTALLER_ARGS) {
  $kitArgs += @('-InstallerArgs', $env:KIRO_WC_INSTALLER_ARGS)
  [Console]::Out.WriteLine("NOTE WC installer switches from KIRO_WC_INSTALLER_ARGS: $($env:KIRO_WC_INSTALLER_ARGS)")
}
$kitArgs += @('-InstallPolicy', '-Wrappers', '-TamperTest')

# --- The kit. Output is streamed; with a prefix its lines are shown but not read as CHECK lines.
function Invoke-Kit([string]$Shell, [string[]]$Arguments, [string]$Prefix) {
  $argv = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $kit) + $Arguments
  $lines = New-Object System.Collections.Generic.List[string]
  & $Shell @argv 2>&1 | ForEach-Object { $l = "$_"; [Console]::Out.WriteLine($Prefix + $l); $lines.Add($l) }
  $rc = $LASTEXITCODE
  if ($null -eq $rc) { $rc = -1 }
  return @{ rc = $rc; lines = $lines.ToArray() }
}
# PASS detail, or a text starting with "FAIL:": did the kit end with its PHASE line and a matching exit code?
function Get-KitVerdict($Run, [string]$Phase) {
  $fails = @($Run.lines | Where-Object { $_ -cmatch '^CHECK \S+ FAIL( |$)' }).Count
  if (-not $Phase) { return "FAIL: the kit did not finish (no PHASE W2 RESULT line); exit=$($Run.rc)" }
  if (($Run.rc -eq 0 -and $fails -eq 0) -or ($Run.rc -eq 1 -and $fails -gt 0)) { return "exit=$($Run.rc); $Phase" }
  return "FAIL: exit code $($Run.rc) does not match $fails FAIL line(s); $Phase"
}

$run = Invoke-Kit 'powershell.exe' $kitArgs ''
$kitStatus = @{}; $kitPhase = ''
foreach ($l in $run.lines) {
  if ($l -cmatch '^CHECK (\S+) (PASS|FAIL|SKIP|INFO)( |$)') {
    $kitStatus[$Matches[1]] = $Matches[2]
    Add-Count $Matches[2]
  } elseif ($l -cmatch '^PHASE W2 RESULT ') { $kitPhase = $l }
}
# The kit's own FAIL lines are counted above; WC.kit fails only when the kit itself broke.
$verdict = Get-KitVerdict $run $kitPhase
if ($verdict -like 'FAIL:*') { Check 'WC.kit' 'FAIL' $verdict.Substring(6) } else { Check 'WC.kit' 'PASS' $verdict }

# --- The read-only inventory again under PowerShell 7 (the "windows" stage installs it)
$pwsh = 'C:\Program Files\PowerShell\7\pwsh.exe'
if (Test-Path -LiteralPath $pwsh -PathType Leaf) {
  $pwshVersion = ((& $pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()') | Out-String).Trim()
  # The same signer check as in the first run, so that W2.2.signer ends the same way in both.
  $run7 = Invoke-Kit $pwsh (@('-RepoDir', $RepoDir, '-OutDir', 'C:\kiro-test\w2-pwsh7', '-InstallerPath', $exe) + $signerArgs) 'PWSH7 '
  $phase7 = ''; $diff = @()
  foreach ($l in $run7.lines) {
    if ($l -cmatch '^CHECK (\S+) (PASS|FAIL|INFO)( |$)') {
      $id = $Matches[1]; $st = $Matches[2]
      # A check that ran in both editions must end the same way.
      if ($kitStatus.ContainsKey($id) -and $kitStatus[$id] -cne 'SKIP' -and $kitStatus[$id] -cne $st) { $diff += "${id}: $($kitStatus[$id]) under 5.1, $st under 7" }
    } elseif ($l -cmatch '^PHASE W2 RESULT ') { $phase7 = $l }
  }
  $verdict = Get-KitVerdict $run7 $phase7
  if ($verdict -like 'FAIL:*') {
    Check 'WC.kit-pwsh7' 'FAIL' "PowerShell $pwshVersion; $($verdict.Substring(6))"
  } elseif ($diff.Count -gt 0) {
    Check 'WC.kit-pwsh7' 'FAIL' "PowerShell $pwshVersion; results differ from Windows PowerShell 5.1: $($diff -join '; ')"
  } else {
    Check 'WC.kit-pwsh7' 'PASS' "PowerShell $pwshVersion; same results as Windows PowerShell 5.1 for the checks run in both; $verdict"
  }
} else {
  Check 'WC.kit-pwsh7' 'SKIP' "no PowerShell 7 at $pwsh (the windows stage installs it)"
}

# --- Two facts the kit does not collect: the install folder content and the uninstall command
function Get-KiroUninstallEntries {
  $found = @()
  foreach ($view in 'Registry64', 'Registry32') {
    $base = $null
    try {
      $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', $view)
      $root = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
      if ($root) {
        foreach ($name in $root.GetSubKeyNames()) {
          $k = $root.OpenSubKey($name)
          if (-not $k) { continue }
          $dn = "$($k.GetValue('DisplayName'))"
          if ($dn -like 'Kiro*') { $found += @{ view = $view; key = $name; location = "$($k.GetValue('InstallLocation'))"; uninstall = "$($k.GetValue('UninstallString'))".Trim() } }
          $k.Dispose()
        }
        $root.Dispose()
      }
    } catch { } finally { if ($base) { $base.Dispose() } }
  }
  return $found
}
$entries = @(Get-KiroUninstallEntries)
$folder = ''
foreach ($e in $entries) { if (-not $folder -and $e.location) { $folder = $e.location.TrimEnd('\') } }
if (-not $folder) { $folder = 'C:\Program Files\Kiro' }
if (Test-Path -LiteralPath $folder -PathType Container) {
  $names = @(Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { if ($_.PSIsContainer) { $_.Name + '\' } else { $_.Name } })
  $more = ''
  if ($names.Count -gt 40) { $more = " ... (+$($names.Count - 40) more)" }
  Check 'WC.install-folder-entries' 'INFO' "${folder}: $($names.Count) top-level entries: $(@($names | Select-Object -First 40) -join ', ')$more"
} else {
  Check 'WC.install-folder-entries' 'SKIP' "install folder not found: $folder"
}

$kitReported = @($run.lines | Where-Object { $_ -cmatch '^CHECK W2\.1\.uninstall-entry(:\S+)? INFO( |$)' }).Count -gt 0
$withCommand = @($entries | Where-Object { $_.uninstall })
$switches = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
if (-not $kitReported -or $withCommand.Count -eq 0) {
  Check 'WC.uninstall-command' 'SKIP' 'the kit reported no Uninstall entry, or the entry has no UninstallString'
  $withCommand = @()
}
foreach ($e in $withCommand) {
  $tag = 'hklm64'; $viewText = '64-bit registry view'
  if ($e.view -eq 'Registry32') { $tag = 'hklm32'; $viewText = '32-bit registry view (WOW6432Node)' }
  $unExe = ''
  if ($e.uninstall -match '^"([^"]+)"') { $unExe = $Matches[1] } elseif (Test-Path -LiteralPath $e.uninstall -PathType Leaf -ErrorAction SilentlyContinue) { $unExe = $e.uninstall }
  Check "WC.uninstall-command:$tag" 'INFO' "$($e.uninstall) $switches - UninstallString from the $viewText plus Inno Setup switches that Kiro does not document (verify)"
  if ($env:KIRO_WC_UNINSTALL -ne '1') {
    Check "WC.uninstall:$tag" 'SKIP' 'recorded only, not run: KIRO_WC_UNINSTALL is not 1 (operator machine: IT_WC_UNINSTALL=1)'
    continue
  }
  Stop-KiroProcesses "before-uninstall-$tag"
  # The silent switches belong to Inno Setup; another uninstaller could wait for input.
  if (-not $unExe -or -not (Test-Path -LiteralPath $unExe -PathType Leaf) -or ((Split-Path -Leaf $unExe) -notmatch '^unins\d{3}\.exe$')) {
    Check "WC.uninstall:$tag" 'FAIL' 'not run: the UninstallString is not an existing Inno Setup uninstaller (unins<nnn>.exe)'
    continue
  }
  $appDir = Split-Path -Parent $unExe
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $unExe; $psi.Arguments = $switches; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $p = $null
  try { $p = [System.Diagnostics.Process]::Start($psi) } catch { }
  if (-not $p) { Check "WC.uninstall:$tag" 'FAIL' "could not start $unExe"; continue }
  if (-not $p.WaitForExit(600000)) {
    try { $p.Kill() } catch { }
    Check "WC.uninstall:$tag" 'FAIL' "no exit within 10 minutes; process stopped: $unExe $switches"
    continue
  }
  $sw.Stop()
  if ($p.ExitCode -eq 0) { Check "WC.uninstall:$tag" 'PASS' "exit=0 after $([int]$sw.Elapsed.TotalSeconds) s: $unExe $switches" } else { Check "WC.uninstall:$tag" 'FAIL' "exit=$($p.ExitCode) after $([int]$sw.Elapsed.TotalSeconds) s: $unExe $switches" }
  # An Inno Setup uninstaller removes the files from a temporary copy; wait up to a minute.
  $folderGone = $false
  foreach ($n in 1..30) {
    if (-not (Test-Path -LiteralPath $appDir)) { $folderGone = $true; break }
    Start-Sleep -Seconds 2
  }
  $entryGone = (@(Get-KiroUninstallEntries | Where-Object { $_.view -eq $e.view -and $_.key -eq $e.key }).Count -eq 0)
  $left = ''
  if (-not $folderGone) { $left = '; left in the folder: ' + (@(Get-ChildItem -LiteralPath $appDir -Force -ErrorAction SilentlyContinue | Select-Object -First 10 | ForEach-Object { $_.Name }) -join ', ') }
  $detail = "Uninstall entry gone=$entryGone; install folder $appDir gone=$folderGone$left"
  if ($entryGone -and $folderGone) { Check "WC.uninstall-leftovers:$tag" 'PASS' $detail } else { Check "WC.uninstall-leftovers:$tag" 'FAIL' $detail }
}

Finish
