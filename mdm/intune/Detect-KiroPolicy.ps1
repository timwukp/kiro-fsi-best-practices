<#
Detect-KiroPolicy.ps1 - Intune REMEDIATIONS detection script for the Kiro admin policy.

Upload as the detection script of a Remediations script package, with Remediate-KiroPolicy.ps1 as
the remediation script. Settings: "Run this script using the logged-on credentials" = No (runs as
SYSTEM); "Run script in 64-bit PowerShell" = Yes. Remediations needs Windows Enterprise E3/E5,
Education A3/A5 or Windows VDA per user; without that licence use Detect-KiroPolicy-Win32.ps1 as
the Win32 app detection script instead. Runbook: kiro-docs/intune-deployment.md.

Runs the copy of lockdown-windows.ps1 that the Win32 app staged in C:\ProgramData\Kiro\deploy
(-StageSources) with -Check, and maps its exit code to the Remediations convention, in which only
exit 1 means "issue found" and runs the remediation script:
  0 compliant (and, when $ExpectedPolicySha256 is set, the policy of
    the current package is the one deployed)                       -> exit 0
  3 drift, 2 source missing or refused, 1 error, any other code,
  or the staged script is missing                                 -> exit 1
Prints one line (Remediations keeps at most 2,048 characters of output); the full -Check output is
written to $LogFile when its folder exists.
#>
# --- Configuration: the same switches as the Win32 app install command, without -StageSources ---
$DeployDir = Join-Path $env:ProgramData 'Kiro\deploy'
$Options = @()   # e.g. @('-DeployHooks', '-InstallUser', '-DisableUpdates'); a pin: '-ManifestSha256', '<hex>'. Values must not contain spaces or end with a backslash
# SHA-256 of the policy file in the CURRENT package (the install log and -DryRun print it as sha256=...).
# Leave empty to compare the device only with its own staged copy; set it so that a device still
# holding an older package is reported and the Win32 app installs the new one.
$ExpectedPolicySha256 = ''
$PolicyFile = Join-Path $env:ProgramData 'Kiro\managed-settings.json'
$LogFile = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs\KiroPolicy-Detect.log'
# -------------------------------------------------------------------------------------------------

$ErrorActionPreference = 'Continue'
$Lockdown = Join-Path $DeployDir 'mdm\lockdown-windows.ps1'

# From a 32-bit host, System32 is redirected to the 32-bit PowerShell; Sysnative reaches the 64-bit one.
function Get-WindowsPowerShell {
  if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    return (Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe')
  }
  return (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
}

function Invoke-Lockdown([string[]]$Mode) {
  $argv = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $Lockdown) + $Mode + $Options
  $lines = @(& (Get-WindowsPowerShell) @argv 2>&1 | ForEach-Object { "$_" })
  $code = $LASTEXITCODE
  if ($null -eq $code) { $code = 1 }
  # Appended, so the record of a drift is not erased by the next clean run. At 512 KB the file is
  # kept as <name>.1 and a new one is started.
  try {
    if (Test-Path -LiteralPath (Split-Path -Parent $LogFile) -PathType Container) {
      if ((Test-Path -LiteralPath $LogFile -PathType Leaf) -and ((Get-Item -LiteralPath $LogFile).Length -gt 524288)) { Move-Item -LiteralPath $LogFile -Destination "$LogFile.1" -Force }
      [System.IO.File]::AppendAllLines($LogFile, [string[]](@("$(Get-Date -Format o) $($Mode -join ' ') exit=$code") + $lines))
    }
  } catch { }
  return @{ Code = $code; Lines = $lines }
}

# '' when no expected hash is configured or the deployed policy has it; otherwise the reason.
function Test-ExpectedPolicy {
  if (-not $ExpectedPolicySha256) { return '' }
  $have = ''
  try { $have = (Get-FileHash -Algorithm SHA256 -LiteralPath $PolicyFile -ErrorAction Stop).Hash.ToLowerInvariant() } catch { }
  if ($have -eq $ExpectedPolicySha256.Trim().ToLowerInvariant()) { return '' }
  return "the deployed policy is not the version of the current package (sha256 $have, expected $($ExpectedPolicySha256.Trim().ToLowerInvariant()))"
}

function Get-FirstLine([string[]]$Lines, [string]$Tag) {
  foreach ($l in $Lines) { if ($l -match "\] ${Tag}: (.*)$") { return $Matches[1] } }
  return '(no detail)'
}

function Write-Summary([string]$Text) {
  $t = ($Text -replace '[\r\n]+', ' ').Trim()
  if ($t.Length -gt 2000) { $t = $t.Substring(0, 2000) }
  Write-Output $t
}

if (-not (Test-Path -LiteralPath $Lockdown -PathType Leaf)) {
  Write-Summary "NON-COMPLIANT: staged script not found ($Lockdown); install or repair the Kiro policy Win32 app"
  exit 1
}
$r = Invoke-Lockdown @('-Check')
if ($r.Code -eq 0) {
  $stale = Test-ExpectedPolicy
  if ($stale) {
    Write-Summary "NON-COMPLIANT: $stale; the Kiro policy Win32 app has not installed the current package on this device"
    exit 1
  }
  Write-Summary 'COMPLIANT: the deployed Kiro controls match the staged sources'
  exit 0
}
if ($r.Code -eq 3) {
  $n = @($r.Lines | Where-Object { $_ -match '\] DRIFT: ' }).Count
  Write-Summary "NON-COMPLIANT: drift in $n item(s); first: $(Get-FirstLine $r.Lines 'DRIFT')"
} else {
  Write-Summary "NON-COMPLIANT: lockdown-windows.ps1 -Check exited $($r.Code): $(Get-FirstLine $r.Lines 'ERROR')"
}
exit 1
