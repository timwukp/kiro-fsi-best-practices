<#
Detect-KiroPolicy-Win32.ps1 - Intune WIN32 APP custom detection script for the Kiro policy app.

Use as the detection rule ("Use a custom detection script") of the Win32 app that runs
lockdown-windows.ps1 -StageSources. Settings: "Run script as 32-bit process on 64-bit clients" = No.
Intune treats the app as installed only when the script exits 0 AND writes to STDOUT AND writes
nothing to STDERR. This script therefore reports "installed" only when the staged
lockdown-windows.ps1 -Check passes (exit 0) and, when $ExpectedPolicySha256 is set, the deployed policy
is the one of the current package (set it for every new package version: without it, a device
that still has an older package is reported as installed and never receives the new policy); on drift, a missing source, an error or a missing
staged script it exits 1 with no output, so Intune reinstalls the required app on its next
evaluation, which restores the controls. This is the self-repair path for tenants without the
Remediations licence. Runbook: kiro-docs/intune-deployment.md.
#>
# --- Configuration: the same switches as the Win32 app install command, without -StageSources ---
$DeployDir = Join-Path $env:ProgramData 'Kiro\deploy'
$Options = @()   # e.g. @('-DeployHooks', '-InstallUser', '-DisableUpdates'); a pin: '-ManifestSha256', '<hex>'. Values must not contain spaces or end with a backslash
# SHA-256 of the policy file in the CURRENT package (the install log and -DryRun print it as sha256=...).
# Leave empty to compare the device only with its own staged copy; set it so that a device still
# holding an older package is reported and the Win32 app installs the new one.
$ExpectedPolicySha256 = ''
$PolicyFile = Join-Path $env:ProgramData 'Kiro\managed-settings.json'
$LogFile = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs\KiroPolicy-Win32Detect.log'
# -------------------------------------------------------------------------------------------------

# Anything on STDERR would make Intune report "not installed", even on success.
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
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

try {
  if (Test-Path -LiteralPath $Lockdown -PathType Leaf) {
    $r = Invoke-Lockdown @('-Check')
    if ($r.Code -eq 0 -and -not (Test-ExpectedPolicy)) {
      [Console]::Out.WriteLine('Kiro policy compliant')
      exit 0
    }
  }
} catch { }
exit 1
