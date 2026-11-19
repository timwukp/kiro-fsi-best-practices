<#
Remediate-KiroPolicy.ps1 - Intune REMEDIATIONS remediation script for the Kiro admin policy.

Upload as the remediation script of the Remediations package whose detection script is
Detect-KiroPolicy.ps1; use the same settings (logged-on credentials = No, 64-bit PowerShell = Yes)
and the same $Options. Runbook: kiro-docs/intune-deployment.md.

Runs the staged C:\ProgramData\Kiro\deploy\mdm\lockdown-windows.ps1 deploy (no -Check), which
restores the policy, the ACLs and the other configured controls from the staged sources. Exit 0 on
success; exit 1 (remediation failed) on any other result, including a missing staged script, which
only the Win32 app can restore. Prints one line; the full output is written to $LogFile.
#>
# --- Configuration: must match Detect-KiroPolicy.ps1 ------------------------------------------------
$DeployDir = Join-Path $env:ProgramData 'Kiro\deploy'
$Options = @()   # e.g. @('-DeployHooks', '-InstallUser', '-DisableUpdates'); a pin: '-ManifestSha256', '<hex>'. Values must not contain spaces or end with a backslash
# SHA-256 of the policy file in the CURRENT package (the install log and -DryRun print it as sha256=...).
# Leave empty to compare the device only with its own staged copy; set it so that a device still
# holding an older package is reported and the Win32 app installs the new one.
$ExpectedPolicySha256 = ''
$PolicyFile = Join-Path $env:ProgramData 'Kiro\managed-settings.json'
$LogFile = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs\KiroPolicy-Remediate.log'
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
  Write-Summary "FAILED: staged script not found ($Lockdown); reinstall the Kiro policy Win32 app"
  exit 1
}
$r = Invoke-Lockdown @()
if ($r.Code -eq 0 -and (Test-ExpectedPolicy)) {
  Write-Summary "FAILED: $(Test-ExpectedPolicy); the staged sources are an older package, which only the Kiro policy Win32 app can replace"
  exit 1
}
if ($r.Code -eq 0) {
  $n = @($r.Lines | Where-Object { $_ -match '\] (installed|set|replacing|removed)' }).Count
  Write-Summary "REMEDIATED: lockdown-windows.ps1 restored the Kiro controls ($n change(s))"
  exit 0
}
Write-Summary "FAILED: lockdown-windows.ps1 exited $($r.Code): $(Get-FirstLine $r.Lines 'ERROR')"
exit 1
