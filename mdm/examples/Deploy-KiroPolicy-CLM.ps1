# Deploy-KiroPolicy-CLM.ps1 - example script for the policy step (policy file and its ACL) that uses no .NET types, no Add-Type and no
# New-Object, so that it also runs when PowerShell is in Constrained Language Mode (App Control / AppLocker script enforcement).
# Not part of the reference deployment; see README.md in this folder.
# Package: this script and managed-settings.json (UTF-8 without BOM, validated before packaging).
# Install command: %SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File Deploy-KiroPolicy-CLM.ps1
# Exit codes: 0 ok | 2 packaged file invalid | 4 write or ACL error | 5 verification failed

# Relaunch in 64-bit PowerShell when started from a 32-bit host (PROCESSOR_ARCHITEW6432 exists only in a 32-bit process on 64-bit Windows).
if ($env:PROCESSOR_ARCHITEW6432) {
  & (Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
  exit $LASTEXITCODE
}

$ErrorActionPreference = 'Stop'
$Log   = 'C:\Windows\Temp\kiro-policy-deploy.log'
$Src   = Join-Path $PSScriptRoot 'managed-settings.json'
$Dir   = 'C:\ProgramData\Kiro'
$Dest  = Join-Path $Dir 'managed-settings.json'
$Users = '*S-1-5-32-545'                            # BUILTIN\Users (locale-independent SID)
$Deny  = "$($Users):(DE,DC,WD,AD,WA,WEA)"
$code  = 0
$relock = $false

function Log([string]$m) { Add-Content -LiteralPath $Log -Value "$(Get-Date -Format o) $m" }
function Invoke-Icacls {
  $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try { $out = & icacls.exe @args 2>&1; $rc = $LASTEXITCODE } finally { $ErrorActionPreference = $old }
  foreach ($l in $out) { Log "icacls $($args -join ' '): $l" }
  if ($rc -ne 0) { throw "icacls $($args -join ' ') failed with exit code $rc" }
}

try {
  Log "start; language mode=$($ExecutionContext.SessionState.LanguageMode); architecture=$($env:PROCESSOR_ARCHITECTURE); account=$($env:USERNAME)"

  # 1. Check the packaged file: no BOM, not UTF-16, parses as JSON.
  $b = @(Get-Content -LiteralPath $Src -Encoding Byte -TotalCount 3)
  if ($b.Count -ge 3 -and $b[0] -eq 239 -and $b[1] -eq 187 -and $b[2] -eq 191) { $code = 2; throw 'packaged file starts with a UTF-8 BOM' }
  if ($b.Count -ge 2 -and (($b[0] -eq 255 -and $b[1] -eq 254) -or ($b[0] -eq 254 -and $b[1] -eq 255))) { $code = 2; throw 'packaged file is UTF-16' }
  try { $null = Get-Content -LiteralPath $Src -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $code = 2; throw "packaged file is not valid JSON: $_" }

  # 2. Remove the Users deny entry first: it also blocks SYSTEM and Administrators.
  if (-not (Test-Path -LiteralPath $Dir -PathType Container)) { New-Item -ItemType Directory -Path $Dir | Out-Null }
  if (Test-Path -LiteralPath $Dest -PathType Leaf) { $relock = $true; Invoke-Icacls $Dest '/remove:d' $Users }

  # 3. Copy the packaged file unchanged (a file copy; no PowerShell text encoding is involved).
  $relock = $true
  Copy-Item -LiteralPath $Src -Destination $Dest -Force

  # 4. Lock the file: owner Administrators, no inheritance, SYSTEM and Administrators Full, Users Read, Users deny.
  Invoke-Icacls $Dest '/setowner' '*S-1-5-32-544'
  Invoke-Icacls $Dest '/inheritance:r'
  Invoke-Icacls $Dest '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' "$($Users):R"
  Invoke-Icacls $Dest '/deny' $Deny
  $relock = $false

  # 5. Verify: same hash as the packaged file, first byte is '{' (123).
  $want = (Get-FileHash -LiteralPath $Src -Algorithm SHA256).Hash
  $have = (Get-FileHash -LiteralPath $Dest -Algorithm SHA256).Hash
  $first = @(Get-Content -LiteralPath $Dest -Encoding Byte -TotalCount 1)[0]
  if ($have -ne $want) { $code = 5; throw "hash mismatch after the write: $have, expected $want" }
  if ($first -ne 123) { $code = 5; throw "first byte is $first, expected 123" }
  Log "deployed $Dest sha256=$have firstbyte=$first"
} catch {
  if ($code -eq 0) { $code = 4 }
  Log "ERROR exit=$code : $_"
  if ($relock -and (Test-Path -LiteralPath $Dest -PathType Leaf)) {
    try { Invoke-Icacls $Dest '/deny' $Deny } catch { Log "could not re-apply the deny entry: $_" }
  }
}
Log "exit $code"
exit $code
