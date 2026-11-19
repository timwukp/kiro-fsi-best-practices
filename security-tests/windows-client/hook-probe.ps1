# hook-probe.ps1 - W2 hook probe for Kiro on Windows. For TEST devices only.
#
# Installed by Invoke-W2Checks.ps1 -InstallProbes as a PreToolUse hook with matcher "*". It records
# THAT a hook was called and from which process chain, so that a tester can see whether Kiro IDE
# and Kiro CLI load global hooks on Windows (W2.7) and which shell runs hook commands (W2.8).
#
# Contract (https://kiro.dev/docs/hooks/):
#   stdin  : JSON {"hook_event_name","cwd","session_id","tool_name","tool_input":{...}}
#   exit 0 : allow
#   exit 2 : block; the one-line reason on STDERR is returned to the model
#
# What it does:
#   - Appends ONE JSON line to %LOCALAPPDATA%\KiroW2\hook-probe.log: UTC time, hook_event_name,
#     tool_name, whether the hook input could be read (input), whether the call was a block test
#     (block_test), the PowerShell edition, version and bitness of this process, and the names of
#     the parent processes (up to 6 levels). No command lines, no user names, and never tool_input
#     (it can hold secrets). Nothing is appended once the log is larger than 5 MB; the exit code
#     is not affected.
#   - Exits 0 always, with one exception: when tool_input.command contains the literal text
#     W2-BLOCK-TEST it writes "w2-probe: BLOCKED - W2 block test" to STDERR and exits 2, so the
#     tester can see whether exit 2 blocks the tool call.
#   - Any internal error: exit 0 (a probe must not block work). Nothing is written to STDOUT.
#
# Targets Windows PowerShell 5.1 and PowerShell 7 (pure ASCII source, no syntax that differs
# between the two).

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

trap { exit 0 }

$Clock = [System.Diagnostics.Stopwatch]::StartNew()
$MaxInputBytes = 4194304
$StdinBudgetMs = 2500    # a hook caller that never closes STDIN must not hang the probe
$ChainBudgetMs = 4000    # measured from the start of the script
$MaxLogBytes = 5242880
$script:InputState = 'ok'

# Reading code of agent-hooks/windows/pii-guard.ps1, with a time limit on every read.
function Read-StdinText {
  $stdin = [Console]::OpenStandardInput()
  $ms = New-Object System.IO.MemoryStream
  $buf = New-Object byte[] 8192
  while ($true) {
    $left = $StdinBudgetMs - [int]$Clock.ElapsedMilliseconds
    if ($left -lt 1) { $script:InputState = 'stdin-timeout'; break }
    $task = $stdin.ReadAsync($buf, 0, $buf.Length)
    if (-not $task.Wait($left)) { $script:InputState = 'stdin-timeout'; break }
    $read = [int]$task.Result
    if ($read -le 0) { break }
    $ms.Write($buf, 0, $read)
    if ($ms.Length -gt $MaxInputBytes) { $script:InputState = 'too-large'; break }
  }
  # On a time-out the bytes read so far are still parsed: a caller that keeps the pipe open has sent the event.
  if ($script:InputState -eq 'too-large') { return '' }
  $bytes = $ms.ToArray()
  if ($bytes.Length -eq 0) { return '' }
  $start = 0
  # Strip a leading UTF-8 BOM if present.
  if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $start = 3 }
  return [System.Text.Encoding]::UTF8.GetString($bytes, $start, $bytes.Length - $start)
}

# Printable ASCII only, at most 120 characters, escaped for a JSON string.
function ConvertTo-JsonText([string]$Value) {
  if ([string]::IsNullOrEmpty($Value)) { return '' }
  $v = $Value
  if ($v.Length -gt 120) { $v = $v.Substring(0, 120) }
  $v = [regex]::Replace($v, '[^\x20-\x7E]', '?')
  return $v.Replace('\', '\\').Replace('"', '\"')
}

# Names of the parent processes, nearest first. Level 0 is this process and is not recorded.
function Get-ParentNames {
  $names = New-Object System.Collections.Generic.List[string]
  $id = [int]$PID
  $childStart = $null
  for ($level = 0; $level -le 6; $level++) {
    if ($Clock.ElapsedMilliseconds -gt $ChainBudgetMs) { $names.Add('(time limit)'); break }
    $p = $null
    try {
      $found = @(Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$id" -Property ProcessId, ParentProcessId, Name, CreationDate -OperationTimeoutSec 3 -ErrorAction Stop)
      if ($found.Count -gt 0) { $p = $found[0] }
    } catch { $names.Add('(lookup failed)'); break }
    if ($null -eq $p) { break }
    if ($level -gt 0) {
      # A "parent" that started after its child is a reused process ID, not the parent.
      if (($null -ne $childStart) -and ($null -ne $p.CreationDate) -and ($p.CreationDate -gt $childStart)) { break }
      $names.Add([string]$p.Name)
    }
    $childStart = $p.CreationDate
    $next = [int]$p.ParentProcessId
    if (($next -le 0) -or ($next -eq $id)) { break }
    $id = $next
  }
  return ,$names
}

# Two probes can finish at the same moment; a locked file is tried again a few times.
function Add-LogLine([string]$Path, [string]$Line) {
  $enc = New-Object System.Text.UTF8Encoding $false
  for ($i = 0; $i -lt 5; $i++) {
    try { [System.IO.File]::AppendAllText($Path, $Line + "`r`n", $enc); return } catch { Start-Sleep -Milliseconds 40 }
  }
}

$exitCode = 0
$eventName = ''
$toolName = ''

# 1. Read the event. Only the two names and the block-test marker are taken from it.
try {
  $raw = Read-StdinText
  # A caller that never closes STDIN ends in 'stdin-timeout'; what it sent is parsed all the same,
  # and the state stays visible in the log.
  $timedOut = ($script:InputState -eq 'stdin-timeout')
  if (($script:InputState -eq 'ok') -or $timedOut) {
    if ([string]::IsNullOrEmpty($raw)) {
      if (-not $timedOut) { $script:InputState = 'empty' }
    } elseif ($raw -notmatch '^\s*\{') {
      if (-not $timedOut) { $script:InputState = 'not-a-json-object' }
    } else {
      $obj = $null
      try { $obj = $raw | ConvertFrom-Json } catch { if (-not $timedOut) { $script:InputState = 'not-json' } }
      if (($null -ne $obj) -and ($obj -is [System.Management.Automation.PSCustomObject])) {
        $eventName = [string]$obj.hook_event_name
        $toolName = [string]$obj.tool_name
        $toolInput = $obj.tool_input
        if (($null -ne $toolInput) -and ($toolInput -is [System.Management.Automation.PSCustomObject])) {
          $command = $toolInput.command
          if (($command -is [string]) -and $command.Contains('W2-BLOCK-TEST')) { $exitCode = 2 }
        }
      } elseif ($script:InputState -eq 'ok') {
        $script:InputState = 'not-a-json-object'
      }
    }
  }
} catch { $script:InputState = 'error' }

# 2. Write the log line. A failure here changes nothing for the tool call.
try {
  if ($env:LOCALAPPDATA) {
    $dir = Join-Path $env:LOCALAPPDATA 'KiroW2'
    $log = Join-Path $dir 'hook-probe.log'
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    $tooBig = $false
    if (Test-Path -LiteralPath $log -PathType Leaf) { $tooBig = ((Get-Item -LiteralPath $log).Length -gt $MaxLogBytes) }
    if (-not $tooBig) {
      $quoted = New-Object System.Collections.Generic.List[string]
      foreach ($n in (Get-ParentNames)) { $quoted.Add('"' + (ConvertTo-JsonText $n) + '"') }
      $blockTest = 'false'
      if ($exitCode -eq 2) { $blockTest = 'true' }
      $edition = [string]$PSVersionTable.PSEdition
      if (-not $edition) { $edition = 'Desktop' }
      $line = '{"time_utc":"' + [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture) + '"' +
        ',"hook_event_name":"' + (ConvertTo-JsonText $eventName) + '"' +
        ',"tool_name":"' + (ConvertTo-JsonText $toolName) + '"' +
        ',"input":"' + $script:InputState + '"' +
        ',"block_test":' + $blockTest +
        ',"ps_edition":"' + (ConvertTo-JsonText $edition) + '"' +
        ',"ps_version":"' + (ConvertTo-JsonText ([string]$PSVersionTable.PSVersion)) + '"' +
        ',"ps_bitness":' + ([IntPtr]::Size * 8) +
        ',"parents":[' + [string]::Join(',', $quoted.ToArray()) + ']}'
      Add-LogLine $log $line
    }
  }
} catch { }

if ($exitCode -eq 2) {
  [Console]::Error.WriteLine('w2-probe: BLOCKED - W2 block test')
  exit 2
}
exit 0
