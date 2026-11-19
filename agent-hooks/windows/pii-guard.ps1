# pii-guard.ps1 - Kiro preToolUse hook (matcher "*" / any tool). PowerShell port of pii-guard.sh.
#
# Blocks a tool call when its input contains secrets or Singapore personal data
# (PDPA; MAS TRM 11.1). Defense in depth only: the primary control is the admin
# policy in managed-settings/ (deny/ask rules enforced by the Kiro client).
#
# Contract (https://kiro.dev/docs/hooks/):
#   stdin  : JSON {"hook_event_name","cwd","session_id","tool_name","tool_input":{...}}
#   exit 0 : allow
#   exit 2 : block; the one-line reason on STDERR is returned to the model
# Every failure path (empty stdin, invalid JSON, JSON that is not an object, input
# over the size limit, matching over the time budget, any internal error) exits 2
# (fail closed). Nothing is written to STDOUT.
#
# Targets Windows PowerShell 5.1 and PowerShell 7 (pure ASCII source, no syntax
# that differs between the two). Patterns mirror pii-guard.sh and match PER LINE
# like grep: IgnoreCase and Multiline make ^/$ line anchors, and no character
# class can match a line feed ([[:space:]] -> [^\S\n], negated classes exclude
# \n), so a match never spans two lines (a YAML key "secret:" followed by a
# nested block is not a finding). Patterns are intentionally broad: a false
# positive costs a retry, a false negative can leak data. Tune them per institution.
#
# Limits (all fail closed):
#   - hook input longer than 1,048,576 characters (1 MiB of text) is blocked.
#     Every pattern runs in linear time; the estimate for the .NET regex
#     interpreter is 0.5-2 microseconds per character for the ten patterns
#     together, so 1 MiB takes about 1-2 seconds, which leaves room for JSON
#     parsing and powershell.exe start-up inside the 5-second hook timeout.
#     Larger content has to be written in parts.
#   - matching that is still running 3,000 ms after the script started is
#     stopped (regex match timeout) and the call is blocked.

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
  [Console]::Error.WriteLine("pii-guard: BLOCKED - $Message")
  exit 2
}

trap { Fail 'internal error in guard (failing closed)' }

# Limits. Every one of them fails closed (exit 2); see the header for the reasoning.
$Clock = [System.Diagnostics.Stopwatch]::StartNew()
$BudgetMs = 3000
$MaxInputBytes = 4194304
$MaxRawChars = 1048576

function Read-StdinText {
  $stdin = [Console]::OpenStandardInput()
  $ms = New-Object System.IO.MemoryStream
  $buf = New-Object byte[] 8192
  while ($true) {
    $read = $stdin.Read($buf, 0, $buf.Length)
    if ($read -le 0) { break }
    $ms.Write($buf, 0, $read)
    # Stop reading once the input is certainly over the size limit (checked by the caller).
    if ($ms.Length -gt $MaxInputBytes) { break }
  }
  $bytes = $ms.ToArray()
  if ($bytes.Length -eq 0) { return '' }
  $start = 0
  # Strip a leading UTF-8 BOM if present.
  if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $start = 3 }
  return [System.Text.Encoding]::UTF8.GetString($bytes, $start, $bytes.Length - $start)
}

$script:PiiValues = New-Object System.Collections.Generic.List[string]

# Collect every scalar value (string, number, boolean) inside tool_input,
# recursing through PSCustomObject properties and arrays. One value per entry.
function Add-Scalars($Node) {
  if ($null -eq $Node) { return }
  if ($Node -is [System.Management.Automation.PSCustomObject]) {
    foreach ($prop in $Node.PSObject.Properties) { Add-Scalars $prop.Value }
    return
  }
  if (($Node -is [System.Collections.IEnumerable]) -and ($Node -isnot [string])) {
    foreach ($item in $Node) { Add-Scalars $item }
    return
  }
  $script:PiiValues.Add([string]$Node)
}

$raw = Read-StdinText
if ([string]::IsNullOrEmpty($raw)) { Fail 'empty hook input (failing closed)' }
if ($raw.Length -gt $MaxRawChars) { Fail 'tool input is too large to inspect in time (failing closed). Write the content in smaller parts.' }

# PowerShell 7 unrolls a one-element JSON array, so the object check is made on the text.
if ($raw -notmatch '^\s*\{') { Fail 'hook input is not a JSON object (failing closed)' }
try { $obj = $raw | ConvertFrom-Json } catch { Fail 'hook input is not a JSON object (failing closed)' }
if (($null -eq $obj) -or ($obj -isnot [System.Management.Automation.PSCustomObject])) {
  Fail 'hook input is not a JSON object (failing closed)'
}

Add-Scalars $obj.tool_input
if ($script:PiiValues.Count -eq 0) { exit 0 }
$payload = $script:PiiValues -join "`n"

# Extended regular expressions from pii-guard.sh, translated to .NET. grep matches
# line by line; here the whole payload is matched once, so every class is written
# so that it cannot match a line feed: [[:space:]] -> [^\S\n], [^a-z0-9] ->
# [^a-z0-9\n], [^0-9] -> [^0-9\n]. A carriage return stays an ordinary whitespace
# character, exactly as grep sees it at the end of a CRLF line. The first pattern
# bounds its repeat ([A-Z ]{0,40}; the longest real label is "ENCRYPTED "), so a
# long run of letters after BEGIN cannot cost quadratic time.
$patterns = @(
  'BEGIN [A-Z ]{0,40}PRIVATE KEY',
  '(^|[^a-z0-9\n])(akia|asia)[a-z0-9]{16}([^a-z0-9\n]|$)',
  'aws_secret_access_key[^a-z0-9\n]{0,4}[:=]',
  '(^|[^a-z0-9\n])gh[pousr]_[a-z0-9]{30,}',
  'github_pat_[a-z0-9_]{20,}',
  'sk-ant-[a-z0-9_-]{20,}',
  '(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)[^a-z0-9\s]{0,2}[^\S\n]*[:=][^\S\n]*[^\s,;}]{6,}',
  '(^|[^a-z0-9\n])[stfgm][0-9]{7}[a-z]([^a-z0-9\n]|$)',
  '(^|[^0-9\n])[0-9]{4}([ .-]?[0-9]{4}){2}[ .-]?[0-9]{1,7}([^0-9\n]|$)',
  '(^|[^0-9\n])3[47][0-9]{2}[ .-]?[0-9]{6}[ .-]?[0-9]{5}([^0-9\n]|$)'
)

$opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline
foreach ($pattern in $patterns) {
  # Each match gets the time that is left of the budget; a timeout blocks.
  $left = $BudgetMs - $Clock.ElapsedMilliseconds
  if ($left -lt 1) { Fail 'tool input could not be inspected in time (failing closed). Write the content in smaller parts.' }
  $hit = $false
  try {
    $hit = [regex]::IsMatch($payload, $pattern, $opts, [TimeSpan]::FromMilliseconds([double]$left))
  } catch {
    Fail 'tool input could not be inspected in time (failing closed). Write the content in smaller parts.'
  }
  if ($hit) {
    Fail 'tool input matches a secret or personal-data pattern (PDPA / MAS TRM 11.1). Remove or mask the value and retry.'
  }
}

exit 0
