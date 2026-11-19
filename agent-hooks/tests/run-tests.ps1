<#
run-tests.ps1 - regression tests for the Windows PowerShell guards in agent-hooks/windows/.

  powershell.exe -NoProfile -ExecutionPolicy Bypass -File agent-hooks\tests\run-tests.ps1
  pwsh         -NoProfile -ExecutionPolicy Bypass -File agent-hooks/tests/run-tests.ps1

Runs on Windows PowerShell 5.1 AND PowerShell 7. No admin, no network, never touches
the real profile. Each guard runs as a SEPARATE process using the same host as this
runner, fed the hook event JSON on stdin (UTF-8, no BOM). The commands in the fixtures
are passed as JSON text only; nothing from the fixtures is executed.

Fixtures (tab-separated) in agent-hooks/tests/fixtures/:
  git-fs-cases.tsv  : expected_exit  hook  command  [known_gap]   (shared with the bash guards)
  windows-cases.tsv : same format, Windows PowerShell / cmd forms
  pii-cases.tsv     : expected_exit  description  tool_input-JSON  (__TOKEN__ placeholders expanded here)
Expected exit codes are exact: 2 = blocked, 0 = allowed.

Cases that a TSV row cannot hold are built in this file: multi-line commands
(line continuations), commands with non-ASCII spaces, dashes and quotes (this
file and the fixtures stay pure ASCII), and multi-line pii-guard payloads
(pii-cases.tsv is shared with the bash runner).

Output ends with exactly:  RESULT: PASS=<n> FAIL=<n> KNOWN_GAP=<n>
and the script exits 1 when FAIL > 0, else 0.
#>
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$agentHooks = Split-Path -Parent $here
$win = Join-Path $agentHooks 'windows'
$fix = Join-Path $here 'fixtures'
$hostExe = (Get-Process -Id $PID).Path

$script:pass = 0
$script:fail = 0
$script:gap = 0

function Note-Pass { $script:pass++ }
function Note-Fail([string]$Desc, $Expected, $Actual) {
  $script:fail++
  Write-Output "FAIL: $Desc (expected $Expected, got $Actual)"
}

$utf8NoBom = New-Object System.Text.UTF8Encoding $false

function Invoke-Hook([string]$HookPath, [string]$StdinText) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $hostExe
  $psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $HookPath + '"'
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $proc = New-Object System.Diagnostics.Process
  $proc.StartInfo = $psi
  [void]$proc.Start()
  # Read both streams asynchronously so a full pipe never deadlocks the child.
  $outTask = $proc.StandardOutput.ReadToEndAsync()
  $errTask = $proc.StandardError.ReadToEndAsync()
  $bytes = $utf8NoBom.GetBytes($StdinText)
  if ($bytes.Length -gt 0) { $proc.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length) }
  $proc.StandardInput.BaseStream.Flush()
  $proc.StandardInput.Close()
  if (-not $proc.WaitForExit(30000)) {
    try { $proc.Kill() } catch { }
    return @{ rc = 124; out = ''; err = 'timeout' }
  }
  $out = $outTask.GetAwaiter().GetResult()
  $err = $errTask.GetAwaiter().GetResult()
  return @{ rc = $proc.ExitCode; out = $out; err = $err }
}

function New-ShellEvent([string]$Cmd) {
  $o = [ordered]@{
    hook_event_name = 'preToolUse'
    cwd             = 'C:\repo'
    session_id      = 'test'
    tool_name       = 'execute_pwsh'
    tool_input      = [ordered]@{ command = $Cmd }
  }
  return ($o | ConvertTo-Json -Compress -Depth 10)
}

function New-PiiEvent($ToolInput) {
  $o = [ordered]@{
    hook_event_name = 'preToolUse'
    cwd             = 'C:\repo'
    session_id      = 'test'
    tool_name       = 'fs_write'
    tool_input      = $ToolInput
  }
  return ($o | ConvertTo-Json -Compress -Depth 10)
}

# Run one shell-command fixture row against the named guard.
function Test-ShellRow([int]$Expected, [string]$Hook, [string]$Cmd) {
  $hookPath = Join-Path $win ($Hook + '.ps1')
  $r = Invoke-Hook $hookPath (New-ShellEvent $Cmd)
  $desc = "${Hook}: $Cmd"
  $ok = $true
  if ($r.rc -ne $Expected) { Note-Fail $desc $Expected $r.rc; $ok = $false }
  if ($r.out.Trim() -ne '') { Note-Fail "$desc [stdout must be empty]" '' $r.out.Trim(); $ok = $false }
  if (($Expected -eq 2) -and ($r.err -notmatch 'BLOCKED')) { Note-Fail "$desc [stderr must contain BLOCKED]" 'BLOCKED' $r.err.Trim(); $ok = $false }
  if ($ok) { Note-Pass }
}

function Invoke-TsvShellCases([string]$Path) {
  foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
    if (($line -eq '') -or $line.StartsWith('#')) { continue }
    $cols = $line -split "`t"
    if ($cols.Count -lt 3) { continue }
    $expected = $cols[0]
    $hook = $cols[1]
    $cmd = $cols[2]
    $maybeGap = ''
    if ($cols.Count -ge 4) { $maybeGap = $cols[3] }
    if ($maybeGap -eq 'known_gap') { $script:gap++; continue }
    Test-ShellRow ([int]$expected) $hook $cmd
  }
}

Write-Output '== git-fs-cases.tsv (shared with the bash guards)'
Invoke-TsvShellCases (Join-Path $fix 'git-fs-cases.tsv')

Write-Output '== windows-cases.tsv (PowerShell / cmd forms)'
Invoke-TsvShellCases (Join-Path $fix 'windows-cases.tsv')

Write-Output '== multi-line and Unicode shell cases (built here)'
$bt = [string][char]96
$lf = "`n"
$crlf = "`r`n"
$nbsp = [string][char]0x00A0
$formFeed = [string][char]12
$enDash = [string][char]0x2013
$lsq = [string][char]0x2018
$rsq = [string][char]0x2019
$ldq = [string][char]0x201C
$rdq = [string][char]0x201D
$builtCases = @(
  # Line continuations: PowerShell backtick, cmd caret, sh backslash (each before a newline).
  @{ e = 2; h = 'git-guard'; c = ('git push ' + $bt + $lf + '--force origin feature') },
  @{ e = 2; h = 'git-guard'; c = ('git push ' + $bt + $crlf + '  --force origin feature') },
  @{ e = 2; h = 'git-guard'; c = ('git push ^' + $lf + '--force origin feature') },
  @{ e = 2; h = 'git-guard'; c = ('git push \' + $lf + '--force origin feature') },
  # A path that ends in a backslash before a real newline must not hide the next command.
  @{ e = 2; h = 'git-guard'; c = ('cd C:\repo\' + $lf + 'git push --force origin x') },
  @{ e = 0; h = 'git-guard'; c = ('git push ' + $bt + $lf + '-u origin feature/x') },
  @{ e = 0; h = 'git-guard'; c = ('git status' + $lf + 'git log --oneline -5') },
  @{ e = 2; h = 'destructive-fs-guard'; c = ('Remove-Item ' + $bt + $lf + '  -Recurse -Force ' + $bt + $lf + '  C:\Users') },
  @{ e = 2; h = 'destructive-fs-guard'; c = ('rd /s /q ^' + $lf + 'C:\Users') },
  @{ e = 2; h = 'destructive-fs-guard'; c = ('rm -rf \' + $lf + '/') },
  @{ e = 0; h = 'destructive-fs-guard'; c = ('Remove-Item ' + $bt + $lf + '  -Recurse -Force ' + $bt + $lf + '  .\build') },
  # Spaces, dashes and quotes that PowerShell accepts besides the ASCII ones.
  @{ e = 2; h = 'destructive-fs-guard'; c = ('Remove-Item' + $nbsp + '-Recurse' + $nbsp + 'C:\Users') },
  @{ e = 2; h = 'destructive-fs-guard'; c = ('Remove-Item' + $formFeed + '-Recurse' + $formFeed + 'C:\Users') },
  @{ e = 2; h = 'destructive-fs-guard'; c = ('Remove-Item ' + $enDash + 'Recurse C:\Users') },
  @{ e = 2; h = 'destructive-fs-guard'; c = ('Remove-Item -Recurse ' + $lsq + 'C:\Users' + $rsq) },
  @{ e = 2; h = 'destructive-fs-guard'; c = ('Remove-Item -Recurse -Force ' + $ldq + '.git' + $rdq) },
  @{ e = 0; h = 'destructive-fs-guard'; c = ('Remove-Item ' + $enDash + 'Recurse ' + $ldq + '.\build' + $rdq) },
  @{ e = 2; h = 'git-guard'; c = ('git push ' + $lsq + '--force' + $rsq) },
  @{ e = 0; h = 'git-guard'; c = ('git commit -m ' + $ldq + 'fix: typo' + $rdq) }
)
foreach ($tc in $builtCases) { Test-ShellRow ([int]$tc.e) ([string]$tc.h) ([string]$tc.c) }

Write-Output '== second hardening round: multi-line and Unicode shell cases (built here)'
$builtCases2 = @(
  # A directory path that ends in a backslash before a real newline is not a line continuation:
  # the next line is a command of its own and its words are not deletion targets.
  @{ e = 0; h = 'destructive-fs-guard'; c = ('Remove-Item -Recurse -Force .\dist\' + $lf + 'git add .') },
  @{ e = 0; h = 'destructive-fs-guard'; c = ('Remove-Item -Recurse -Force .\build\' + $lf + 'cd ..') },
  @{ e = 0; h = 'destructive-fs-guard'; c = ('rd /s /q build\' + $lf + 'cd ..') },
  @{ e = 0; h = 'destructive-fs-guard'; c = ('Remove-Item -Recurse -Force C:\work\app\build\' + $lf + 'Set-Location C:\') },
  @{ e = 0; h = 'destructive-fs-guard'; c = ('Remove-Item -Recurse .\out\' + $lf + 'Copy-Item -Recurse src\* .') },
  @{ e = 0; h = 'git-guard'; c = ('cd C:\repo\' + $lf + 'npm test') },
  @{ e = 0; h = 'destructive-fs-guard'; c = ('cd C:\repo\' + $lf + 'npm test') },
  @{ e = 0; h = 'git-guard'; c = ('cd C:\repo\' + $lf + 'git push origin feature/x') },
  # A continuation written as one (whitespace, backslash, newline) is still joined.
  @{ e = 2; h = 'destructive-fs-guard'; c = ('rm -rf \' + $lf + '  ~') },
  # Escaped quotes in a multi-line wrapper payload and in a multi-line commit message.
  @{ e = 2; h = 'git-guard'; c = ('bash -c "git commit -m \"a b\"' + $lf + 'git push -f"') },
  @{ e = 0; h = 'git-guard'; c = ('git commit -m "line one' + $lf + $lf + 'say \"hi\"; done"') },
  # A powershell switch written with an en dash; typographic quotes around a wrapper payload.
  @{ e = 2; h = 'git-guard'; c = ('powershell ' + $enDash + 'Command "git push -f"') },
  @{ e = 2; h = 'git-guard'; c = ('pwsh ' + $enDash + 'c "git reset --hard"') },
  @{ e = 0; h = 'git-guard'; c = ('powershell ' + $enDash + 'Command "git status"') },
  @{ e = 2; h = 'git-guard'; c = ('bash -c ' + $ldq + 'git push -f' + $rdq) }
)
foreach ($tc in $builtCases2) { Test-ShellRow ([int]$tc.e) ([string]$tc.h) ([string]$tc.c) }

Write-Output '== size bound and time budget: fail closed, and always inside the 5-second hook timeout'
# Runs one hook input, requires one of the allowed exit codes and an answer within 5000 ms
# (process start-up included). A blocked input must still say BLOCKED on STDERR.
function Test-Bounded([string]$Desc, [string]$HookPath, [string]$StdinText, $Allowed) {
  $watch = [System.Diagnostics.Stopwatch]::StartNew()
  $r = Invoke-Hook $HookPath $StdinText
  $elapsed = $watch.ElapsedMilliseconds
  $ok = $true
  if ($Allowed -notcontains $r.rc) { Note-Fail $Desc ($Allowed -join ' or ') $r.rc; $ok = $false }
  if ($elapsed -gt 5000) { Note-Fail "$Desc [must answer inside the 5 s hook timeout]" '<= 5000 ms' "$elapsed ms"; $ok = $false }
  if ($r.out.Trim() -ne '') { Note-Fail "$Desc [stdout must be empty]" '' 'output on stdout'; $ok = $false }
  if (($r.rc -eq 2) -and ($r.err -notmatch 'BLOCKED')) { Note-Fail "$Desc [stderr must contain BLOCKED]" 'BLOCKED' $r.err.Trim(); $ok = $false }
  if ($ok) { Note-Pass }
}
$boundCases = @(
  # Over the 32,767-character command limit: blocked without being analysed.
  @{ d = 'one 100,000-character word'; c = ('echo ' + ('a' * 100000)); a = @(2) },
  @{ d = '100,000 characters of {a,a,a'; c = ('echo {' + ('a,' * 50000)); a = @(2) },
  @{ d = '100,000 characters of pwsh x lines'; c = (('pwsh x' + $lf) * 14300); a = @(2) },
  # Under the limit: analysed. The shapes below used to cost quadratic time.
  @{ d = 'one 30,000-character word'; c = ('echo ' + ('a' * 30000)); a = @(0) },
  @{ d = '30,000 characters of {a,a,a'; c = ('echo {' + ('a,' * 15000)); a = @(0) },
  @{ d = '28,000 characters of pwsh x lines'; c = (('pwsh x' + $lf) * 4000); a = @(0, 2) }
)
foreach ($g in @('git-guard', 'destructive-fs-guard')) {
  $hookPath = Join-Path $win ($g + '.ps1')
  foreach ($tc in $boundCases) { Test-Bounded ("${g}: " + [string]$tc.d) $hookPath (New-ShellEvent ([string]$tc.c)) ($tc.a) }
}
$piiHookPath = Join-Path $win 'pii-guard.ps1'
Test-Bounded 'pii-guard: 93,000 characters of "begin " (linear, allowed)' $piiHookPath (New-PiiEvent ([ordered]@{ content = ('begin ' * 15500) })) @(0)
Test-Bounded 'pii-guard: input over 1,048,576 characters (blocked)' $piiHookPath (New-PiiEvent ([ordered]@{ content = ('lorem ipsum ' * 100000) })) @(2)

Write-Output '== pii-cases.tsv'
$PEM_BEGIN = '-----' + 'BEGIN'
$GH_TOKEN = 'gh' + 'p_' + ('a' * 36)
$AWS_EXAMPLE_SECRET = 'wJalrXUtnFEMI' + 'K7MDENGbPxRfiCY' + 'EXAMPLEKEY'
$piiHook = Join-Path $win 'pii-guard.ps1'
foreach ($line in [System.IO.File]::ReadAllLines((Join-Path $fix 'pii-cases.tsv'))) {
  if (($line -eq '') -or $line.StartsWith('#')) { continue }
  $cols = $line -split "`t"
  if ($cols.Count -lt 3) { continue }
  $expected = [int]$cols[0]
  $desc = $cols[1]
  $json = $cols[2]
  $json = $json.Replace('__PEM_BEGIN__', $PEM_BEGIN).Replace('__GH_TOKEN__', $GH_TOKEN).Replace('__AWS_EXAMPLE_SECRET__', $AWS_EXAMPLE_SECRET)
  try { $ti = $json | ConvertFrom-Json } catch { Note-Fail "pii fixture is not valid JSON: $desc" 'valid JSON' $json; continue }
  $r = Invoke-Hook $piiHook (New-PiiEvent $ti)
  $ok = $true
  if ($r.rc -ne $expected) { Note-Fail "pii-guard: $desc" $expected $r.rc; $ok = $false }
  if ($r.out.Trim() -ne '') { Note-Fail "pii-guard: $desc [stdout must be empty]" '' $r.out.Trim(); $ok = $false }
  if (($expected -eq 2) -and ($r.err -notmatch 'BLOCKED')) { Note-Fail "pii-guard: $desc [stderr must contain BLOCKED]" 'BLOCKED' $r.err.Trim(); $ok = $false }
  if ($ok) { Note-Pass }
}

Write-Output '== pii-guard matches per line, like grep (built here)'
$pwKey = 'pass' + 'word'
$piiBuilt = @(
  @{ e = 0; d = 'YAML secret key followed by a nested block'; t = ('spec:' + $lf + '  tls:' + $lf + '    secret:' + $lf + '      secretName: my-tls-cert' + $lf) },
  @{ e = 0; d = 'YAML password property followed by a nested block (CRLF)'; t = ($pwKey + ':' + $crlf + '  description: The user password' + $crlf) },
  @{ e = 2; d = 'value on the same line still blocks'; t = ('db:' + $lf + '  ' + $pwKey + ': hunter2xyz' + $lf) }
)
foreach ($tc in $piiBuilt) {
  $r = Invoke-Hook $piiHook (New-PiiEvent ([ordered]@{ content = [string]$tc.t }))
  $ok = $true
  if ($r.rc -ne $tc.e) { Note-Fail "pii-guard: $($tc.d)" $tc.e $r.rc; $ok = $false }
  if ($r.out.Trim() -ne '') { Note-Fail "pii-guard: $($tc.d) [stdout must be empty]" '' $r.out.Trim(); $ok = $false }
  if (($tc.e -eq 2) -and ($r.err -notmatch 'BLOCKED')) { Note-Fail "pii-guard: $($tc.d) [stderr must contain BLOCKED]" 'BLOCKED' $r.err.Trim(); $ok = $false }
  if ($ok) { Note-Pass }
}

Write-Output '== fail-closed behaviour (all three guards)'
$allGuards = @('pii-guard', 'git-guard', 'destructive-fs-guard')
foreach ($g in $allGuards) {
  $hookPath = Join-Path $win ($g + '.ps1')
  # The one-element array matters on PowerShell 7, where ConvertFrom-Json unrolls it to the inner object.
  foreach ($bad in @(@{ d = 'invalid JSON'; s = '{not json' }, @{ d = 'empty stdin'; s = '' }, @{ d = 'JSON array'; s = '[1,2]' }, @{ d = 'one-element JSON array'; s = '[{"tool_input":{"command":"git status"}}]' })) {
    $r = Invoke-Hook $hookPath $bad.s
    $ok = $true
    if ($r.rc -ne 2) { Note-Fail "${g}: $($bad.d)" 2 $r.rc; $ok = $false }
    if ($r.out.Trim() -ne '') { Note-Fail "${g}: $($bad.d) [stdout must be empty]" '' $r.out.Trim(); $ok = $false }
    if ($r.err -notmatch 'BLOCKED') { Note-Fail "${g}: $($bad.d) [stderr must contain BLOCKED]" 'BLOCKED' $r.err.Trim(); $ok = $false }
    if ($ok) { Note-Pass }
  }
}

Write-Output '== tool_input that is not an object is rejected by the shell guards'
foreach ($g in @('git-guard', 'destructive-fs-guard')) {
  $hookPath = Join-Path $win ($g + '.ps1')
  foreach ($bad in @(@{ d = 'tool_input is a string'; s = '{"tool_input":"x"}' }, @{ d = 'tool_input is an array'; s = '{"tool_input":["a"]}' }, @{ d = 'tool_input is a number'; s = '{"tool_input":5}' })) {
    $r = Invoke-Hook $hookPath $bad.s
    $ok = $true
    if ($r.rc -ne 2) { Note-Fail "${g}: $($bad.d)" 2 $r.rc; $ok = $false }
    if ($r.out.Trim() -ne '') { Note-Fail "${g}: $($bad.d) [stdout must be empty]" '' $r.out.Trim(); $ok = $false }
    if ($r.err -notmatch 'BLOCKED') { Note-Fail "${g}: $($bad.d) [stderr must contain BLOCKED]" 'BLOCKED' $r.err.Trim(); $ok = $false }
    if ($ok) { Note-Pass }
  }
}

Write-Output '== non-shell tool call is allowed by the shell guards'
$nonShell = '{"hook_event_name":"preToolUse","tool_name":"fs_read","tool_input":{"path":"README.md"}}'
foreach ($g in @('git-guard', 'destructive-fs-guard')) {
  $r = Invoke-Hook (Join-Path $win ($g + '.ps1')) $nonShell
  if (($r.rc -eq 0) -and ($r.out.Trim() -eq '')) { Note-Pass } else { Note-Fail "${g}: non-shell tool" 0 $r.rc }
}

Write-Output '== banking-guards.windows.json'
$cfgPath = Join-Path (Join-Path $agentHooks 'hooks') 'banking-guards.windows.json'
try {
  $cfg = (Get-Content -LiteralPath $cfgPath -Raw) | ConvertFrom-Json
  Note-Pass
  foreach ($h in $cfg.hooks) {
    $cmd = [string]$h.action.command
    $m = [regex]::Match($cmd, '-File\s+(\S+)')
    if ($m.Success) {
      $leaf = Split-Path -Leaf ($m.Groups[1].Value -replace '/', '\')
      if (Test-Path -LiteralPath (Join-Path $win $leaf)) { Note-Pass } else { Note-Fail "config references missing hook $leaf" 'exists' 'missing' }
    } else {
      Note-Fail "config hook command has no -File path" '-File <path>' $cmd
    }
  }
} catch {
  Note-Fail 'banking-guards.windows.json parses' 'valid JSON' $_.Exception.Message
}

Write-Output ''
Write-Output ("RESULT: PASS=$script:pass FAIL=$script:fail KNOWN_GAP=$script:gap")
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
