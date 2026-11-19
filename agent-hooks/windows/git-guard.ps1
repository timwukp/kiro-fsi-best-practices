# git-guard.ps1 - Kiro preToolUse hook for shell commands (matcher "shell" / execute_pwsh).
# PowerShell port of git-guard.sh.
#
# Blocks git operations that rewrite or delete shared history, or that push
# directly to a protected branch (MAS TRM 6.3 segregation of duties, 7.5 change
# management). Normal commits and feature-branch pushes pass through.
#
# Defense in depth only. Authoritative controls:
#   - managed-settings/ admin deny/ask rules (Kiro splits compound commands);
#   - server-side branch protection / rulesets on the Git host.
#
# Contract (https://kiro.dev/docs/hooks/):
#   stdin  : JSON {"hook_event_name","cwd","session_id","tool_name","tool_input":{"command":...}}
#   exit 0 : allow (also when there is no tool_input.command)
#   exit 2 : block; the one-line reason on STDERR is returned to the model
# Every failure path (empty stdin, invalid JSON, JSON that is not an object, input
# over the size limit, analysis over the time budget, any internal error) exits 2
# (fail closed). Nothing is written to STDOUT. The inspected command is only
# parsed as text; it is never executed.
#
# Targets Windows PowerShell 5.1 and PowerShell 7 (pure ASCII source, no syntax
# that differs between the two). How a command is read:
#   - It is split into simple commands, quote-aware, on ; | || && & newline and
#     on ( ) { } and $( . A single & is a separator (cmd.exe, PowerShell 7
#     background operator, call operator) unless it is part of a redirection
#     such as 2>&1. Git reflog selectors such as stash@{0}, sh brace expansions
#     and parenthesised lists of literals stay with their command.
#   - Each simple command is tokenized quote-aware, so a quoted program path
#     with a space ("C:\Program Files\Git\cmd\git.exe") stays one token; the
#     directory and ".exe" are then stripped from the command token.
#   - Env assignments (NAME=value), PowerShell assignments ($r = ...) and
#     transparent prefixes are skipped.
#   - sh -c, powershell/pwsh -Command (any unambiguous prefix, or positional for
#     powershell.exe), cmd /c and Invoke-Expression / iex are unwrapped and the
#     inner command is inspected the same way, up to 40 levels deep (deeper
#     nesting is blocked).
#   - Several readings are evaluated and ANY reading that blocks, blocks:
#     backticks removed (PowerShell escape) and backticks as separators (bash
#     subshell); line continuations joined (backtick or caret before a newline,
#     backslash before a newline only after whitespace); cmd caret escapes
#     removed; wrappers unwrapped as text; cmd /c "..." with only the first and
#     last quote removed; escaped double quotes (backtick-quote, backslash-quote)
#     removed, because the shell that will run the command is not known.
#
# Limits (all fail closed):
#   - tool_input.command longer than 32,767 characters is blocked. That is the
#     longest command line Windows can start (CreateProcess limit). Estimated
#     cost under Windows PowerShell 5.1 is 20-50 microseconds per quote or
#     separator character and 0.1-0.3 ms per simple command, per reading, and a
#     command usually needs 1-4 readings: about 1 second for a dense
#     32,767-character command, which leaves room for powershell.exe start-up
#     inside the 5-second hook timeout. A longer text cannot be guaranteed.
#   - hook input longer than 262,144 characters is blocked before JSON parsing
#     (a 32,767-character command is at most 196,602 characters when every
#     character is written as a \uXXXX escape).
#   - analysis that is still running 2,500 ms after the script started is
#     stopped and the command is blocked (many readings of a contrived command).
#   No regular expression in this file can take more than linear time.

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
  # The reason can quote a token of the command: keep the message on one line.
  $Message = $Message -replace '[\r\n]+', ' '
  [Console]::Error.WriteLine("git-guard: BLOCKED - $Message. Use a feature branch and a pull request (MAS TRM 6.3 / 7.5).")
  exit 2
}

trap { Fail 'internal error in guard (failing closed)' }

# Limits. Every one of them fails closed (exit 2); see the header for the reasoning.
$Clock = [System.Diagnostics.Stopwatch]::StartNew()
$BudgetMs = 2500
$MaxInputBytes = 4194304
$MaxRawChars = 262144
$MaxCommandChars = 32767
$TooSlow = 'command could not be inspected in time (failing closed)'

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
  if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $start = 3 }
  return [System.Text.Encoding]::UTF8.GetString($bytes, $start, $bytes.Length - $start)
}

# Text-level unwrap of sh/zsh/dash/ksh -c, powershell/pwsh -Command and cmd /c|/k
# wrappers: the wrapper words are removed and the enclosing quote pair of the
# inner command is dropped, so the inner words are parsed again. Every wrapper is
# unwrapped. The search resumes where the last wrapper was found (the text before
# it cannot change), and the repeated groups are bounded, so the cost stays linear.
$WrapperRx = [regex]'(?i)(^|[;&|(){}\s])(?:(?:/usr/bin/|/bin/)?(?:ba|z|da|k)?sh(?:\.exe)?\s+-[A-Za-z]*c\s+|(?:pwsh|powershell)(?:\.exe)?(?:\s+\S+){0,40}?\s+[-/]c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?\s+|cmd(?:\.exe)?(?:\s+/[A-Za-z](?::\S+)?){0,10}?\s+/[ck]\s*)'

function Expand-Wrappers([string]$Text) {
  $guard = 0
  $pos = 0
  while ($true) {
    $m = $WrapperRx.Match($Text, $pos)
    if (-not $m.Success) { break }
    $guard++
    if ($guard -gt 2000) { Fail 'too many nested command wrappers (failing closed)' }
    if ($Clock.ElapsedMilliseconds -gt $BudgetMs) { Fail $TooSlow }
    $pos = $m.Index
    $before = $Text.Substring(0, $m.Index) + $m.Groups[1].Value
    $rest = $Text.Substring($m.Index + $m.Length)
    $inner = $rest
    if (($rest.Length -gt 0) -and (($rest[0] -eq '"') -or ($rest[0] -eq "'"))) {
      $q = $rest[0]
      $end = $rest.IndexOf($q, 1)
      if ($end -ge 0) {
        $inner = $rest.Substring(1, $end - 1) + ' ' + $rest.Substring($end + 1)
      } else {
        $inner = $rest.Substring(1)
      }
    }
    $Text = $before + ' ' + $inner
  }
  return $Text
}

# cmd.exe rule for /c and /k: when the text after the switch starts with a quote
# and holds more quotes, cmd removes only the FIRST and the LAST quote of the line
# (cmd /s /c ""C:\Program Files\Git\cmd\git.exe" push --force"). This rewrites
# such a wrapper to its inner command; it is evaluated as one more reading.
$CmdOuterRx = [regex]'(?i)(^|[;&|(){}\s])cmd(?:\.exe)?(?:\s+/[A-Za-z](?::\S+)?){0,10}?\s+/[ck]\s*"([^"\r\n]*"[^\r\n]*)"'

# Spans copied verbatim by Split-Segments so their brackets are not separators:
# ${name} / ${env:ProgramFiles(x86)} (plain variable names only), %NAME% /
# %ProgramFiles(x86)% and git selectors such as stash@{0} or @{u}.
$VarRe = [regex]'\G(?:\$\{[A-Za-z_][A-Za-z0-9_:]*(?:\([A-Za-z0-9]+\))?\}|%[A-Za-z_][A-Za-z0-9_]*(?:\([A-Za-z0-9]+\))?%|@\{[A-Za-z0-9_.+-]*\})'

# A sh brace expansion such as ./{build,dist} or {1..3}: no whitespace, and a comma
# or "..". It is copied verbatim; a script block { ... } that runs a command with
# arguments contains whitespace and is therefore still split. Runs are bounded.
$BraceRe = [regex]'\G\{[^\s{}"'';&|()]{0,200}(?:,|\.\.)[^\s{}"'';&|()]{0,200}\}'

# A parenthesised list of literals: ('.git', 'build'), @("C:\Users", "D:\x"),
# ($a, $b), ('x'). Its items are arguments of the command in front of it, so the
# list stays in the same simple command (the brackets become spaces). Anything
# else in parentheses - (Join-Path $PWD 'build'), (rm -rf /) - is a command of
# its own and is split off.
$ListItem = '(?:''[^'']{0,2000}''|"[^"]{0,2000}"|\$[A-Za-z_{][^\s,()]{0,200})'
$ListRe = [regex]('\G\(\s*' + $ListItem + '(?:\s*,\s*' + $ListItem + '){0,200}\s*\)')

# Characters at which Split-Segments has to look; everything else is ordinary text.
$SegSpecials = ("'" + '"$%@;|&(){}' + "`n`r").ToCharArray()
$QuoteChars = ("'" + '"').ToCharArray()
# Next quote or whitespace character, for Split-Tokens.
$TokRe = [regex]'[\s"'']'

# True when every quote in the text has a partner (same pairing as Split-Segments).
function Test-QuotesBalanced([string]$s) {
  $len = $s.Length
  $k = 0
  while ($k -lt $len) {
    $next = $s.IndexOfAny($QuoteChars, $k)
    if ($next -lt 0) { return $true }
    $close = $s.IndexOf($s[$next], $next + 1)
    if ($close -lt 0) { return $false }
    $k = $close + 1
  }
  return $true
}

# Split into simple commands, quote-aware, keeping quotes and backslashes.
# Separators outside quotes: ; newline | || && & ( ) { } . An & next to > is a
# redirection (2>&1, &>) and is kept. A quote is closed by the next quote of the
# same kind; a doubled quote ("" or '') therefore keeps the scanner inside the
# string, as in PowerShell. Escaped quotes (backtick or backslash) are handled by
# the caller, which also evaluates the text with them removed. If a quote is left
# open, the text is split again with all quotes removed, so an unbalanced quote
# cannot hide a command.
function Split-Segments([string]$s) {
  $segs = New-Object System.Collections.Generic.List[string]
  $sb = New-Object System.Text.StringBuilder
  $open = $false
  $len = $s.Length
  $k = 0
  while ($k -lt $len) {
    # Jump to the next character that can matter; ordinary text is copied in one piece.
    $next = $s.IndexOfAny($SegSpecials, $k)
    if ($next -lt 0) { [void]$sb.Append($s.Substring($k)); break }
    if ($next -gt $k) { [void]$sb.Append($s.Substring($k, $next - $k)); $k = $next }
    $c = $s[$k]
    if (($c -eq "'") -or ($c -eq '"')) {
      $close = $s.IndexOf($c, $k + 1)
      if ($close -lt 0) { $open = $true; break }
      [void]$sb.Append($s.Substring($k, $close - $k + 1))
      $k = $close + 1
      continue
    }
    if (($c -eq '$') -or ($c -eq '%') -or ($c -eq '@')) {
      $vm = $VarRe.Match($s, $k)
      if ($vm.Success) { [void]$sb.Append($vm.Value); $k += $vm.Length; continue }
    }
    if ($c -eq '{') {
      $bm = $BraceRe.Match($s, $k)
      if ($bm.Success) { [void]$sb.Append($bm.Value); $k += $bm.Length; continue }
    }
    if ($c -eq '(') {
      $lm = $ListRe.Match($s, $k)
      if ($lm.Success) {
        # Drop the @ of @( ... ) and keep the items as arguments.
        if (($sb.Length -gt 0) -and $sb.ToString().EndsWith('@')) { [void]$sb.Remove($sb.Length - 1, 1) }
        [void]$sb.Append(' ')
        [void]$sb.Append($s.Substring($k + 1, $lm.Length - 2))
        [void]$sb.Append(' ')
        $k += $lm.Length
        continue
      }
    }
    $sep = $false
    if (($c -eq ';') -or ($c -eq "`n") -or ($c -eq "`r")) {
      $sep = $true
    } elseif ($c -eq '|') {
      $sep = $true
      if ((($k + 1) -lt $len) -and ($s[$k + 1] -eq '|')) { $k++ }
    } elseif ($c -eq '&') {
      $prevGt = ($k -gt 0) -and ($s[$k - 1] -eq '>')
      $nextGt = (($k + 1) -lt $len) -and ($s[$k + 1] -eq '>')
      if (-not ($prevGt -or $nextGt)) {
        $sep = $true
        if ((($k + 1) -lt $len) -and ($s[$k + 1] -eq '&')) { $k++ }
      }
    } elseif (($c -eq '(') -or ($c -eq ')') -or ($c -eq '{') -or ($c -eq '}')) {
      $sep = $true
    }
    if ($sep) {
      $segs.Add($sb.ToString())
      [void]$sb.Clear()
    } else {
      [void]$sb.Append($c)
    }
    $k++
  }
  if ($open) {
    $again = Split-Segments ($s.Replace('"', '').Replace("'", ''))
    return ,@($again)
  }
  $segs.Add($sb.ToString())
  return ,$segs.ToArray()
}

# Tokenize one simple command, quote-aware. Quotes are removed, backslashes kept,
# so "C:\Program Files\Git\cmd\git.exe" becomes one token. Any Unicode whitespace
# separates tokens, as in the PowerShell tokenizer.
function Split-Tokens([string]$s) {
  $list = New-Object System.Collections.Generic.List[string]
  if ((-not $s.Contains('"')) -and (-not $s.Contains("'"))) {
    # No quotes: plain whitespace split.
    foreach ($word in [regex]::Split($s, '\s+')) { if ($word -ne '') { $list.Add($word) } }
    return ,$list.ToArray()
  }
  $sb = New-Object System.Text.StringBuilder
  $has = $false
  $len = $s.Length
  $k = 0
  while ($k -lt $len) {
    $m = $TokRe.Match($s, $k)
    if (-not $m.Success) { [void]$sb.Append($s.Substring($k)); $has = $true; break }
    if ($m.Index -gt $k) { [void]$sb.Append($s.Substring($k, $m.Index - $k)); $has = $true; $k = $m.Index }
    $ch = $s[$k]
    if (($ch -eq "'") -or ($ch -eq '"')) {
      $has = $true
      $close = $s.IndexOf($ch, $k + 1)
      if ($close -lt 0) { [void]$sb.Append($s.Substring($k + 1)); break }
      [void]$sb.Append($s.Substring($k + 1, $close - $k - 1))
      $k = $close + 1
      continue
    }
    # Whitespace ends the current token.
    if ($has) { $list.Add($sb.ToString()); [void]$sb.Clear(); $has = $false }
    $k++
  }
  if ($has) { $list.Add($sb.ToString()) }
  return ,$list.ToArray()
}

# Last path component of a token (text after the last \ or /). String search, no
# regular expression: a long token without a separator must not cost quadratic time.
$PathSeps = '\/'.ToCharArray()
function Get-Leaf([string]$Tok) {
  $cut = $Tok.LastIndexOfAny($PathSeps)
  if ($cut -ge 0) { return $Tok.Substring($cut + 1) }
  return $Tok
}

# Command name of a token: directory and ".exe" stripped, lower case.
function Get-CommandName([string]$Tok) {
  $name = ([string](Get-Leaf $Tok)).ToLowerInvariant()
  if ($name.EndsWith('.exe')) { $name = $name.Substring(0, $name.Length - 4) }
  return $name
}

# Join tokens $First.. back into command text with single spaces. With $Requote,
# a token that contains whitespace is quoted again so it stays one token (how
# cmd keeps a quoted argument); without it the words are joined as they are
# (how powershell -Command joins its arguments). The caller inspects both.
function Join-Tokens($Tokens, [int]$First, [bool]$Requote) {
  $n = $Tokens.Count
  if ($First -ge $n) { return '' }
  if ($First -eq ($n - 1)) { return [string]$Tokens[$First] }
  $sb = New-Object System.Text.StringBuilder
  for ($j = $First; $j -lt $n; $j++) {
    $t = [string]$Tokens[$j]
    if ($j -gt $First) { [void]$sb.Append(' ') }
    if ($Requote -and ($t -match '\s')) {
      $q = '"'
      if ($t.Contains('"')) { $q = "'" }
      [void]$sb.Append($q); [void]$sb.Append($t); [void]$sb.Append($q)
    } else {
      [void]$sb.Append($t)
    }
  }
  return $sb.ToString()
}

$ShNames = @('sh', 'bash', 'zsh', 'dash', 'ksh')
$IexNames = @('iex', 'invoke-expression')

# When the command ($Name, arguments from $First) is a wrapper that runs command
# text, return that text, otherwise $null.
#   sh/bash/zsh/dash/ksh : the argument after a -c cluster
#   powershell / pwsh    : everything after -Command (any prefix -c .. -command);
#                          the argument after -CommandWithArgs / -cwa; for
#                          powershell.exe also the first positional argument
#                          (its default parameter is -Command); -File and
#                          -EncodedCommand are not inspected
#   cmd                  : everything after /c or /k (also /c"..." without a space)
#   Invoke-Expression/iex: its argument (PowerShell's own eval)
function Get-WrappedCommand($Tokens, [int]$First, [string]$Name, [bool]$Requote) {
  $n = $Tokens.Count
  if ($ShNames -contains $Name) {
    for ($j = $First; $j -lt $n; $j++) {
      $t = [string]$Tokens[$j]
      if (($t -cmatch '^-[A-Za-z]+$') -and $t.Contains('c') -and (($j + 1) -lt $n)) { return [string]$Tokens[$j + 1] }
    }
    return $null
  }
  if (($Name -eq 'powershell') -or ($Name -eq 'pwsh')) {
    $j = $First
    while ($j -lt $n) {
      $t = [string]$Tokens[$j]
      if ($t -match '^[-/]c(o(m(m(a(n(d)?)?)?)?)?)?$') { return (Join-Tokens $Tokens ($j + 1) $Requote) }
      if ($t -match '^[-/](cwa|commandwithargs)$') {
        if (($j + 1) -lt $n) { return [string]$Tokens[$j + 1] }
        return $null
      }
      if ($t -match '^[-/](f|fi|fil|file|e|ec|ea|en[a-z]*)$') { return $null }
      if ($t -match '^[-/]') {
        $j++
        if (($t -match '^[-/](ex|ep|w|inp|if|o|v|config|ps|se|cu)') -and ($j -lt $n) -and ([string]$Tokens[$j] -notmatch '^[-/]')) { $j++ }
        continue
      }
      if ($Name -eq 'powershell') { return (Join-Tokens $Tokens $j $Requote) }
      return $null
    }
    return $null
  }
  if ($Name -eq 'cmd') {
    for ($j = $First; $j -lt $n; $j++) {
      $t = [string]$Tokens[$j]
      if ($t -match '^/[ck]') { return ($t.Substring(2) + ' ' + (Join-Tokens $Tokens ($j + 1) $Requote)) }
      if (-not $t.StartsWith('/')) { return $null }
    }
    return $null
  }
  if ($IexNames -contains $Name) {
    $j = $First
    if (($j -lt $n) -and ([string]$Tokens[$j] -match '^-c(o(m(m(a(n(d)?)?)?)?)?)?$')) { $j++ }
    if ($j -ge $n) { return $null }
    return (Join-Tokens $Tokens $j $Requote)
  }
  return $null
}

# A PowerShell assignment in front of a command: $r = git push, [string]$r = ...,
# $null = Remove-Item ..., $a = $b = ... . It is removed before tokenizing, the
# way NAME=value env assignments are skipped.
$AssignRx = [regex]'^\s*(?:(?:\[[^\]\s]+\]\s*)*\$[A-Za-z_{][^\s=]*\s*[-+*/%]?=\s*)+'

$GitGlobalWithArg = @('-C', '-c', '--git-dir', '--work-tree', '--namespace')
$GitPrefixes = @('env', 'command', 'exec', 'nohup', 'time', 'sudo', '&', 'call', 'then', 'do', 'else', 'elif', '!')

# Inspect one simple command (token array). Returns a block reason or $null.
function Test-GitCommand($Tokens, [int]$Depth) {
  $n = $Tokens.Count
  if ($n -eq 0) { return $null }
  $i = 0
  while (($i -lt $n) -and (($Tokens[$i] -match '^[A-Za-z_][A-Za-z0-9_]*=') -or ($GitPrefixes -contains $Tokens[$i]))) { $i++ }
  if ($i -ge $n) { return $null }
  $cmd = Get-CommandName ([string]$Tokens[$i])
  if ($cmd -ne 'git') {
    # A wrapper: inspect the wrapped text, joined as written and joined with
    # multi-word arguments quoted again.
    $inner = Get-WrappedCommand $Tokens ($i + 1) $cmd $false
    if ($null -eq $inner) { return $null }
    $reason = Test-Text ([string]$inner) ($Depth + 1)
    if ($reason) { return $reason }
    $alt = Get-WrappedCommand $Tokens ($i + 1) $cmd $true
    if (($null -ne $alt) -and ([string]$alt -cne [string]$inner)) { return (Test-Text ([string]$alt) ($Depth + 1)) }
    return $null
  }
  $i++
  while (($i -lt $n) -and ($Tokens[$i].StartsWith('-'))) {
    if ($GitGlobalWithArg -contains $Tokens[$i]) { $i += 2 } else { $i++ }
  }
  if ($i -ge $n) { return $null }
  $op = $Tokens[$i]
  $i++

  switch -CaseSensitive ($op) {
    'push' {
      $pos = 0
      for (; $i -lt $n; $i++) {
        $a = $Tokens[$i]
        if ($a -eq '--') { continue }
        if ($a -match '^--(force|force-with-lease|force-if-includes|mirror|delete|prune)') { return "git push $a" }
        if (($a -match '^-[A-Za-z]+$') -and ($a -cmatch '[fd]')) { return "git push $a" }
        if ($a.StartsWith('-')) { continue }
        $pos++
        if ($pos -eq 1) { continue }
        if ($a.StartsWith('+')) { return "forced refspec $a" }
        if ($a.StartsWith(':')) { return "branch deletion via refspec $a" }
        $dst = $a -replace '^.*:', '' -replace '^refs/heads/', ''
        if (($dst -eq 'main') -or ($dst -eq 'master')) { return "direct push to protected branch $dst" }
      }
    }
    'reset' {
      for (; $i -lt $n; $i++) { if ($Tokens[$i] -eq '--hard') { return 'git reset --hard' } }
    }
    'clean' {
      for (; $i -lt $n; $i++) {
        $a = $Tokens[$i]
        if (($a -eq '--force') -or (($a -match '^-[A-Za-z]+$') -and ($a -cmatch 'f'))) { return "git clean $a" }
      }
    }
    'branch' {
      $del = $false; $frc = $false; $prot = $false
      for (; $i -lt $n; $i++) {
        $a = $Tokens[$i]
        if (($a -match '^-[A-Za-z]+$') -and ($a -cmatch 'D')) { return 'git branch -D' }
        if (($a -eq '-d') -or ($a -eq '--delete')) { $del = $true }
        if (($a -eq '-f') -or ($a -eq '--force')) { $frc = $true }
        if (($a -eq 'main') -or ($a -eq 'master')) { $prot = $true }
      }
      if ($del -and ($frc -or $prot)) { return 'deletion of a protected or unmerged branch' }
    }
    'filter-branch' { return 'git filter-branch (history rewrite)' }
    'filter-repo'   { return 'git filter-repo (history rewrite)' }
    'update-ref' {
      for (; $i -lt $n; $i++) { if (($Tokens[$i] -eq '-d') -or ($Tokens[$i] -eq '--delete')) { return 'git update-ref -d' } }
    }
    'reflog' {
      for (; $i -lt $n; $i++) { if (($Tokens[$i] -eq 'expire') -or ($Tokens[$i] -eq 'delete')) { return "git reflog $($Tokens[$i])" } }
    }
    'gc' {
      for (; $i -lt $n; $i++) { if ($Tokens[$i] -match '^--prune=now') { return 'git gc --prune=now' } }
    }
  }
  return $null
}

# Inspect command text: every simple command, wrappers followed recursively.
# Returns a block reason or $null. The depth bound and the time budget fail closed.
function Test-Text([string]$Text, [int]$Depth) {
  if ($Depth -gt 40) { Fail 'too many nested command wrappers (failing closed)' }
  foreach ($segment in (Split-Segments $Text)) {
    if ($Clock.ElapsedMilliseconds -gt $BudgetMs) { Fail $TooSlow }
    $seg = $AssignRx.Replace($segment, '')
    if ($seg.Trim() -eq '') { continue }
    $toks = Split-Tokens $seg
    $reason = Test-GitCommand $toks $Depth
    if ($reason) { return $reason }
  }
  return $null
}

function Add-Unique($List, [string]$Item) {
  if (-not $List.Contains($Item)) { $List.Add($Item) }
}

$bt = [string][char]96
$Seen = New-Object System.Collections.Generic.List[string]

# Evaluate one spelling of the command in all its readings; any reading that
# blocks, blocks (Fail exits). $Derived marks a spelling made by removing escaped
# quotes: it only counts when its quotes are balanced (otherwise that
# interpretation is not a runnable command, and the spelling as written has
# already been evaluated with the quote-stripped fallback).
function Test-Form([string]$Form, [bool]$Derived) {
  # Line continuations: PowerShell backtick+newline, cmd caret+newline, and sh
  # backslash+newline when whitespace precedes the backslash. The joined forms are
  # ADDED as readings, never substituted, and a path that ends in "\" directly
  # before a newline (cd C:\repo\) is never joined with the next line.
  $bases = New-Object System.Collections.Generic.List[string]
  Add-Unique $bases $Form
  Add-Unique $bases ([regex]::Replace($Form, $bt + '\r?\n', ' '))
  Add-Unique $bases ([regex]::Replace($Form, '\^\r?\n', ''))
  Add-Unique $bases ([regex]::Replace($Form, '(?<=\s)\\\r?\n', ' '))

  # Per base: backticks removed (PowerShell escape), backticks as separators (bash
  # subshell), and cmd caret escapes removed.
  $variants = New-Object System.Collections.Generic.List[string]
  foreach ($b in $bases) {
    Add-Unique $variants ($b.Replace($bt, ''))
    Add-Unique $variants ($b.Replace($bt, "`n"))
    if ($b.Contains('^')) { Add-Unique $variants ($b.Replace($bt, '').Replace('^', '')) }
  }

  foreach ($variant in $variants) {
    if ($Derived -and (-not (Test-QuotesBalanced $variant))) { continue }
    # Reading 1: the text as written (wrappers followed token by token).
    # Reading 2: wrappers unwrapped as text first.
    # Reading 3: cmd /c "..." with only the first and the last quote removed.
    $readings = New-Object System.Collections.Generic.List[string]
    Add-Unique $readings $variant
    Add-Unique $readings ([string](Expand-Wrappers $variant))
    $nested = $CmdOuterRx.Replace($variant, '$1 $2 ')
    if ($nested -cne $variant) { Add-Unique $readings ([string](Expand-Wrappers $nested)) }
    foreach ($reading in $readings) {
      if ($Seen.Contains($reading)) { continue }
      $Seen.Add($reading)
      $reason = Test-Text $reading 0
      if ($reason) { Fail $reason }
    }
  }
}

$raw = Read-StdinText
if ([string]::IsNullOrEmpty($raw)) { Fail 'empty hook input (failing closed)' }
if ($raw.Length -gt $MaxRawChars) { Fail 'hook input is too large to inspect in time (failing closed)' }
# PowerShell 7 unrolls a one-element JSON array, so the object check is made on the text.
if ($raw -notmatch '^\s*\{') { Fail 'hook input is not a JSON object (failing closed)' }
try { $obj = $raw | ConvertFrom-Json } catch { Fail 'hook input is not a JSON object (failing closed)' }
if (($null -eq $obj) -or ($obj -isnot [System.Management.Automation.PSCustomObject])) {
  Fail 'hook input is not a JSON object (failing closed)'
}

$ti = $obj.tool_input
if (($null -ne $ti) -and ($ti -isnot [System.Management.Automation.PSCustomObject])) {
  Fail 'tool_input is not a JSON object (failing closed)'
}
$command = $ti.command
if ($null -eq $command) { exit 0 }
$command = [string]$command
if ([string]::IsNullOrEmpty($command)) { exit 0 }
if ($command.Length -gt $MaxCommandChars) {
  Fail "command is longer than $MaxCommandChars characters and cannot be inspected in time (failing closed)"
}

# Typographic dashes and quotes are parameter dashes and quotes for PowerShell.
# Built from code points: the file stays ASCII.
$dashRe = '[' + [char]0x2013 + [char]0x2014 + [char]0x2015 + ']'
$sqRe = '[' + [char]0x2018 + [char]0x2019 + [char]0x201A + [char]0x201B + ']'
$dqRe = '[' + [char]0x201C + [char]0x201D + [char]0x201E + ']'
$command = [regex]::Replace($command, $dashRe, '-')
$command = [regex]::Replace($command, $sqRe, "'")
$command = [regex]::Replace($command, $dqRe, '"')

# The command as written.
Test-Form $command $false

# Escaped quotes. Which shell reads the command is not known, so each escape
# convention is evaluated as one more spelling, with the escaped quote removed
# (it is a literal character, not a string delimiter):
#   backtick + "       PowerShell, inside a double-quoted string
#   backslash + " or ' sh (inside double quotes, and the '\'' idiom), and the C
#                      runtime argument rules that cmd and PowerShell rely on
#                      for native programs
#   both
# Doubled quotes ("" and '') need no extra spelling: see Split-Segments.
$noBt = $command.Replace($bt + '"', '')
$noBs = $command.Replace('\"', '').Replace("\'", '')
$noBoth = $noBt.Replace('\"', '').Replace("\'", '')
foreach ($form in @($noBt, $noBs, $noBoth)) {
  if ($form -cne $command) { Test-Form ([string]$form) $true }
}

exit 0
