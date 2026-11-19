# agent-hooks — Kiro hook scripts (defense in depth)

These hooks are a **secondary** runtime control. The primary controls are:

1. **Admin policy** — [`managed-settings/`](../managed-settings/README.md) deployed by MDM to the official
   `managed-settings.json` path (deny/ask rules evaluated by the Kiro client; compound shell commands are
   split and each part is checked).
2. **Server-side branch protection / rulesets** on your Git host (the only control that cannot be bypassed
   from a developer workstation).

The hooks add content inspection that permission globs cannot do (secrets and personal data in tool input),
a second check for history-destroying git operations, and a supplementary local audit trail.

| File | Trigger / matcher | Purpose | MAS TRM |
|---|---|---|---|
| `pii-guard.sh` | PreToolUse, `*` | Block tool input containing private keys, AWS/GitHub/Anthropic credentials, password assignments, Singapore NRIC/FIN (S/T/F/G/M) or card numbers | 11.1 |
| `git-guard.sh` | PreToolUse, shell (`execute_bash`) | Block force-push, `+`/`:` refspecs, pushes to `main`/`master`, `reset --hard`, `clean -f`, `branch -D`, history rewrites | 6.3, 7.5 |
| `destructive-fs-guard.sh` | PreToolUse, shell (`execute_bash`) | Block recursive deletion of `/`, `~`, `$HOME`, `.`, `..`, system directories or `.git`; moving `.git`; `find -delete` / `-exec rm`; `mkfs`; `dd` to a device | 11.3 |
| `audit-logger.sh` | PostToolUse, `*` | Append a hash-chained JSONL record (SHA-256 of the input, never the raw input) | 12.2 |
| `banking-secure.agent.json` | — | Kiro CLI custom agent: `permissions.rules` + embedded hooks + resources (AGENTS.md, steering, skills) | — |
| `hooks/banking-guards.json` | — | The same hooks in the v1 hook-file format (IDE 1.0+ and CLI V3) | — |
| `windows/pii-guard.ps1`, `windows/git-guard.ps1`, `windows/destructive-fs-guard.ps1` | PreToolUse, `*` / shell | PowerShell ports of the three guards for Windows (no `jq` or bash needed). Same rules and exit-code contract, plus Windows forms: `Remove-Item`/`rd`/`del` with recursion on protected paths (drive roots, `C:\Windows`, `C:\Program Files`, `C:\Users`, `%USERPROFILE%`, `.git`), `Format-Volume`, `Clear-Disk`, `diskpart`, `format X:`, `cipher /w`, and `powershell -Command` / `pwsh -c` / `cmd /c` wrappers | 11.1, 6.3, 7.5, 11.3 |
| `hooks/banking-guards.windows.json` | — | v1 hook file for Windows: the three PowerShell guards (`powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:/ProgramData/Kiro/hooks/<guard>.ps1`); no audit logger | — |
| `SHA256SUMS` | — | Pinned hashes of the bash scripts, the PowerShell guards and the Windows hook file; `mdm/` verifies them before deploying (the Linux and macOS scripts verify the `windows/` and `hooks/` entries but deploy only the top-level `*.sh`) | — |

## Two configuration formats

- **v1 hook files** (`hooks/banking-guards.json`) — Kiro IDE 1.0+ and the CLI V3 engine load hook files from
  `~/.kiro/hooks/` (global) and `.kiro/hooks/` (workspace). Matchers use categories (`shell`, `write`, `*`);
  `timeout` is in seconds.
- **CLI custom agent** (`banking-secure.agent.json`) — hooks embedded in the agent (`preToolUse` /
  `postToolUse`, matchers use tool names such as `execute_bash`, `timeout_ms`). Kiro loads agents only from
  `~/.kiro/agents/` and the workspace `.kiro/agents/` (workspace wins on a name clash). The deprecated
  `toolsSettings` block was replaced by `permissions.rules`.

## Deployment

The scripts are referenced by absolute path:

| OS | Script directory | Deployed by |
|---|---|---|
| Linux | `/opt/kiro/hooks/` | `mdm/lockdown-linux.sh` (root-owned, 0755, after `SHA256SUMS` verification) |
| macOS | `/Library/Application Support/Kiro/hooks/` | `mdm/lockdown-macos.sh` (rewrites `/opt/kiro/hooks` in the deployed copies) |
| Windows | `C:\ProgramData\Kiro\hooks\` | `mdm/lockdown-windows.ps1 -DeployHooks` (the PowerShell guards and the bash scripts, Administrators-owned with a Users deny); `-InstallUser` writes `hooks/banking-guards.windows.json` to `.kiro\hooks\` in every profile and `C:\Users\Default`. See [`../kiro-docs/intune-deployment.md`](../kiro-docs/intune-deployment.md) |

Requirements: `bash`, `jq`, `awk`, `sed`, `grep`, and `shasum` or `sha256sum` for the bash scripts; Windows PowerShell 5.1 or PowerShell 7 for the PowerShell guards.

**Windows pilot items:** Kiro documents global hooks in `~/.kiro/hooks` for Kiro CLI V3; whether Kiro IDE loads them on Windows, and which shell runs a hook command there, is not documented. The commands use forward slashes so they work from cmd, PowerShell and Git Bash. The `shell` matcher covers `execute_pwsh`. The `banking-secure` agent's hooks match `execute_bash` and reference `/opt/kiro/hooks`, so the agent is not installed on Windows.

## Exit-code contract

- stdin is the hook event JSON: `{"hook_event_name","cwd","session_id","tool_name","tool_input":{...}}`
  (`postToolUse` adds `tool_response`).
- `exit 0` allows; `exit 2` blocks and returns stderr to the model.
- **Docs conflict:** newer Kiro pages say only exit 2 blocks and any other non-zero code is treated as an
  error (the call proceeds); an older IDE page says any non-zero code blocks. The guards therefore map every
  failure — empty or invalid input, missing `jq`, an internal error — to **exit 2** (fail closed).
- `audit-logger.sh` never blocks (always exit 0).
- **A guard that cannot start cannot block.** If the interpreter fails before the script runs, the exit code is not 2 and Kiro lets the call proceed. On Windows this happens when a Group Policy execution policy (`AllSigned`, `Restricted`) overrides `-ExecutionPolicy Bypass`, when Constrained Language Mode blocks the script, or when the file is missing: sign the guards where script signing is enforced, and treat a hook failure shown in Kiro as a finding. The admin policy does not depend on the hooks.

## Limitations (read before relying on the hooks)

- Pattern-based. Commands are normalized (shell `-c` wrappers, quotes, compound commands, `git -C/-c`
  options; on Windows also `powershell -Command`, `pwsh -c`, `cmd /c` and backtick escapes) but deliberate
  obfuscation — variables (for example a path held in `$p`), pipeline input to `Remove-Item`, aliases,
  `-EncodedCommand`, .NET calls, scripts written to disk and then run (`powershell -File`), other
  interpreters, shell brace expansion (`./{.git,build}`), `rm -rf $(pwd)` — can evade them.
- The PowerShell guards read a command in several ways and block if any reading is blocked: split on
  `;`, `|`, `&`, `&&`, `||`, new lines and `( ) { }`; with backtick, caret and backslash line continuations
  joined; with `^` escapes removed; and with the wrappers below unwrapped.
  - **Quotes.** Text inside quotes is not split. A quote is closed by the next quote of the same kind; a
    doubled quote (`""`, `''`) stays inside the string. Because the shell that will run the command is not
    known, the command is also evaluated with escaped quotes removed (backtick-quote for PowerShell,
    backslash-quote for sh and native argument parsing, and both). If the quotes of the command as written
    are unbalanced, it is inspected with all quotes removed.
  - **Wrappers inspected:** `sh` / `bash` / `zsh` / `dash` / `ksh -c`; `powershell` / `pwsh -Command` (any
    prefix from `-c` to `-command`, also `/c`) and `-CommandWithArgs`; the first positional argument of
    `powershell.exe`; `cmd /c` and `/k` (also `/d /s /c`, `/c"..."` and the nested-quote form);
    `Invoke-Expression` / `iex`. Up to 40 levels of nesting and 2,000 wrappers per command; beyond that the
    command is blocked.
  - **Not inspected:** `-File` scripts, `-EncodedCommand`, `ssh host "..."`, `Start-Process -ArgumentList`,
    text piped to `iex`, `cmd.exe` called by path with nested quotes, and computed paths such as
    `(Join-Path $PWD '.git')`. Shell comments are not stripped, so `git push origin feature/x # not main` is
    blocked.
  - **Size and time bounds, all blocking (exit 2):** a command longer than 32,767 characters (the Windows
    command-line limit), hook input over 262,144 characters, pii-guard input over 1 MiB, and an analysis still
    running 2.5 seconds after the script started. A hook that runs into Kiro's own timeout does not block,
    so the guards stop themselves first.
  - **Difference from the bash guards:** a quoted string that contains a separator and a blocked command
    (`git commit -m "stop; git push --force"`) is blocked by the bash guard and allowed on Windows; the `&`,
    line-continuation, brace and assignment handling exists only in the PowerShell guards.
- `pii-guard.sh` is broad by design; expect occasional false positives (for example, 16-digit IDs).
- A developer with local administrator rights can remove hooks and policy files. MDM detects drift by
  re-running and comparing hashes; it cannot prevent an administrator from changing the machine.
- The audit chain is tamper-evident only against casual edits (no secret key). The authoritative audit trail
  is Kiro prompt logging and user activity reports (S3, profile region) plus CloudTrail.

## Tests

```bash
bash agent-hooks/tests/run-tests.sh          # exact exit codes for every fixture, fail-closed and audit checks
(cd agent-hooks && shasum -a 256 -c SHA256SUMS)
```

```powershell
# Windows: the PowerShell guards against the shared fixtures plus tests\fixtures\windows-cases.tsv
powershell -NoProfile -ExecutionPolicy Bypass -File agent-hooks\tests\run-tests.ps1
```

Fixtures live in `tests/fixtures/` (`git-fs-cases.tsv`, `pii-cases.tsv`, and `windows-cases.tsv` for PowerShell
and cmd forms, used only by the PowerShell guards). Add a row for every new bypass you find; rows marked
`known_gap` in the fourth column are skipped and counted. CI runs the bash tests in `validate-governance` and
the PowerShell tests under Windows PowerShell 5.1 and PowerShell 7 in `validate-windows`.

After changing a script, regenerate the hashes:

```bash
cd agent-hooks && shasum -a 256 audit-logger.sh destructive-fs-guard.sh git-guard.sh pii-guard.sh \
  hooks/banking-guards.windows.json windows/destructive-fs-guard.ps1 windows/git-guard.ps1 windows/pii-guard.ps1 > SHA256SUMS
```

The repository's `.gitattributes` keeps these files LF on every platform; a CRLF checkout changes their hashes.
