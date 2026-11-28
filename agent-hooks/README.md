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

**Windows pilot items:** Kiro documents global hooks in `~/.kiro/hooks` for Kiro CLI V3 only; for Kiro IDE it still does not document them. Measured on Windows 11 Enterprise 26H2 (Evaluation) with Kiro IDE 1.4.236 (system-wide build, standard user, 2026-11-20): Kiro IDE lists and runs the global PreToolUse hooks in `%USERPROFILE%\.kiro\hooks`, starts hook commands through `cmd.exe`, an exit code 2 blocks the tool call, and `pii-guard.ps1` blocked a write of a test NRIC. Kiro CLI 3.5.0, headless, also loaded them, ran them through `cmd.exe` and honoured exit code 2 on Windows Server 2022 (2026-11-19) and Windows 11 (2026-11-20). The hook file sits in the user's profile, and the standard user could rename it, so let MDM restore it and keep must-hold rules in `managed-settings.json`. Re-test after each Kiro update. The PowerShell guards match without regard to case, which backs up the case-sensitive shell rules on Windows (finding F1) only for what they cover: with Kiro CLI 3.5.0 on Windows 11, `destructive-fs-guard.ps1` blocked `REMOVE-ITEM .git -RECURSE -FORCE`, but `INVOKE-WEBREQUEST` still ran, because no guard covers network commands (egress needs a network control). The commands use forward slashes so they work from cmd, PowerShell and Git Bash. The `shell` matcher covers `execute_pwsh`. The `banking-secure` agent's hooks match `execute_bash` and reference `/opt/kiro/hooks`, so the agent is not installed on Windows.

**Kiro IDE 1.5.11 (Windows 11 Enterprise 26H2 (Evaluation) VM, 2026-11-21, system-wide build upgraded in place from 1.4.236, interactive session of a standard user, one run per result; not the emulated Intune context and not a real Intune tenant).** Kiro was driven without a person, and the evidence is screenshots and the log of a probe hook; no second person has reviewed the results. The limits of each row are in [`managed-settings/README.md`](../managed-settings/README.md#measured-on-windows-with-kiro-ide-1511-2026-11-21).

- **Global hooks run before tool calls (R2-71).** Kiro IDE 1.5.11 ran the four global hooks in `%USERPROFILE%\.kiro\hooks` (the three guards and a probe hook) before each tool call in the valid runs. The probe log shows that the calls come from `Kiro.exe`. The in-place upgrade left the hook files unchanged (R2-70).
- **A hook blocked (R2-72).** The probe hook blocked a test command (`echo` of a marker text). The git guard blocked `GIT push --force origin main` and, in an earlier attempt, `git push --force origin main`. Limit: these are the texts asked for in the chat; for the two git rows the screenshots do not show the exact command string that Kiro sent to the hook.
- **Hooks as the second layer for letter case.** In Kiro IDE 1.5.11 the all-capitals `INVOKE-WEBREQUEST` was not refused by the admin deny rule in Supervised mode (R2-74, one run); in the mode "Approve for me" Kiro reported that it ran the command, which is consistent with the deny rule not matching that spelling (R2-94, one run; the command string was not visible). The four hooks ran in both rows and did not block, because no guard covers network commands. The guards back up the policy only for destructive deletes, git and secrets.
- **Global steering (R2-90).** In a new chat in Supervised mode, Kiro answered with the marker text of a probe steering file, showed "Included Steering" and made no tool call. This is consistent with a steering file in `%USERPROFILE%\.kiro\steering\` being loaded; it does not show it. Limits: the "Included Steering" line was not expanded, so the screenshot does not name the file that was included; the probe file, which contains the marker, was open in the editor of the same window, so the open file as chat context is not excluded as the source of the answer; where that file lies on disk is not visible in the screenshot; the same question and answer from an earlier session was already in the window (the row itself is a new tab).
- **Not tested with Kiro IDE 1.5.11:** a new user's first start of Kiro, the mode "Accept file changes", whether Kiro treats a hook exit code other than 2 as a block, and hooks on a device with App Control (see the next section). *(Note, 2026-11-28: Round 3 tested hook exit codes other than 2 and the mode "Accept file changes"; see the next paragraph and the Exit-code contract.)*

**Kiro IDE 1.5.11, Round 3 (one Windows 11 Enterprise 26H2 (Evaluation) lab VM, 2026-11-27, a standard user's console session, one run per test, each with a named control; not a real Intune tenant).** Kiro was driven without a person and no approval button was clicked. "Ran" was read from a trace file that the asked command writes; a probe hook logged the exact command string that Kiro sent. "Verified by a test here" means that a single test with the verdict PASS carries the sentence. The rows, the controls and the limits are in [`../kiro-docs/mdm-test-evidence.md`](../kiro-docs/mdm-test-evidence.md#round-3-spec-driven-re-test-windows-11-kiro-ide-1511-2026-11-27), tables A and C.

- **For one shell tool call the probe hook logged `cmd.exe` as its parent process and `Kiro.exe` as the grandparent (T-HOOK-08a).** With the hook files removed from the user's profile and Kiro started again, no probe line was written for a tool call (T-HOOK-08b). The guard's working folder was the folder Kiro was opened on, for two workspaces (T-HOOK-06a, T-HOOK-06b; the second is a sub-folder of the first). T-HOOK-06a and 08a made no tool call of their own: they read one tool call of another chat of the same start.
- **Global steering (T-HOOK-09a, T-HOOK-09b).** With a steering file that holds a random marker in `%USERPROFILE%\.kiro\steering`, a new chat wrote the marker to a file when asked. With the file removed and Kiro started again, the same question gave "NONE". This repeats R2-90 with a control. The marker file was written by the test and was not opened in the editor by it (not a check; the editor showed another file); no other tool call was made in that chat.
- **The user can rename the hook file (T-HOOK-12a).** The standard user renamed the hook file in the user's own profile; the next detection run exited 1. The same user could not write, rename or delete a guard script in `C:\ProgramData\Kiro\hooks` (T-POL-18a).
- **`-DeployHooks` puts 7 files into `C:\ProgramData\Kiro\hooks` (T-POL-17a):** the four bash scripts and the three PowerShell guards. `SHA256SUMS` is not copied to that folder; its staged copy is under `C:\ProgramData\Kiro\deploy`. The test had expected 8 files; that expected value was wrong.
- **Hooks as the second layer for letter case.** In "Approve for me" the all-capitals spelling of `Invoke-WebRequest` and of `Invoke-Expression` ran with no prompt (T-CASE-04a, T-CASE-05a). Only the probe hook was installed in those tests, so they say nothing about the guards. No guard covers network commands.
- **Not tested in Round 3:** the shipped git guard on a force push asked for in Kiro IDE (those tests were not valid), and a new user's first start of Kiro. A secret asked for in Kiro IDE was not part of the round. R2-72 is unchanged, with its limit.

## Exit-code contract

- stdin is the hook event JSON: `{"hook_event_name","cwd","session_id","tool_name","tool_input":{...}}`
  (`postToolUse` adds `tool_response`).
- `exit 0` allows; `exit 2` blocks and returns stderr to the model.
- **Docs conflict:** newer Kiro pages say only exit 2 blocks and any other non-zero code is treated as an
  error (the call proceeds); an older IDE page says any non-zero code blocks. The guards therefore map every
  failure — empty or invalid input, missing `jq`, an internal error — to **exit 2** (fail closed).
- `audit-logger.sh` never blocks (always exit 0).
- **A guard that cannot start cannot block.** If the interpreter fails before the script runs, the exit code is not 2 and Kiro lets the call proceed. On Windows this happens when a Group Policy execution policy (`AllSigned`, `Restricted`) overrides `-ExecutionPolicy Bypass`, when Constrained Language Mode blocks the script, or when the file is missing: sign the guards where script signing is enforced, and treat a hook failure shown in Kiro as a finding. The admin policy does not depend on the hooks.
- **A guard that starts in Constrained Language Mode may end with exit 1, not 2 (R2-86).** Measured once (Windows 11 Enterprise 26H2 VM, 2026-11-21, Windows PowerShell 5.1) under an enforced lab App Control for Business policy with script enforcement, built from Microsoft's "AllowMicrosoft" example policy plus one signer rule. Unsigned scripts ran in ConstrainedLanguage there. The deployed `git-guard.ps1` (unsigned) was run as the standard user with a force-push test input: **exit 1**, nothing on STDOUT. The first error is at the line that writes the "BLOCKED" message, a .NET call that ConstrainedLanguage refuses. That line is in the guard's one `Fail` function, which is used for every block and for the internal-error handler, so it is not shown that the guard judged the command. By reading the script, its first .NET call (before the input is read) is refused in the same way; then the result would be the same for any command, also a harmless one. No harmless input was tested *(note, 2026-11-28: tested in Round 3, T-APPC-10a, below)*. So on that device the rule "every failure maps to exit 2" did not hold. Limits: one guard of three, one input, one run, one lab policy; an organisation's App Control or AppLocker policy may behave differently. Whether Kiro treats exit 1 from a hook as a block was not tested (see the docs conflict above) *(note, 2026-11-28: in Round 3 exit 1 did not block in Kiro IDE 1.5.11, T-HOOK-02a and T-HOOK-02b, below)*.
- **Re-test the hooks on devices with App Control script enforcement before you rely on them.** Signed guards were not tested *(note, 2026-11-28: Round 3 ran the signed guards outside Kiro, T-APPC-12a, below)*. Kiro starts the hook commands with `-File`, and in one run in the same lab the signed MDM reference script did not run when it was started with `-File` (R2-82; the cause is not understood). So "sign the guards" in the bullet above is not a tested remedy for App Control. The statement in that bullet that Kiro lets the call proceed for an exit code other than 2 follows Kiro's newer pages; it was not measured, and in the one lab run under Constrained Language Mode the guard started and failed part-way (exit 1) rather than not starting. An allow rule by path or hash was not tested either. Signing a hook script changes its hash, so it means rebuilding `SHA256SUMS` (see [Tests](#tests)); this was not done and not tested.
- **Round 3 (2026-11-27): what blocked in Kiro IDE 1.5.11, measured.** One lab VM, a standard user's console session, a harmless shell command, one run per test, no approval button clicked. The guard whose exit code was changed is a **lab test guard** started by a PreToolUse hook, not one of the shipped guards. In the start of most of these rows the user's profile also held a second lab guard, a launcher of the shipped `git-guard.ps1` and a probe hook; for these calls they ended with exit code 0, except the second lab guard in T-HOOK-05a, where it is the guard under test (read from their logs, not a check).
  - Guard ends with **exit 2: blocked**, in Supervised and in "Approve for me" (T-HOOK-01a, T-HOOK-01b, T-HOOK-03c, T-HOOK-04c, T-HOOK-05a; the last one with `powershell.exe` named by its full path and a guard path with a space in it).
  - Guard ends with **exit 1: not blocked.** Supervised: the normal approval prompt appeared. "Approve for me": the command ran with no prompt (T-HOOK-02a, T-HOOK-02b).
  - Guard **sleeps 45 seconds with a `timeout` value of 10 in the hook file**, and would then have ended with exit 2: **not blocked**, and the guard was not stopped. The command ran, or the prompt came, before the guard ended (T-HOOK-03a, T-HOOK-03b). A guard that slept 3 seconds and ended with exit 2 blocked (T-HOOK-03c).
  - **Guard file missing: not blocked** (T-HOOK-04a). Outside Kiro that hook command ended with exit code -196608, neither 0 nor 2 (T-HOOK-04b).
  - **Verified by a test here:** a lab test guard that ended with exit 2 blocked; one that ended with exit 1 did not; one that ran 45 seconds with a timeout value of 10 did not; a missing guard file did not (test IDs above).
  - **Not verified:** a guard that ends with exit 0 (those tests are open) and other exit codes; the unit of the timeout value, where the limit lies (in T-HOOK-03a the command ran 17.6 seconds after the guard started) and other timeout values; the shipped guards started by Kiro in this round, and their self-stop after 2.5 seconds (see [Limitations](#limitations-read-before-relying-on-the-hooks)); Kiro CLI; the exit code that Kiro itself received (the guard logs its own); what happens after "Allow" on a prompt. The App Control state and the language mode were not read in this batch. Reasoning, not a test: the rule "every failure maps to exit 2" can only cover failures that a guard catches itself.
- **Round 3 (2026-11-27): the three shipped PowerShell guards under the lab App Control policy.** Started directly as SYSTEM from the 32-bit `cmd.exe` with `powershell.exe ... -File <guard>` and a test input on STDIN, not by Kiro. One run per test, two inputs per guard. For the enforced rows the language mode was read as ConstrainedLanguage at the start of the group only; the read at the end is missing, and whether the rows stay valid without it is an open decision ([evidence, table D](../kiro-docs/mdm-test-evidence.md#d-app-control-script-enforcement-and-constrained-language-mode-batch-11c)).
  - Policy off, unsigned: exit 2 for an input that must be blocked, exit 0 for a harmless input, all three guards (T-APPC-10b).
  - Policy enforced, **unsigned: exit 1 for both inputs, all three guards**, with the same error at the line that writes the "BLOCKED" message (T-APPC-10a). So for the open point of R2-86: the result was the same for a harmless input.
  - Policy enforced, copies **signed** with a certificate that the policy trusts: exit 2 and exit 0, all three guards (T-APPC-12a). These are also the values with the policy off. The row's own output has no sign of the constrained mode; that is shown in the rows just before and after it. The signed copies were in another folder than the deployed hooks folder.
  - **Verified by a test here:** unsigned, each guard ended with exit code 1 and the same error for the blocking and for the harmless input (T-APPC-10a); signed copies started with `-File` ended with 2 and 0 (T-APPC-12a, with the limits above).
  - **Not verified:** a signed guard started by Kiro under the policy (those tests were not valid); `SHA256SUMS` rebuilt for signed guards and deployed with `lockdown-windows.ps1`; an allow rule by path or hash; AppLocker. With exit 1 a guard did not block in Kiro IDE 1.5.11 (T-HOOK-02a, T-HOOK-02b), but that was a lab test guard, and no App Control policy was applied by that test; the two results were not tested together.

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

An Authenticode signature is added to the script file, so signing the PowerShell guards also changes their hashes: rebuild `SHA256SUMS` from the signed files, and pin the new manifest hash where you use one. This was not tested (the guards were not signed in the 2026-11-21 lab runs).
