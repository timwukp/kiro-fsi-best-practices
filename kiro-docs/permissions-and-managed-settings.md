# Kiro Permissions, Managed Settings, Hooks and Custom Agents (Reference Snapshot)

> **Source:** kiro.dev: [Permissions](https://kiro.dev/docs/permissions/) (updated 2026-10-01), [Permission policies](https://kiro.dev/docs/enterprise/governance/permissions/) (2026-09-12), [Sign-in controls](https://kiro.dev/docs/enterprise/governance/sign-in/) (2026-09-30), [Hooks](https://kiro.dev/docs/hooks/) and [Hook triggers](https://kiro.dev/docs/hooks/types/) (2026-09-30), [Hook actions](https://kiro.dev/docs/hooks/actions/) (2026-08-04), [Custom agents](https://kiro.dev/docs/custom-agents/) (2026-09-02) and the [configuration reference](https://kiro.dev/docs/custom-agents/configuration-reference/) (2026-10-02).
> **Last verified:** 2026-10-08 for the pages above; the applicability table and the minimum versions below were re-checked on 2026-11-19 against the [changelog](https://kiro.dev/changelog/), [Sign-in controls](https://kiro.dev/docs/enterprise/governance/sign-in/), [Hook triggers](https://kiro.dev/docs/hooks/types/), [Enterprise Management](https://kiro.dev/docs/enterprise/enterprise-management/) and [Choose an agent harness](https://kiro.dev/docs/cli/agent-harness/).
>
> **Measured results on this page** are marked as measured and are kept apart from the vendor statements. The Round 3 results (test IDs such as T-CASE-04a) were added on 2026-11-28; they come from one Windows 11 Enterprise 26H2 lab VM with Kiro IDE 1.5.11 on 2026-11-27, one run per test, not a real Intune tenant. "Verified by a test here" means that a single test with the verdict PASS carries the sentence. The vendor pages were not read again for that change.
>
> Condensed, banking-oriented snapshot for offline use. Where official pages conflict, the newer page is followed and the conflict is noted. Deployable files that implement this reference are in [`../managed-settings/`](../managed-settings/) and [`../agent-hooks/`](../agent-hooks/).

## 1. Applicability

| Feature | Kiro IDE | Kiro CLI |
|---------|----------|----------|
| Capability-based permissions (`permissions.yaml`) | 1.0+ (GA 2026-06-25) | V3 agent harness: the default in CLI 3.0.0+ for interactive sessions and headless runs with `--trust-all-tools`; `kiro-cli --v3` in CLI 2.x. A headless run with no harness named starts on V2, so name it (`kiro-cli chat --v3 --no-interactive`) |
| Admin permission policies (`managed-settings.json`) | Minimum version not stated; requires the 1.x permission system. Verify on your version | Same (V3 engine) |
| Sign-in controls (same file) | 1.2+ | 2.25.0+ |
| v1 hook files (`.kiro/hooks/*.json`) | 1.0+ | V3 engine |
| Kiro Web | Not applicable: Web runs in an isolated cloud sandbox; `permissions.yaml`, admin policies and sign-in controls do not apply | |

"V3" names the CLI agent harness, not the 3.x version number; Kiro's pages still say "V3 sessions". Current versions: [changelog](https://kiro.dev/changelog/) (on 2026-11-19: IDE 1.4.236 and CLI 3.5.0).

**Minimum client versions** (checked 2026-11-19):

| Feature | Kiro IDE | Kiro CLI | Source |
|---------|----------|----------|--------|
| Sign-in controls (`signin_method`, `settings`) | 1.2 | 2.25.0 | [Sign-in controls](https://kiro.dev/docs/enterprise/governance/sign-in/) |
| Windows system-wide installer | 1.4.62 | — | [IDE 1.4.62](https://kiro.dev/changelog/ide/1-4-62/) |
| V3 harness by default, single `kiro-cli` binary | — | 3.0.0 | [CLI 3.0.0](https://kiro.dev/changelog/cli/3-0/) |
| Enterprise Management (preview) | 1.4.154 | 3.1.0 | [Enterprise Management](https://kiro.dev/docs/enterprise/enterprise-management/) |
| `PermissionRequest` hook; Pre Tool Use `updatedInput` | 1.4.236 | 3.4.0 | [Hook triggers](https://kiro.dev/docs/hooks/types/) |

## 2. Permissions (`permissions.yaml`)

The capability-based model replaces the IDE 0.x Trusted Commands and Command Denylist (IDE 1.0 breaking change: trusted command prefixes become `allow` rules and denylist entries become `deny` rules; `kiroAgent.trustedCommands` and `kiroAgent.commandDenylist` are no longer used).

**Rule keys:** `capability` (required), `match` (globs, optional = all resources), `exclude` (globs that must not match), `effect` (`deny` | `ask` | `allow`).

**Capabilities:** `fs_read`, `fs_write`, `shell`, `web_fetch`, `web_search`, `mcp`, `subagent`, `skill`, `power`, `context`, `diagnostics`, `sandbox_network`. Meta-capabilities: `all`, `builtin` (all built-in tools), `filesystem` (`fs_read` + `fs_write`). `sandbox_network` is not part of `all`.

**Scopes** (all evaluated together, deny-overrides: `deny > ask > allow`; no precedence between scopes, the most restrictive effect wins, except an admin `ask` under `--trust-all-tools` in headless runs, measured, see CLI session overrides below):

| Scope | Location | Effects allowed |
|-------|----------|-----------------|
| Kiro | Hardcoded invariants | deny, ask |
| Administration | `managed-settings.json` (section 3) | deny, ask |
| User | `~/.kiro/settings/permissions.yaml` | deny, ask, allow |
| Workspace | `~/.kiro/workspace-roots/<hash>/permissions.yaml` (per user, outside the repository; a cloned repo cannot inject rules) | deny, ask, allow |
| Agent | `permissions` field of an agent profile | deny, ask, allow |
| Session | In-memory consent decisions; policy presets requested by ACP clients | deny, ask, allow |

**Pattern syntax**

- `fs_read` / `fs_write`: `*` within one path component, `**` across separators, `{a,b}` and `[abc]` supported; a pattern without wildcards also matches children (`~/temp` matches `~/temp/child`).
- `shell`, `web_fetch`, `mcp`: `*` matches any sequence of characters; `**`, `?` and character classes are not supported. MCP patterns are `<server>/<tool>`.
- Globs only, no regular expressions.
- Shell commands are parsed first: compound commands (`;`, `&&`, `||`, `|`) are split and each sub-command is evaluated independently.
- Letter case is not documented for shell patterns (only sign-in method names are documented as case-sensitive). Measured with Kiro CLI 3.5.0 on Windows Server 2022 and Windows 11 (2026-11-19 and 2026-11-20): shell patterns match case-sensitively, while PowerShell runs every casing as the same cmdlet. `INVOKE-WEBREQUEST` in capitals ran past an admin `deny` for `Invoke-WebRequest*` and `invoke-webrequest*`. On Windows, a shell `deny` is therefore a guardrail, not a boundary ([details](../managed-settings/README.md#measured-limits-on-windows-kiro-cli-350-2026-11-20)). Kiro IDE 1.5.11 (Windows 11 Enterprise 26H2 VM, 2026-11-21, interactive session of a standard user, one run per row): the same deny rule refused `Invoke-WebRequest` (R2-73, R2-93). `INVOKE-WEBREQUEST` in capitals was not refused by it in Supervised mode: Kiro asked the user, and "Deny" was chosen (R2-74). In the mode "Approve for me" no prompt appeared and Kiro reported that it ran the command; the command string and its output were not visible, so "ran" is Kiro's own report, and the result is consistent with the deny rule not matching the capitals spelling (R2-94). This is a weakness in how the policy is enforced, seen once per mode, for one cmdlet, one casing and one rule; all limits are in [the Kiro IDE 1.5.11 results](../managed-settings/README.md#measured-on-windows-with-kiro-ide-1511-2026-11-21). Other casings and the mode "Accept file changes" were not tested.
- **Measured again with a named control per test (Round 3, 2026-11-27; one Windows 11 Enterprise 26H2 lab VM, Kiro IDE 1.5.11, a standard user's console session, the default policy, no guard hooks, one run per test, no approval button clicked).** "Ran" was read from a trace file and a listener on the loopback address, and a probe hook logged the exact command string that Kiro sent.

  | Spelling asked | Supervised | Accept file changes | Approve for me |
  |----------------|------------|---------------------|----------------|
  | `Invoke-WebRequest ...` (listed) | Did not run, no prompt (T-CASE-01a) | Did not run, no prompt (T-CASE-06b) | Did not run, no prompt (T-CASE-02a) |
  | `INVOKE-WEBREQUEST ...` (capitals) | Approval prompt; not run (T-CASE-03a) | Approval prompt; not run (T-CASE-06a) | **Ran, no prompt** (T-CASE-04a) |
  | `Invoke-Expression "..."` (listed) | Did not run, no prompt (T-CASE-09b) | not tested | Did not run, no prompt (T-CASE-05b) |
  | `INVOKE-EXPRESSION "..."` (capitals) | Approval prompt; not run (T-CASE-09a) | not tested | **Ran, no prompt** (T-CASE-05a) |

  **Verified by a test here:** in "Approve for me" the all-capitals spelling of these two cmdlets, which the policy denies in the listed spelling, ran, and the user was not asked (T-CASE-04a, T-CASE-05a); in Supervised Kiro asked the user for both (T-CASE-03a, T-CASE-09a), and in "Accept file changes" for `INVOKE-WEBREQUEST` (T-CASE-06a). **Not verified:** that the command runs after "Allow" (the prompts were left unanswered); `Invoke-Expression` in "Accept file changes"; other casings, cmdlets and rules; whether an administrator can lock the mode; what stopped the listed spelling (no check names a rule, and in "Approve for me" the approval model is not excluded; a harmless command ran directly before and after). The two commands that ran were harmless; another command was not tested. The rows show the outcome, not how Kiro compares the text. Rows, controls and limits: [Round 3 evidence](mdm-test-evidence.md#round-3-spec-driven-re-test-windows-11-kiro-ide-1511-2026-11-27), table A.

**Defaults without any file:** silent `fs_read` on `./**`, common read-only git commands (`git status`, `git log`, `git diff`, `git branch` …), system-info commands (`pwd`, `whoami`, `uname` …) and utility tools; everything else prompts. A `permissions.yaml` adds to these defaults.

**Kiro hardcoded invariants**

- Always denied: writes to `~/.kiro/settings/`, `.kiro/settings/`, `~/.kiro/workspace-roots/`, an installed Power's `~/.kiro/powers/installed/<name>/mcp.json`, and Kiro state stores (`~/.kiro/sandbox-state/`, `~/.kiro/web-session/`, `~/.kiro/cloud-cache/`, `~/.kiro/sandbox-curl/`).
- Always ask (trusted or not; no allow rule removes the prompt): writes to `.git/**`, `.vscode/**`, `**/*.code-workspace`, `.kiroignore`, and the agents, hooks, workflows and powers directories of the workspace `.kiro` and of `~/.kiro`.
- Ask while the workspace is untrusted: writes to `.kiro/steering`, `.kiro/skills`, `.kiro/extensions` and any undeclared `.kiro` directory.

**Headless:** with no interactive client, every `ask` is treated as `deny`, unless the run is started with `--trust-all-tools` (see below).

**IDE autonomy:** `kiroAgent.agentAutonomy` = `Autopilot` (proceed with allowed operations) or `Supervised` (prompt before any action). The permission layer applies after the autonomy decision. In Kiro IDE 1.5.11 the mode menu shows Supervised, Accept file changes and Approve for me, and no entry named "Autopilot" (R2-92, Windows 11 Enterprise 26H2 VM, 2026-11-21, one look at the menu); how these choices map to `kiroAgent.agentAutonomy` was not checked.

**Interactive approvals:** Allow / Always allow / Deny / Always deny. "Always allow" saves to all workspaces (user file), this workspace (workspace-roots file) or this session. Chained commands are approved sub-command by sub-command.

**CLI session overrides:** `--trust-all-tools` still works as a session-scope override, and V3 adds `/tools trust-all` (CLI 2.24.0) and `/tools untrust <tool>`. These are allow sources and cannot override an admin `deny`. **Conflict between the official pages:** the permission policies page says an admin `ask` forces a prompt even over a user `allow`, and that a preset `allow` never overrides an admin `deny` or `ask`; the permissions page says `--trust-all-tools` and `/tools trust-all` trust every tool action the rules do not deny. Measured with Kiro CLI 3.5.0 in headless runs on Windows Server 2022 and Windows 11 (2026-11-19 and 2026-11-20), the second statement holds: with `--trust-all-tools`, `Remove-Item <file> -Force` under an admin `ask` rule ran and nobody was asked; without the flag it was refused; with the rule changed to `deny` it was refused (for the listed spelling; `REMOVE-ITEM <file> -FORCE` in capitals ran, because shell patterns match case-sensitively). `/tools trust-all` in an interactive session was not measured. Use admin `deny` for anything that must never run, and keep `--trust-all-tools` and `--trust-tools` out of unattended and agent configurations ([details](../managed-settings/README.md#measured-limits-on-windows-kiro-cli-350-2026-11-20)).

**Official example:**

```yaml
rules:
  - capability: shell
    effect: allow
    match: ["npm *"]
    exclude: ["npm publish*"]
  - capability: fs_read
    effect: deny
    match: ["**/.env", "**/.env.*", "secrets/**", "**/*.pem"]
```

## 3. Admin policy (`managed-settings.json`)

| OS | Path |
|----|------|
| macOS | `/Library/Application Support/Kiro/managed-settings.json` |
| Windows | `C:\ProgramData\Kiro\managed-settings.json` (UTF-8 **without** BOM; Windows PowerShell `Out-File` writes UTF-16 by default, which Kiro rejects) |
| Linux | `/etc/kiro/managed-settings.json` |

- Paths require administrator/root to modify. Deploy with MDM (Jamf, Kandji, Intune), Group Policy or SCCM. Restart Kiro to apply.
- One file serves every Kiro surface on the machine (IDE and CLI). Administration scope is for enterprise plans.
- Schema: `{"rules": [ ... ], "settings": { ... }}`. Keep `"rules": []` even if only settings are used. Rule fields: `capability` (required), `match`, `exclude`, `effect` (required; `deny` or `ask` only).
- **Validation (permission rules fail closed):** malformed JSON → whole file rejected, all tool calls denied until fixed or removed; `"effect": "allow"` → whole file rejected (same result); unknown fields → whole file rejected; unknown capabilities → rule skipped with a warning (forward compatibility).
- A denial caused by the policy names the rule source "administration"; the user is told their own settings cannot override it.
- **Measured, not a vendor statement (Round 3, 2026-11-27, Kiro IDE 1.5.11 on one Windows 11 lab VM, one run each):** with a UTF-8 BOM in the policy file and Kiro started again, a harmless shell command that ran under the valid file did not run, and the window text had "Permissions: Failed" and "Kiro could not load your permission settings" (T-POL-09a, control T-POL-09b). One command, one kind of invalid file, the default policy, a user who was signed in to Kiro. In one start, the prompt for `git.exe push origin feature/x`, which an admin `ask` pattern matches, had three buttons (Allow, Always deny, Deny), and the prompt for a command that no rule covers had four (with "Always allow"); the prompts were not answered (T-POL-16a, T-POL-16b). The two prompts are for different commands, and the same command was not prompted without the rule, so it is not shown that the `ask` rule is the cause. The policy of that start was the default policy with one `fs_write` deny rule added and two steering ask patterns removed. [Round 3 evidence](mdm-test-evidence.md#round-3-spec-driven-re-test-windows-11-kiro-ide-1511-2026-11-27), table E.
- **Client-side enforcement:** "can be circumvented by users, e.g., via administrative access to their local machine."

Official examples:

```json
{ "rules": [ { "capability": "web_fetch", "effect": "deny" }, { "capability": "shell", "match": ["rm *", "sudo *"], "effect": "deny" } ] }
```

```json
{ "rules": [ { "capability": "web_fetch", "exclude": ["docs.aws.amazon.com", "*.amazonaws.com", "*.github.com"], "effect": "deny" } ] }
```

The second example denies every domain except the excluded ones; excluded domains fall through to the user's own rules.

## 4. Sign-in controls (same file)

- Rule: `{"capability": "signin_method", "match": ["*"], "exclude": ["<kept methods>"], "effect": "deny"}`. Effect must be exactly `deny`; anything else (including `allow`, `ask`, `Deny`) makes Kiro ignore the restriction with a warning. At most 16 entries across `match` and `exclude`. If several rules exist, a method denied by any of them is denied.
- Method names (case-sensitive): `idc`, `external_idp`, `builder_id`, `google`, `github`, `social` (Google and GitHub). Screen labels and internal identifiers (`awsidc`, `builderid`) are not valid.
- Settings keys (optional, strings of at most 2,048 bytes of UTF-8 without control characters, URLs must be https): `idc_start_url`, `idc_region`, `external_idp_domain`, `external_idp_start_url`, `external_idp_region` (without it Kiro looks up the organization across Regions), `signin_help_url` (rendered by the client only, so an internal URL is fine), `auth_portal_url` (Kiro CLI 3.5.0+: the portal that `kiro-cli login` opens in the browser instead of `https://app.kiro.dev`; an https URL with no credentials, query or fragment).
- **Sign-in portal (Kiro CLI 3.5.0+, browser sign-in only, re-checked 2026-11-19):** Kiro CLI takes the portal from the first source that is set: (1) the `AuthPortalUrl` OS policy (Windows: a string value under `HKLM\SOFTWARE\Policies\Kiro`; macOS: a forced managed preference in the `dev.kiro.desktop` domain; Linux has no OS policy store), (2) `auth_portal_url` in `managed-settings.json`, (3) the user's `KIRO_AUTH_PORTAL_URL` environment variable, then the user's own setting and the default. The two administrator sources win over the user sources. A policy value of the wrong type reads as unset; a value that is present but invalid sends users to the default portal, never to their own settings. If no administrator source is set, the user's environment variable applies and is not validated. Kiro's page describes the portal for the CLI only, not for the IDE.
- Read when a sign-in starts (next sign-in). The client re-checks the method when the browser returns and refuses a denied method before a token is issued.
- **The method restriction fails open** (the portal selection above does not): an invalid/unreadable file, a BOM, non-UTF-8 encoding, rules that deny every method or none, unrecognized `exclude` names or more than 16 entries drop the restriction and offer every method. Because the same file carries permission policies, an invalid file also blocks the agent's tools. Unknown settings keys are ignored.
- **Measured, not a vendor statement (Round 3, 2026-11-27, Kiro IDE 1.5.11 on one Windows 11 lab VM, a new local user not signed in to Kiro, one run each; no method was clicked and no credential was typed):** with the Entra ID variant of the policy (`exclude: ["external_idp"]`) the sign-in page offered one method, "Your organization" (T-POL-20a). With no policy file it offered four: Builder ID, GitHub, Google and "Your organization" (T-POL-20b). With the same policy file rewritten with a UTF-8 BOM it also offered four (T-POL-21a): the method restriction was not visible on the page. The methods were read from the UI Automation tree of the page. The rows differ in the whole policy file; a file that differs only in the sign-in rule was not tested. Whether a sign-in with one of the offered methods completes was not tested. This test and T-POL-09a used two different files and users; no test read a tool call and the sign-in page for one invalid file. Not tested: UTF-16, malformed JSON, a completed sign-in, an Entra ID account. [Round 3 evidence](mdm-test-evidence.md#round-3-spec-driven-re-test-windows-11-kiro-ide-1511-2026-11-27), table E.
- Not applied in Kiro Web or on devices without the file; older clients ignore it. Controlling who can use Kiro remains the job of the IdP and Kiro subscriptions.

```json
{
  "rules": [
    { "capability": "signin_method", "match": ["*"], "exclude": ["idc"], "effect": "deny" }
  ],
  "settings": {
    "idc_start_url": "https://my-org.awsapps.com/start",
    "idc_region": "us-east-1",
    "signin_help_url": "https://it.example.com/kiro-help"
  }
}
```

## 5. Workspace trust

A workspace is untrusted until the user trusts it; the decision is stored outside the workspace, so a repository cannot change its own trust status. While untrusted, Kiro:

- does not load the workspace's custom agents, steering files, MCP server configuration, skills or workflow files;
- asks before every shell command (including background processes), even if a rule allows it; a deny still refuses;
- asks before every MCP tool call and every Power activation, content read or tool call, even if a saved rule or `autoApprove` allows it;
- asks before writes to `.kiro/steering`, `.kiro/skills`, `.kiro/extensions` and undeclared `.kiro` directories;
- refuses writes to `~/.kiro/memories/` and the session store (`~/.kiro/sessions/` by default) and does not let the agent change memories, knowledge bases or remote learnings.

User, administration, agent, session and workspace-roots rules still load. One exception: an `fs_write` allow in the user `permissions.yaml` with no `match` and no `exclude` lifts the untrusted-only `.kiro` write prompts (not the always-ask paths).

**Not documented:** the untrusted list does not mention workspace hook files (`.kiro/hooks/`). Verify on your Kiro version whether hooks from an untrusted repository run, and review `.kiro/hooks/` in third-party repositories before opening them.

## 6. Protected configuration (IDE 1.2)

Kiro asks before the agent changes agent, hook or Power files or `.kiro/workflows/` recipes, even when broader file permissions allow the write.

## 7. Hooks (v1 hook files)

- Locations: `.kiro/hooks/<id>.json` (workspace) and `~/.kiro/hooks/` (global). Any `.json` file name; several hooks per file; active at session start. Replaces the IDE 0.x `.kiro.hook` format and the CLI 2.x hooks embedded in agent config (`kiro-cli agent migrate` converts them).
- Schema: `{"version": "v1", "hooks": [{"name", "description", "trigger", "matcher", "action": {"type": "command" | "agent", "command" | "prompt"}, "timeout", "enabled", "confirm"}]}`. `matcher` is a regular expression on the tool name (tool events) or file path (file events); omitted = always. `timeout` in seconds for command actions (default 60; 0 disables).
- Triggers: `UserPromptSubmit`, `Stop`, `SessionStart`, `SessionEnd` (CLI V3, 2.25.0), `PreToolUse`, `PostToolUse`, `PostFileCreate`, `PostFileSave`, `PostFileDelete`, `PreTaskExec`, `PostTaskExec`, `Manual`, `AgentSpawn` (alias of `SessionStart`). Triggers that can block: `PreToolUse`, `UserPromptSubmit`, `PreTaskExec`.
- Matchers: IDE categories `read`, `write`, `shell`, `web`, `spec`, `*`, plus `@mcp`, `@powers`, `@builtin`; CLI canonical tool names (`fs_read`, `fs_write`, `execute_bash`, `use_aws`) and aliases (`read`, `write`, `shell`, `aws`); CLI 2.28.0 lets V3 hooks match by category. MCP tools appear as `@<server>/<tool>`.
- STDIN (command actions): `{"hook_event_name": "preToolUse", "cwd": "…", "session_id": "…", "tool_name": "…", "tool_input": {…}}`; `postToolUse` adds `tool_response`, `userPromptSubmit` has `prompt`, `stop` has `assistant_response`.

**Exit codes (Hook triggers page, 2026-09-30):**

| Exit code | PreToolUse / UserPromptSubmit / PreTaskExec | Other triggers |
|-----------|---------------------------------------------|----------------|
| 0 | Proceed; STDOUT added to the agent's context | Success; STDOUT added to context |
| 2 | **Block**; STDERR returned to the model | No block; STDERR shown as a warning |
| Any other non-zero | Error, **not** a block: execution proceeds and STDERR is shown as a warning | STDERR warning |

**Docs conflict:** the older Hook actions page (2026-08-04) still says any non-zero exit blocks a Pre Tool Use or Prompt Submit hook. Design guard hooks to exit 2 both on a policy block **and** on any internal failure (missing dependency, parse error, timeout handling) so that they block under either reading.

**Measured in Kiro IDE 1.5.11 on Windows (Round 3, 2026-11-27; one Windows 11 Enterprise 26H2 lab VM, a standard user's console session, a lab test guard started by a PreToolUse hook, a harmless shell command, one run per test, no approval button clicked).** This is a measurement, not a vendor statement.

| Guard | Supervised | Approve for me |
|-------|------------|----------------|
| Ends with exit code 2 | Blocked: no prompt, command not run (T-HOOK-01a) | Blocked: command not run (T-HOOK-01b, T-HOOK-03c, T-HOOK-04c, T-HOOK-05a) |
| Ends with exit code 1 | **Not blocked:** the normal approval prompt appeared (T-HOOK-02a) | **Not blocked:** the command ran with no prompt (T-HOOK-02b) |
| Runs 45 seconds with a `timeout` value of 10 in the hook file, then would end with exit code 2 (a guard that ran 3 seconds and ended with exit code 2 blocked, T-HOOK-03c) | **Not blocked:** the prompt appeared before the guard ended (T-HOOK-03b) | **Not blocked:** the command ran before the guard ended; the guard was not stopped (T-HOOK-03a) |
| Guard file missing | not tested | **Not blocked:** the command ran (T-HOOK-04a). Outside Kiro the hook command ended with exit code -196608 (T-HOOK-04b) |

- **Verified by a test here:** a guard that ended with exit code 2 blocked. A guard that ended with exit code 1 did not block. A guard that ran 45 seconds with a timeout value of 10 did not block. A missing guard file did not block (test IDs in the table).
- **Not verified:** a guard that ends with exit code 0 (those tests are open) and other exit codes; the unit of the timeout value and where the limit lies (the command of T-HOOK-03a ran 17.6 seconds after the guard started), and other timeout values; Kiro CLI; other triggers than PreToolUse; the exit code that Kiro itself received (the guard logs its own code); the shipped guards in Kiro IDE in this round. Reasoning, not a test: a rule "exit 2 on every internal failure" inside a guard can only cover failures that the guard itself catches.
- Compared with the vendor table above (the Hook triggers page as dated there; not read again for this change): the same outcome, block or no block, for exit codes 2 and 1. The warning text that the vendor row also names was not read. The older Hook actions page says otherwise (see the docs conflict above). In "Approve for me" a command that does not run may also have been stopped by the approval model; a harmless command ran directly before and after.
- Rows, controls and limits: [Round 3 evidence](mdm-test-evidence.md#round-3-spec-driven-re-test-windows-11-kiro-ide-1511-2026-11-27), table C.

**CLI 2.x embedded hooks** (legacy agent `hooks` field): triggers `agentSpawn`, `userPromptSubmit`, `preToolUse`, `postToolUse`, `stop`; matchers use internal tool names (`fs_read`, `fs_write`, `execute_bash`, `use_aws`); timeout `timeout_ms` (default 30000). Whether the IDE honours the agent `hooks` field differs between pages and versions; use v1 hook files for the IDE.

## 8. Custom agents

- Locations: `.kiro/agents/<name>.json` or `.md` (workspace; loaded only if the workspace is trusted) and `~/.kiro/agents/<name>.json` or `.md` (global). Nested directories become names such as `team/planner`. If both locations define the same name, the workspace agent wins (with a warning). Agent files placed anywhere else (for example under `/opt` or `/Library`) are not loaded as agents.
- Fields: `name`, `description`, `prompt`, `mcpServers`, `tools`, `excludedTools`, `toolAliases`, `allowedTools`, `permissions` (`{"rules": [...]}`), `resources` (`file://`, `skill://`, knowledge bases), `includeMcpJson`, `includePowers`, `model`, `keyboardShortcut`, `welcomeMessage`, `hooks`.
- MCP precedence for the same server name: agent `mcpServers` > workspace `mcp.json` > user `mcp.json`.
- Kiro Web can invoke committed workspace agents as sub-agents but cannot select one as the primary agent.
- **Docs conflict (resources):** the steering and skills pages say custom agents do not load steering or skills automatically (add `skill://.kiro/skills/*/SKILL.md`), while the configuration reference says custom agents inherit default resources unless `chat.disableInheritingDefaultResources` is set. List the resources you need explicitly.

## 9. `toolsSettings` deprecation

- Configuration reference: `toolsSettings` is "deprecated in CLI 3.0 and IDE 1.0. Use the permissions field"; it is still used for MCP-tool-specific settings and subagent settings. The V3 agent-configuration page says `toolsSettings` is removed in V3.
- Migration (`kiro-cli agent migrate` or `/upgrade-agent`): allowed/denied commands and paths become `permissions.rules`. `autoAllowReadonly` and `denyByDefault` have **no** equivalent; express them as explicit rules.

## 10. Related controls (elsewhere in this folder)

- MCP configuration files, MCP governance and the MCP registry: [`mcp-configuration.md`](mcp-configuration.md), [`mcp-security.md`](mcp-security.md).
- Data location, network endpoints and firewall allowlist: [`privacy-and-security.md`](privacy-and-security.md).
- Changelog-derived feature inventory: [`security-governance-features.md`](security-governance-features.md).
