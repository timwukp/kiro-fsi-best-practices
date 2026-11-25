# Kiro Permissions, Managed Settings, Hooks and Custom Agents (Reference Snapshot)

> **Source:** kiro.dev: [Permissions](https://kiro.dev/docs/permissions/) (updated 2026-10-01), [Permission policies](https://kiro.dev/docs/enterprise/governance/permissions/) (2026-09-12), [Sign-in controls](https://kiro.dev/docs/enterprise/governance/sign-in/) (2026-09-30), [Hooks](https://kiro.dev/docs/hooks/) and [Hook triggers](https://kiro.dev/docs/hooks/types/) (2026-09-30), [Hook actions](https://kiro.dev/docs/hooks/actions/) (2026-08-04), [Custom agents](https://kiro.dev/docs/custom-agents/) (2026-09-02) and the [configuration reference](https://kiro.dev/docs/custom-agents/configuration-reference/) (2026-10-02).
> **Last verified:** 2026-10-08 for the pages above; the applicability table and the minimum versions below were re-checked on 2026-11-19 against the [changelog](https://kiro.dev/changelog/), [Sign-in controls](https://kiro.dev/docs/enterprise/governance/sign-in/), [Hook triggers](https://kiro.dev/docs/hooks/types/), [Enterprise Management](https://kiro.dev/docs/enterprise/enterprise-management/) and [Choose an agent harness](https://kiro.dev/docs/cli/agent-harness/).
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
