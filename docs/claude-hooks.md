# Claude Code Hooks

Overwatch ships Claude Code hooks that keep Claude anchored to the engagement graph during long sessions. They are not optional polish: without them, the model can drift into raw Bash, summarize recon in prose, or answer from memory after compaction.

## What gets pulled

A `git pull` gives you the shared pieces:

- `.claude/hooks/*.mjs` — hook scripts.
- `.claude/settings.example.json` — copyable hook configuration.
- `.mcp.example.json` — copyable MCP server configuration.
- `CLAUDE.md`, `AGENTS.md`, and the generated system prompt updates.

It does **not** activate MCP or hooks by itself. `.mcp.json` and
`.claude/settings.json` are intentionally gitignored because they contain
machine-specific paths. The recommended daemon setup creates both safely:

```bash
npm run setup
```

That command preserves other MCP entries, an existing `engagement.json`, and
unrelated Claude settings; it replaces only Overwatch-managed hook entries with
the current checked-in definitions. `--force` is retained as a safe compatibility
alias. If the config is missing beside durable artifacts, setup either
wires one unambiguous state for read-only recovery or stops before writing. It
also writes the shared HTTP MCP credential and converges the managed hook settings
without removing unrelated entries. Use the manual
example-copying flow below only when you intentionally want the solo stdio
compatibility mode or need to merge an existing custom configuration by hand.

For actual engagement work, launch the terminal client with the engagement
gate armed:

```bash
OVERWATCH_ENGAGEMENT_ACTIVE=1 claude
```

Plain `claude` still connects through the generated MCP entry, but these
engagement-only hooks remain silent. Leave the flag unset when developing
Overwatch itself.

## `.mcp.json` vs `.claude/settings.json`

The recommended setup uses two local config files:

| File | Usually contains | Tracked? |
|------|------------------|----------|
| `.mcp.json` | MCP server definitions such as `mcpServers.overwatch` | No |
| `.claude/settings.json` | Claude Code project settings, including hooks; may also contain `mcpServers` | No |

For an explicit **solo stdio** checkout:

```bash
npm run setup:stdio
```

Setup writes absolute lifecycle/profile paths into `.mcp.json` and merges the
managed hooks into `.claude/settings.json`. Do not edit only one side of that
wiring. Do not use stdio alongside a running daemon; use the default `npm run
setup` so terminal Claude connects to the one existing owner.

Do **not** assume copying `.claude/settings.example.json` replaces `.mcp.json`. They are different files for different jobs.

## Manual solo-stdio setup

Use this mode only when one Claude session should launch and own Overwatch:

```bash
npm run setup:stdio
```

Setup publishes the lifecycle-backed shape below with absolute paths:

```json
{
  "mcpServers": {
    "overwatch": {
      "command": "node",
      "args": ["/absolute/path/to/overwatch/scripts/daemon-lifecycle.mjs", "run-stdio"],
      "env": {
        "OVERWATCH_RUNTIME_PROFILE": "/absolute/path/to/overwatch/.overwatch-runtime/profile.json"
      }
    }
  }
}
```

Only use this alternate location if your MCP server is configured in
`.claude/settings.json` instead of `.mcp.json`; copy the exact setup-generated
entry rather than pointing directly at `dist/index.js`:

```json
{
  "hooks": {
    "...": "copy from .claude/settings.example.json"
  },
  "mcpServers": {
    "overwatch": {
      "command": "node",
      "args": ["/absolute/path/to/overwatch/scripts/daemon-lifecycle.mjs", "run-stdio"],
      "env": {
        "OVERWATCH_RUNTIME_PROFILE": "/absolute/path/to/overwatch/.overwatch-runtime/profile.json"
      }
    }
  }
}
```

If you already have `.claude/settings.json`, keep your existing content and paste in the full `"hooks"` object from `.claude/settings.example.json`.

Use absolute paths for MCP config whether it lives in `.mcp.json` or `.claude/settings.json`. Keep `${CLAUDE_PROJECT_DIR}` exactly as written in hook args; Claude Code expands it to this repo path.

## Terminal Claude and dashboard workers

Project hooks and `.mcp.json` configure the **human-operated terminal Claude
session**. Dashboard-deployed planners and agents intentionally do not load
them. The daemon launches each managed worker with:

- a temporary `0600`, task-specific MCP configuration that points back to the
  existing daemon;
- strict MCP configuration, so an old/project stdio server cannot be merged;
- `user` as the only Claude setting source, preserving normal authentication
  without loading project/local hooks or settings;
- Claude session persistence disabled, so agent runs do not pollute the human
  terminal's resume list;
- an archetype-specific Overwatch tool allowlist.

The worker and terminal still see the same Overwatch tasks, findings, approvals,
frontier leases, and durable playbook claims. This is the intended coexistence
model: **one shared Overwatch runtime, separate Claude processes and sessions**.
Run `npm run doctor` to verify that the installed Claude CLI supports the worker
isolation flags before relying on dashboard planners or agents.

## What the hooks do

| Hook | Behavior |
|------|----------|
| `UserPromptSubmit` | Adds a short Overwatch grounding reminder before each user prompt is processed. |
| `PreToolUse` on `Bash` | Blocks obvious target-facing raw Bash such as `nmap 10.0.0.5` or `curl http://target` and redirects Claude to Overwatch `run_tool`, `run_bash`, or session tools. |
| `PreToolUse` on `Task` | Blocks delegating to a host-runtime subagent (which escapes every Overwatch control at once) and redirects to Overwatch `dispatch_agents` / `register_agent`. |
| `PostToolUse` on `Bash` | Reminds Claude to turn discovery-looking output into graph state with `parse_output`, `report_finding`, or `ingest_json`. |
| `PostToolUse` on `Write` / `WebFetch` | Reminds Claude to land anything written to disk or fetched from the web into the graph (not left off-graph). |
| `SessionStart` / `PreCompact` | Injects a reminder to (re)call `get_system_prompt(role="primary")` + `get_state()` — the dynamic prompt is the source of truth, especially after compaction. |
| `Stop` | Turn-scoped: catches likely engagement drift when the **current turn** used no Overwatch tool, and tells Claude to refresh with `get_state`. |

The Bash guard is intentionally narrow. It should not block normal repo work such as `git status`, `rg`, `npm test`, `npx tsc --noEmit`, or `mkdocs build --strict`.

## When the hooks fire (engagement-active gate)

The hooks are **engagement controls, not dev controls.** Every one of them AND-gates on
`isEngagementActive()` — so on a checkout where you're *developing Overwatch itself* they
stay completely silent. This matters because the drift heuristics are text patterns, and
this codebase is saturated with the very words they look for (`mcp`, `session`, `finding`,
`target`, `scan`). Without the gate, all four fire constantly during normal development,
which trains you to ignore them — so by the time a real engagement runs, the reminders are
noise. The gate keeps them quiet until there's something real to protect.

An engagement is considered active when **either**:

- `OVERWATCH_ENGAGEMENT_ACTIVE` is set to `1`/`true`/`yes`/`on` in the Claude Code
  environment (explicit toggle — always wins), **or**
- `OVERWATCH_CONFIG` points at an existing engagement config file in the Claude Code
  environment.

> **Important:** the `OVERWATCH_CONFIG` in your `.mcp.json` is set for the MCP **server**
> subprocess, which the hooks do **not** inherit. To arm the hooks, export the signal in
> the shell you launch Claude Code from for an engagement:
>
> ```bash
> export OVERWATCH_ENGAGEMENT_ACTIVE=1   # simplest; or: export OVERWATCH_CONFIG=/abs/path/engagement.json
> ```
>
> Leave it unset on dev checkouts (the default) and the hooks stay silent.

The soft reminders (`UserPromptSubmit`, `PostToolUse`) and the `Stop` block fail **open**
under the gate — a missed reminder is harmless. The `Bash` deny is best-effort regardless;
the real "never touch targets outside Overwatch" boundary is the MCP/engine layer (sole
credentials + egress control), not this regex.

## Closed gaps + what remains

An adversarial red-team of these hooks (28 findings) surfaced the surface below. Most are
now closed:

- ✅ **Highest-leverage drift surfaces covered.** `PreToolUse` on `Task` denies host-subagent
  delegation; `PostToolUse` on `Write`/`WebFetch` nudges results back into the graph.
- ✅ **The `Stop` check is turn-scoped.** It now keys on structured `tool_use` events since
  the last genuine human prompt, so a tool call from an earlier turn no longer suppresses the
  block on a later "answered from memory" turn.
- ✅ **`SessionStart` / `PreCompact` bootstrap.** Injects the `get_system_prompt(role="primary")`
  + `get_state()` reminder so the model reloads the dynamic prompt after compaction.

Still deliberately **not** addressed:

- **The `Bash` deny is porous** (and, by design, a speed bump not a boundary). `TARGET_TOOL_RE`
  is a closed allowlist beaten by a path prefix (`/usr/bin/nmap`), a quote, command
  substitution, a target hidden in a variable or an `-iL` file, or a tool not on the list.
  The real control is the MCP/engine egress layer (sole creds + scope validation), so chasing
  every regex bypass has low ROI — don't. (The `Task` deny is the meaningful enforcement.)

All hooks AND-gate on `isEngagementActive()` (silent on a dev checkout); add any new hook the
same way with a regression test in `src/__tests__/claude-hooks.test.ts`.

## Verify hooks are active

1. Restart Claude Code after editing `.claude/settings.json`.
2. Run `/hooks` in Claude Code and confirm these hooks are listed:
   - `UserPromptSubmit`
   - `PreToolUse` with matchers `Bash` and `Task`
   - `PostToolUse` with matchers `Bash` and `Write|WebFetch`
   - `SessionStart`, `PreCompact`
   - `Stop`
3. Ask Claude to run a harmless repo command like `git status`; it should work.
4. With the engagement-active gate armed (`export OVERWATCH_ENGAGEMENT_ACTIVE=1`), ask Claude to run raw target-facing Bash like `nmap 10.0.0.5`; it should be blocked and redirected to Overwatch tools. (Without the gate armed — a plain dev checkout — it is intentionally allowed.)

You can smoke-test the scripts outside Claude Code:

```bash
npm run hooks:smoke
```

Or run the underlying hook directly. The hooks are gated on an active engagement, so set
`OVERWATCH_ENGAGEMENT_ACTIVE=1` to exercise the firing path:

```bash
printf '%s' '{"tool_input":{"command":"nmap -sV 10.0.0.5"}}' \
  | OVERWATCH_ENGAGEMENT_ACTIVE=1 node .claude/hooks/overwatch-bash-guard.mjs

printf '%s' '{"tool_input":{"command":"rg hooks docs"}}' \
  | OVERWATCH_ENGAGEMENT_ACTIVE=1 node .claude/hooks/overwatch-bash-guard.mjs
```

The first command should print a JSON denial. The second should print nothing and exit successfully. (Without `OVERWATCH_ENGAGEMENT_ACTIVE=1`, both print nothing — the gate keeps the hooks silent on dev checkouts.)

Hooks are local Claude Code behavior. Tape attribution is server-side Overwatch behavior: when the in-process recorder starts, `/api/tape` and the activity log show `started_by` as `env`, `config`, or `dashboard`.

## Troubleshooting

- **Hooks do not show in `/hooks`:** your local `.claude/settings.json` probably does not include the `"hooks"` block, or Claude Code needs a restart.
- **MCP tools disappeared after copying the example:** your environment expected `mcpServers` in `.claude/settings.json`, but the example contains hooks only. Re-add your `mcpServers.overwatch` block or keep MCP config in `.mcp.json`.
- **A repo command was blocked:** update the Bash guard allow/target detection in `.claude/hooks/overwatch-hook-lib.mjs` and add a regression test in `src/__tests__/claude-hooks.test.ts`.
- **A target command was not blocked:** add that binary or target pattern to the hook library and add a regression test.
