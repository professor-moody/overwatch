# Claude Code Hooks

Overwatch ships Claude Code hooks that keep Claude anchored to the engagement graph during long sessions. They are not optional polish: without them, the model can drift into raw Bash, summarize recon in prose, or answer from memory after compaction.

## What gets pulled

A `git pull` gives you the shared pieces:

- `.claude/hooks/*.mjs` — hook scripts.
- `.claude/settings.example.json` — copyable hook configuration.
- `.mcp.example.json` — copyable MCP server configuration.
- `CLAUDE.md`, `AGENTS.md`, and the generated system prompt updates.

It does **not** activate MCP or hooks by itself. `.mcp.json` and `.claude/settings.json` are intentionally gitignored because they contain machine-specific paths. Every operator creates both local files from the examples.

## `.mcp.json` vs `.claude/settings.json`

The recommended setup uses two local config files:

| File | Usually contains | Tracked? |
|------|------------------|----------|
| `.mcp.json` | MCP server definitions such as `mcpServers.overwatch` | No |
| `.claude/settings.json` | Claude Code project settings, including hooks; may also contain `mcpServers` | No |

For a new checkout:

```bash
cp .mcp.example.json .mcp.json
cp .claude/settings.example.json .claude/settings.json
```

Then edit `.mcp.json` with your absolute paths. Leave `.claude/settings.json` as hooks-only unless you intentionally keep MCP config there too.

Do **not** assume copying `.claude/settings.example.json` replaces `.mcp.json`. They are different files for different jobs.

## Required local setup

Use this exact two-file setup for a new checkout:

```bash
cp .mcp.example.json .mcp.json
cp .claude/settings.example.json .claude/settings.json
```

Then edit `.mcp.json`:

```json
{
  "mcpServers": {
    "overwatch": {
      "command": "node",
      "args": ["/absolute/path/to/overwatch/dist/index.js"],
      "env": {
        "OVERWATCH_CONFIG": "/absolute/path/to/overwatch/engagement.json",
        "OVERWATCH_SKILLS": "/absolute/path/to/overwatch/skills"
      }
    }
  }
}
```

Only use this alternate shape if your MCP server is configured in `.claude/settings.json` instead of `.mcp.json`:

```json
{
  "hooks": {
    "...": "copy from .claude/settings.example.json"
  },
  "mcpServers": {
    "overwatch": {
      "command": "node",
      "args": ["/absolute/path/to/overwatch/dist/index.js"],
      "env": {
        "OVERWATCH_CONFIG": "/absolute/path/to/overwatch/engagement.json",
        "OVERWATCH_SKILLS": "/absolute/path/to/overwatch/skills"
      }
    }
  }
}
```

If you already have `.claude/settings.json`, keep your existing content and paste in the full `"hooks"` object from `.claude/settings.example.json`.

Use absolute paths for MCP config whether it lives in `.mcp.json` or `.claude/settings.json`. Keep `${CLAUDE_PROJECT_DIR}` exactly as written in hook args; Claude Code expands it to this repo path.

## What the hooks do

| Hook | Behavior |
|------|----------|
| `UserPromptSubmit` | Adds a short Overwatch grounding reminder before each user prompt is processed. |
| `PreToolUse` on `Bash` | Blocks obvious target-facing raw Bash such as `nmap 10.0.0.5` or `curl http://target` and redirects Claude to Overwatch `run_tool`, `run_bash`, or session tools. |
| `PostToolUse` on `Bash` | Reminds Claude to turn discovery-looking output into graph state with `parse_output`, `report_finding`, or `ingest_json`. |
| `Stop` | Conservatively catches likely engagement drift when a turn did not use Overwatch tools and tells Claude to refresh with `get_state`. |

The Bash guard is intentionally narrow. It should not block normal repo work such as `git status`, `rg`, `npm test`, `npx tsc --noEmit`, or `mkdocs build --strict`.

## Verify hooks are active

1. Restart Claude Code after editing `.claude/settings.json`.
2. Run `/hooks` in Claude Code and confirm these hooks are listed:
   - `UserPromptSubmit`
   - `PreToolUse` with matcher `Bash`
   - `PostToolUse` with matcher `Bash`
   - `Stop`
3. Ask Claude to run a harmless repo command like `git status`; it should work.
4. Ask Claude to run raw target-facing Bash like `nmap 10.0.0.5`; it should be blocked and redirected to Overwatch tools.

You can smoke-test the scripts outside Claude Code:

```bash
npm run hooks:smoke
```

Or run the underlying hook directly:

```bash
printf '%s' '{"tool_input":{"command":"nmap -sV 10.0.0.5"}}' \
  | node .claude/hooks/overwatch-bash-guard.mjs

printf '%s' '{"tool_input":{"command":"rg hooks docs"}}' \
  | node .claude/hooks/overwatch-bash-guard.mjs
```

The first command should print a JSON denial. The second should print nothing and exit successfully.

Hooks are local Claude Code behavior. Tape attribution is server-side Overwatch behavior: when the in-process recorder starts, `/api/tape` and the activity log show `started_by` as `env`, `config`, or `dashboard`.

## Troubleshooting

- **Hooks do not show in `/hooks`:** your local `.claude/settings.json` probably does not include the `"hooks"` block, or Claude Code needs a restart.
- **MCP tools disappeared after copying the example:** your environment expected `mcpServers` in `.claude/settings.json`, but the example contains hooks only. Re-add your `mcpServers.overwatch` block or keep MCP config in `.mcp.json`.
- **A repo command was blocked:** update the Bash guard allow/target detection in `.claude/hooks/overwatch-hook-lib.mjs` and add a regression test in `src/__tests__/claude-hooks.test.ts`.
- **A target command was not blocked:** add that binary or target pattern to the hook library and add a regression test.
