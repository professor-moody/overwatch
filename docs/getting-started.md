# Getting Started

## Prerequisites

- **Node.js 20+**
- **Claude Code CLI** (`claude` command)

## Install

```bash
git clone https://github.com/professor-moody/overwatch.git
cd overwatch
npm install
npm run build
```

## Configure an Engagement

Create or edit `engagement.json` in the project root:

```json
{
  "id": "eng-001",
  "name": "Internal Pentest - Target Corp",
  "created_at": "2026-03-20T00:00:00Z",
  "scope": {
    "cidrs": ["10.10.10.0/24"],
    "domains": ["target.local"],
    "exclusions": ["10.10.10.254"],
    "hosts": []
  },
  "objectives": [
    {
      "id": "obj-da",
      "description": "Achieve Domain Admin on target.local",
      "target_node_type": "credential",
      "target_criteria": { "privileged": true, "cred_domain": "target.local" },
      "achieved": false
    }
  ],
  "opsec": {
    "name": "pentest",
    "max_noise": 0.7,
    "blacklisted_techniques": ["zerologon"],
    "notes": "Standard internal pentest."
  }
}
```

See [Configuration](configuration.md) for the full schema reference.

## Connect to Claude Code

Add Overwatch as an MCP server in your Claude Code config (`~/.claude/settings.json` or project-level `.claude/settings.json`):

```json
{
  "mcpServers": {
    "overwatch": {
      "command": "node",
      "args": ["<path-to-overwatch>/dist/index.js"],
      "env": {
        "OVERWATCH_CONFIG": "<path-to-engagement.json>",
        "OVERWATCH_SKILLS": "<path-to-overwatch>/skills"
      }
    }
  }
}
```

## Run

```bash
claude
```

Claude Code will connect to the Overwatch MCP server automatically. The `AGENTS.md` file in the project root provides the primary session instructions. Claude will call `get_state()` first to load the engagement briefing, then enter the main scoring loop.

## Verify Setup

Once connected, ask Claude to:

1. Call `get_state` — confirms the server is running and the engagement is loaded
2. Call `run_lab_preflight` — validates tool availability, graph health, and dashboard readiness
3. Call `check_tools` — shows which offensive tools are installed

If all three succeed, you're ready to start. See the [Operator Playbook](playbook/index.md) for step-by-step lab workflows.

## Troubleshooting

### Server Won't Start

**Missing config file:**
```
Error: Cannot find engagement config at ./engagement.json
```
Set `OVERWATCH_CONFIG` to the correct path, or create `engagement.json` in the project root.

**Invalid JSON:**
```
Error: Failed to parse engagement config
```
Validate your `engagement.json` with a JSON linter. Common issues: trailing commas, missing quotes.

**Missing skills directory:**
```
Warning: Skills directory not found
```
Set `OVERWATCH_SKILLS` to the correct path. Default is `./skills` relative to the project root.

### Dashboard Not Loading

- **Port conflict** — If port 8384 is in use, set `OVERWATCH_DASHBOARD_PORT` to another port
- **Dashboard disabled** — Check that `OVERWATCH_DASHBOARD_PORT` is not set to `0`
- **Blank page** — Open the browser console (F12) and check for JavaScript errors. The dashboard requires WebGL support.
- **WebSocket disconnects** — The dashboard auto-reconnects every 3 seconds and falls back to HTTP polling every 5 seconds. Check that no firewall or proxy is blocking WebSocket connections.

### Claude Code Can't Find Tools

**MCP config not loaded:**
Make sure `overwatch` is in your MCP config (`~/.claude/settings.json` or `.claude/settings.json`):

```json
{
  "mcpServers": {
    "overwatch": {
      "command": "node",
      "args": ["<absolute-path>/dist/index.js"]
    }
  }
}
```

!!! warning "Use absolute paths"
    The `args` and `env` values must use **absolute paths**. Relative paths resolve from Claude Code's working directory, which may not be the Overwatch project root.

**Build not run:**
If you see `Cannot find module dist/index.js`, run `npm run build` first.

### State File Issues

**Corrupted state file:**
The atomic write-rename mechanism prevents corruption during normal operation. If a state file is corrupted (e.g., disk full during write):

1. Delete the corrupted `state-<id>.json`
2. Check for snapshot files (`state-<id>.json.bak.*`) — the most recent valid one can be renamed
3. Restart the server — it will create a fresh graph from the engagement config

**Starting fresh:**
Delete `state-<id>.json` and restart. The server seeds a new graph from `engagement.json`.
