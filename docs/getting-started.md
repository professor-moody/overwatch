# Getting Started

This page gets you from a clean clone to "AI is doing recon on my lab" in about five minutes. Anything not strictly required for that path is in [Advanced Setup](#advanced-setup) at the bottom.

!!! tip "Already past setup?"
    Jump to the [Operator Playbook](playbook/index.md) for what to actually do once Overwatch is running, or the [End-to-End Walkthrough](playbook/walkthrough.md) for a narrated lab engagement.

---

## Quick Start (5 minutes)

### 1. Install

```bash
git clone https://github.com/professor-moody/overwatch.git
cd overwatch
npm install
npm run build
```

Requires **Node.js 20+** and the **Claude Code CLI** (`claude`).

### 2. Pick a template

Overwatch ships with ready-made engagement templates in `engagement-templates/`. Copy the one closest to your engagement and edit the scope:

| Template | When to use |
|----------|-------------|
| `internal-pentest.json` | Internal AD-heavy network with standard noise tolerance |
| `external-assessment.json` | External attack surface, careful with noise |
| `red-team.json` | Stealth-first, approval-gated, minimal footprint |
| `assumed-breach.json` | Starting with a foothold credential |
| `cloud-assessment.json` | AWS / Azure / GCP focus |
| `ctf.json` | Lab / HTB / CTF — no constraints |

```bash
cp engagement-templates/internal-pentest.json engagement.json
```

Then open `engagement.json` and fill in **just two things**:

```jsonc
{
  "scope": {
    "cidrs": ["10.10.10.0/24"],          // your target network
    "domains": ["target.local"],          // your target AD domain
    "exclusions": []
  }
  // leave the rest alone for now
}
```

That's enough to start. The full schema is in [Configuration](configuration.md) when you want it.

### 3. Wire Overwatch into Claude Code

Add this block to `~/.claude/settings.json` (or your project's `.claude/settings.json`). **Use absolute paths** — relative paths break.

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

### 4. Launch

```bash
cd /absolute/path/to/overwatch
claude
```

Claude Code starts the Overwatch MCP server automatically and reads [`AGENTS.md`](https://github.com/professor-moody/overwatch/blob/main/AGENTS.md) as the primary session prompt. The first thing the AI does is call `get_state()` to load the engagement briefing.

### 5. Open the dashboard

In another tab: **<http://localhost:8384>**

You'll see the live engagement graph, frontier items, agent activity, and discovered credentials in real time as the AI works. It starts automatically — no extra setup.

**You're ready.** Jump to [What to say next](#what-to-say-next).

---

## What to say next

Once `claude` is running and connected, the AI is waiting for direction. Some good opening prompts:

> **"Run lab preflight, then start the bootstrap phase."**
> Verifies tooling and graph health, then begins reconnaissance against the scope you defined.

> **"What's on the frontier? Pick the highest-leverage item and execute it."**
> Hands the wheel to the AI and lets it work the priority queue.

> **"I just stood up Responder on `0.0.0.0:445`. Register it as a mock_service and watch for captures."**
> Wires operator infrastructure into the graph. See [Operator Infrastructure](playbook/operator-infra.md).

> **"Show me a path from any owned credential to Domain Admin."**
> Triggers `find_paths` and the AI explains what's missing.

You're the operator giving direction; the AI handles the `validate_action` → `log_action_event` → execute → `parse_output` → `report_finding` bookkeeping for you.

For a fully narrated example, read the [End-to-End Walkthrough](playbook/walkthrough.md).

---

## Verify Setup

If something looks off, ask Claude:

1. **`get_state`** — confirms the server is up and the engagement loaded.
2. **`run_lab_preflight`** — checks tools, graph health, dashboard.
3. **`check_tools`** — lists which offensive tools are installed (`nmap`, `nxc`, `bloodhound-python`, etc.).

All three returning clean output means you're good.

---

## Advanced Setup

Skip this section unless you actually need it.

### HTTP / SSE transport (remote, multi-client)

Default transport is stdio (Claude Code talks directly to a child process). For remote deployments, dashboards talking to the same server, or a long-running shared instance:

```bash
OVERWATCH_TRANSPORT=http npm start
# or
node dist/index.js --http
```

Binds `127.0.0.1:3000` by default. The MCP endpoint is `POST /mcp`; sessions are tracked via the `mcp-session-id` header.

| Variable | Default | Description |
|----------|---------|-------------|
| `OVERWATCH_HTTP_PORT` | `3000` | HTTP server port |
| `OVERWATCH_HTTP_HOST` | `127.0.0.1` | Bind address |

### Audit trail (defensible evidence)

Two opt-in features turn Overwatch into a tamper-evident, replayable system of record. Both are off by default and free to ignore for a lab or CTF.

1. **Hash-chained activity log** — set `"hash_chain_enabled": true` in `engagement.json`. Every system + agent event gets `prev_hash` and `event_hash`; `verify_activity_chain` proves the log hasn't been edited.
2. **JSON-RPC tape proxy** — run the AI client through `overwatch-mcp-tape` to capture every wire-level MCP frame. After the engagement, `register_tape_session` imports the tape and links it to the activity log. Now you can prove the AI called `validate_action` before every `run_bash`.

Details in [Concepts — Audit Trail](concepts.md#audit-trail).

### Dashboard configuration

The dashboard is on by default at `http://localhost:8384`. To change the port or token-protect it:

| Variable | Default | Description |
|----------|---------|-------------|
| `OVERWATCH_DASHBOARD_PORT` | `8384` | Set to `0` to disable |
| `OVERWATCH_DASHBOARD_TOKEN` | *(none)* | If set, requires `?token=<value>` |

Full feature list, keyboard shortcuts, and API endpoints in the [Dashboard Guide](dashboard.md).

### Writing engagement.json from scratch

If none of the templates fit, the full schema is in [Configuration](configuration.md). The fields you'll always need: `id`, `name`, `scope`, `objectives`, `opsec`. Everything else has sensible defaults.

---

## Troubleshooting

??? failure "Server won't start: Cannot find engagement config"
    Set `OVERWATCH_CONFIG` to an absolute path, or create `engagement.json` in the directory you launched from.

??? failure "Server won't start: Failed to parse engagement config"
    Validate the JSON. Common culprits: trailing commas, unquoted keys, smart quotes from copy-paste.

??? failure "Claude Code can't find Overwatch tools"
    Open `~/.claude/settings.json` and confirm:

    - The `overwatch` block is present under `mcpServers`.
    - `args` and `env` use **absolute** paths (not `~` or relative).
    - You ran `npm run build` so `dist/index.js` exists.

??? failure "Dashboard won't load"
    - Port conflict? Set `OVERWATCH_DASHBOARD_PORT` to something else.
    - Blank page? Open browser console (F12) — the dashboard needs WebGL.
    - WebSocket disconnects? It auto-reconnects every 3s and falls back to HTTP polling. Check for a proxy/firewall blocking WS.

??? failure "Corrupted state file"
    Atomic write-rename normally prevents this. If it happens (disk full mid-write):

    1. Delete the broken `state-<id>.json`.
    2. Look for snapshot files (`state-<id>.json.bak.*`) and rename the most recent valid one.
    3. Or just restart — Overwatch reseeds the graph from `engagement.json`.

??? tip "Starting fresh"
    Delete `state-<id>.json` and restart. The server rebuilds the graph from `engagement.json` on next launch.
