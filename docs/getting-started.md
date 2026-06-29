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
npm run setup -- --template ctf --name "My Lab" --cidr 10.10.10.0/24
npm run build
npm run doctor
```

Requires **Node.js 20+** and the **Claude Code CLI** (`claude`).

You will also need the offensive tools you plan to use (nmap, nxc, certipy,
sqlmap, etc.) installed on PATH. See [Prerequisites](prerequisites.md) for
grouped install commands by engagement type — install only the group(s) you
need, then use the `check_tools` MCP tool as a preflight.

### 2. Pick a template

Start with the general-purpose **`ctf.json`** template — it has no OPSEC constraints, auto-approves everything, and works for any lab, CTF, HTB box, or "I just want to try Overwatch" scenario. It's the friendliest first run.

```bash
npm run setup -- --template ctf --name "My Lab" --cidr 10.10.10.0/24
```

This creates a local `engagement.json` from the template, fills in the CIDR,
adds a fresh `engagement_nonce`, and writes `.mcp.json` / `.claude/settings.json`
with absolute paths. Re-run with `--force` only when you intentionally want to
replace existing local config.

If you prefer to edit manually, copy `engagement.example.json` or a template to
`engagement.json` and fill in **just two things**:

```jsonc
{
  "scope": {
    "cidrs": ["10.10.10.0/24"],          // your target network or single IP
    "domains": [],                        // leave empty if no AD; fill in if you have one
    "exclusions": []
  }
  // leave the rest alone for now
}
```

That's enough to start. Live graph state is stored separately in
`state-<engagement-id>.json` beside the config. The full schema is in
[Configuration](configuration.md) when you want it.

!!! tip "Or set it up conversationally — no JSON"
    Once Overwatch is wired into Claude Code (even on an empty bootstrap engagement
    via `OVERWATCH_BOOTSTRAP=1`), you can just **tell the model**: *"set up an
    engagement scoped to 10.10.10.0/24, objective domain-admin, quiet OPSEC."* It
    calls [`create_engagement`](tools/create-engagement.md), which writes a
    validated `engagements/<id>.json` and returns the activation steps
    (**create-then-start**: set `OVERWATCH_CONFIG` to it → restart → confirm with
    [`list_engagements`](tools/list-engagements.md)). After it's running, adjust the
    active engagement with [`add_objective`](tools/add-objective.md),
    [`set_opsec`](tools/set-opsec.md), and [`update_scope`](tools/update-scope.md) —
    all without touching the file.

??? info "Other templates (for real engagements)"
    Once you've gotten comfortable with the basics, swap in the template that matches your engagement profile. Each one preconfigures sensible objectives, OPSEC posture, and the right `profile` field so preflight checks the right tools.

    | Template | What it does | Use when |
    |----------|-------------|----------|
    | **`ctf.json`** | No OPSEC, auto-approve, network profile, single "compromise everything" objective | Labs, CTFs, HTB, kicking the tires |
    | **`internal-pentest.json`** | `goad_ad` profile, Domain Admin + DCSync objectives, `max_noise=0.7`, `approve-critical` mode | Internal AD-heavy networks where you can be moderately loud |
    | **`external-assessment.json`** | `web_app` profile, "initial access" objective, conservative noise, full approval gates | External attack surface against web apps and cloud perimeter |
    | **`red-team.json`** | `hybrid` profile, full kill-chain objectives (initial access → persistence → lateral → exfil), strict OPSEC, low-and-slow | Stealth engagements with detection-aware adversary simulation |
    | **`assumed-breach.json`** | `network` profile, lateral movement + data access objectives, post-foothold posture | Starting from a known foothold credential or compromised host |
    | **`cloud-assessment.json`** | `cloud` profile, AWS/Azure/GCP scope fields, IAM-escalation + cross-account-pivot objectives | Multi-account cloud security assessments |

    All templates live in `engagement-templates/`. Open the one closest to your engagement, read the `description` and `objectives` fields, and tweak as needed.

### 3. Wire Overwatch into Claude Code

Use two local config files:

| File | Purpose |
|------|---------|
| `.mcp.json` | Starts the Overwatch MCP server. |
| `.claude/settings.json` | Enables Claude Code hooks that keep Claude using Overwatch correctly. |

Both files are local and gitignored because they contain machine-specific paths.

First, create `.mcp.json`:

```bash
cp .mcp.example.json .mcp.json
```

Edit `.mcp.json` with absolute paths:

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

Then enable the Claude hooks:

```bash
cp .claude/settings.example.json .claude/settings.json
```

That is the recommended setup: `.mcp.json` contains `mcpServers`, and `.claude/settings.json` contains `hooks`.

!!! important "Do not skip hooks"
    Hooks keep Claude from drifting away from Overwatch during long sessions. They block raw target-facing Bash and remind Claude to put discoveries into the graph. Full setup and verification steps are in [Claude Code Hooks](claude-hooks.md).

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
    Open `.mcp.json` and confirm:

    - The `overwatch` block is present under `mcpServers`.
    - `args` and `env` use **absolute** paths (not `~` or relative).
    - You ran `npm run build` so `dist/index.js` exists.

??? failure "Claude hooks don't show up"
    Open `.claude/settings.json` and confirm:

    - It exists in this repo.
    - It contains the `"hooks"` block from `.claude/settings.example.json`.
    - You restarted Claude Code after editing it.
    - `/hooks` lists `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, and `Stop`.

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
