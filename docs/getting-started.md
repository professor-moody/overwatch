# Getting Started

This page gets you from a clean clone to "AI is doing recon on my lab" in about five minutes. There are [**two ways to run Overwatch**](#two-ways-to-run-overwatch). Setup defaults to the shared daemon because it is the straightforward path for terminal Claude, the dashboard, the CLI, and dispatched agents to work together without competing writers. Stdio remains an explicit solo compatibility mode.

!!! tip "Already past setup?"
    Jump to the [Operator Playbook](playbook/index.md) for what to actually do once Overwatch is running, or the [End-to-End Walkthrough](playbook/walkthrough.md) for a narrated lab engagement. Working a specific engagement type? Start from an **Assessment Guide**: [Web Assessment](assessments/web-assessment.md) or [Internal AD / Network](assessments/internal-ad-network.md).

---

## Two ways to run Overwatch

Overwatch is **one engine** — the same graph, tools, and dashboard either way. What differs is how clients attach to it:

| | **stdio** *(solo compatibility)* | **HTTP daemon** *(recommended default)* |
|---|---|---|
| Setup/start | `npm run setup:stdio`, then `claude` launches Overwatch | `npm run setup`, then `npm run daemon:start` once |
| Lifetime | Lives and dies with that one `claude` session | Long-lived; survives client restarts |
| Clients | One Claude Code session | Many at once — the dashboard, a terminal `claude`, the [`overwatch` CLI](cli.md), and dispatched sub-agents, all on the *same* engagement |
| Dashboard | Yes, on `:8384` | Yes, on `:8384` |
| Best for | Solo operator, fastest first run | Dashboard-driven ops, multi-agent dispatch, the `overwatch` CLI, remote/shared instances |

Both bring up the live dashboard. Keep the default **daemon** whenever you use the dashboard, CLI, planner, dispatched agents, or more than one Claude client. Select **stdio** explicitly only when one Claude session should own the entire process.

---

## Quick Start (shared daemon · 5 minutes) { #quick-start-5-minutes }

### 1. Install

```bash
git clone https://github.com/professor-moody/overwatch.git
cd overwatch
npm install
npm run setup -- --template ctf --name "My Lab" --cidr 10.10.10.0/24
npm run daemon:start
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

On a fresh checkout this creates a local `engagement.json` from the template,
fills in the CIDR, adds a fresh `engagement_nonce`, and writes an authenticated
HTTP `.mcp.json`, `.overwatch-mcp-token`, `.overwatch-runtime/profile.json`, and
`.claude/settings.json`. `npm run daemon:start` returns after the verified
daemon is ready, so you can open `http://127.0.0.1:8384` and start `claude` in
the same terminal. Re-running the default `npm run setup` keeps an existing
`engagement.json`; it only refreshes the shared-client wiring. `--force` does
not override that safety rule.

Each setup-owned file is published atomically. If setup reports a late local
wiring write failure, fix the filesystem error and rerun the same setup command;
it converges the token/profile/client files without replacing engagement data.
Do not delete config, state, WAL, evidence, or reports to repair client wiring.

If `engagement.json` is missing while state, WAL, snapshots, migration backups,
evidence, reports, or recovery intents remain, setup does not seed an empty
engagement over them. A single recoverable state is wired explicitly for a
read-only recovery launch. Ambiguous or incomplete artifacts stop setup before
it writes client wiring; restore the matching config or set
`OVERWATCH_STATE_FILE` to the state you intend to inspect.

Before the first daemon start, you may instead copy `engagement.example.json`
or a template to `engagement.json` and fill in **just two things**:

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

After state exists, do not edit the active file out of band. Use the dashboard,
CLI, or MCP configuration commands so file, runtime, and durable state advance
together. If an external edit is detected, Overwatch starts read-only and asks
you to reconcile the exact file/state hashes instead of guessing.

!!! tip "Or set it up conversationally — no JSON"
    Once Overwatch is wired into Claude Code (including a genuinely fresh empty
    bootstrap engagement via `OVERWATCH_BOOTSTRAP=1`), you can just **tell the model**: *"set up an
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
| `.mcp.json` | Connects Claude to the shared Overwatch MCP daemon. |
| `.claude/settings.json` | Enables Claude Code hooks that keep Claude using Overwatch correctly. |

Both files are local and gitignored. The setup command already created them.
The daemon form looks like this:

```json
{
  "mcpServers": {
    "overwatch": {
      "type": "http",
      "url": "http://127.0.0.1:3000/mcp",
      "headers": { "Authorization": "Bearer <local setup token>" }
    }
  }
}
```

The default daemon setup preserves any other MCP servers already present in this
file and updates only `mcpServers.overwatch`.

!!! important "Do not skip hooks"
    Hooks keep Claude from drifting away from Overwatch during long sessions. They block raw target-facing Bash and remind Claude to put discoveries into the graph. Full setup and verification steps are in [Claude Code Hooks](claude-hooks.md).

### 4. Launch

```bash
cd /absolute/path/to/overwatch
npm run daemon:start
```

The command returns only after every configured runtime endpoint reports `READY` (or a truthful
`RECOVERY READ-ONLY` state). Continue in the same terminal:

```bash
cd /absolute/path/to/overwatch
claude
```

Startup verifies that the compiled runtime, engagement, and state family match
the current checkout/profile. A stale or missing build is rebuilt only when no
daemon is live; this prevents an old backend from serving newly replaced
dashboard assets. `npm run doctor` reports the same identity without changing
engagement files.

If you run doctor before the first start, its daemon-not-running warning is
expected. With the daemon active, run `npm run doctor`
to verify its PID/build/state identity, MCP token, Claude CLI
worker flags, and port ownership.

Terminal Claude connects to the already-running Overwatch engine and reads
[`AGENTS.md`](https://github.com/professor-moody/overwatch/blob/main/AGENTS.md)
as the primary session prompt. The dashboard, CLI, Claude, and dispatched agents
now share the same durable commands, state, leases, and playbook ownership.

Dashboard-managed Claude workers are separate headless processes, not copies of
your terminal session. Each gets a temporary task-specific MCP configuration,
a restricted tool surface, strict MCP isolation, user-only Claude settings, and
no Claude session persistence. User settings remain available for
authentication, while this project's terminal hooks/settings, MCP servers, and
resume history do not leak into the worker. You can therefore keep using
terminal Claude while deploying agents from the dashboard.

### 5. Open the dashboard

In another tab: **<http://localhost:8384>**

You'll see the live engagement graph, frontier items, agent activity, and discovered credentials in real time as the AI works.

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

First run the local/runtime check (with the daemon active, it also verifies the
running build):

```bash
npm run doctor
```

Then ask Claude:

1. **`get_state`** — confirms the server is up and the engagement loaded.
2. **`run_lab_preflight`** — checks tools, graph health, dashboard.
3. **`check_tools`** — lists which offensive tools are installed (`nmap`, `nxc`, `bloodhound-python`, etc.).

All three returning clean output means you're good.

### After pulling an update

Pull the update, then use the state-preserving lifecycle command:

```bash
git pull --ff-only origin main
npm run upgrade
npm run doctor
```

For the first update from a version that has no
`.overwatch-runtime/profile.json`, stop the old foreground/stdio owner and run
`npm run setup` once before `npm run upgrade`. The managed lifecycle refuses to
infer writable state without that profile. Setup inventories and preserves the
existing config, state/WAL/snapshots, evidence, and reports while recording the
selected paths; it does not reseed the engagement.

`upgrade` first verifies that this is a buildable source checkout with its lock
file intact and checks migration readiness while the daemon stays available.
It then verifies and gracefully stops the recorded owner and repeats the
state/WAL check against the frozen file family. Only a successful second check
permits install/build. A cross-process state-family reservation remains held
through install/build; the replacement daemon publishes durable runtime
ownership before that reservation is released. A second checkout or direct
runtime therefore cannot write the engagement during the upgrade gap. If the
frozen check fails, the reservation is released and the lifecycle attempts to
restart the unchanged compiled daemon. A competing physical owner in that
legacy-runtime handoff window makes restart fail closed; it never authorizes a
second writer or modifies engagement data.
Packaged installations fail before downtime
and must be updated through the package/source manager that installed them. It does not replace
`engagement.json`, state/WAL/snapshots, evidence, or reports. Hard-reload the
dashboard after the new daemon starts. If `doctor` identifies another PID or a
different build, stop that owner instead of starting a second daemon.

If startup reports read-only recovery, preserve the engagement files and run
`overwatch recovery` (or inspect **Settings → Recovery**). A configuration
divergence is an explicit reconciliation decision; it is not a reason to delete
the current graph or reseed the engagement. `npm run doctor` reports which
preserved state was selected or why explicit selection is required; never use
setup flags to overwrite recovery artifacts.

---

## Run as a persistent daemon (HTTP)

The Quick Start already runs Overwatch as an **HTTP daemon** so the dashboard,
the [`overwatch` CLI](cli.md), terminal Claude, and dispatched sub-agents share
the same live engagement. This section explains the wiring and how to switch an
older solo stdio setup.

The default setup already wires Claude to this endpoint and creates the same
stable token the daemon will reuse:

```bash
cd /absolute/path/to/overwatch
npm run daemon:start                # detached; returns after READY
npm run start:daemon                # foreground equivalent
npm run daemon:status
```

Lifecycle commands are identity-verified against the persisted runtime profile
and the daemon's state-family lease:

| Command | Behavior |
|---|---|
| `npm run daemon:start` | Detached start; exact READY daemon is a successful no-op |
| `npm run daemon:status` | Shows PID, lifecycle, engagement, state path, endpoints, build match, and recovery state |
| `npm run daemon:stop` | Requests authenticated graceful shutdown only after PID/start/instance/state identity all match; waits for durable acknowledgement (verified POSIX runtimes retain a SIGTERM compatibility fallback) |
| `npm run daemon:restart` | Verified stop, freshness build if needed, detached start |
| `npm run daemon -- logs` | Shows the managed log path and recent output |
| `npm run start:daemon` | Foreground form for service managers or interactive diagnostics |
| `npm run upgrade` | Dependency/live state preflight, verified stop, authoritative frozen state/WAL preflight, `npm ci`, build, and detached restart after you pull |

The first upgrade preflight runs before downtime; a blocked early check leaves
the current daemon running. The authoritative frozen check runs after stop and,
if blocked, attempts to restart the unchanged compiled daemon before any
install/build. A competing physical owner can make that availability recovery
fail closed, but cannot become a second writer.
After that check passes, a cross-process state-family reservation remains held
through dependency installation and build. Startup hands the reservation to
the replacement runtime by publishing the new durable owner before release;
competing checkouts and direct runtimes fail closed during this interval.
The lifecycle never runs `git pull`
and never rewrites engagement configuration,
state/WAL/snapshots, evidence, reports, tapes, or migration backups. If stop
cannot prove the live PID's physical identity, it fails closed and signals
nothing. Start, stop, restart, and upgrade are serialized by a local lifecycle
lock. A failed final flush is not reported as a clean stop and blocks automatic
restart or upgrade until recovery is inspected.

It binds two loopback ports:

| Port | Serves | Who connects |
|------|--------|--------------|
| `127.0.0.1:3000` | MCP endpoint (`POST /mcp`) | Claude Code, headless sub-agents |
| `127.0.0.1:8384` | Dashboard + `/api` | The browser dashboard, the `overwatch` CLI |

Every MCP client gets its own `mcp-session-id`, but they all read and write the **same** graph, sessions, and approval queue — that's what lets the dashboard, a terminal Claude, the CLI, and sub-agents coordinate on one engagement.

### Point Claude Code at the daemon

If you started with solo stdio mode, switch safely without replacing the
engagement. First exit the terminal Claude session that owns the stdio runtime;
setup deliberately refuses to change profiles while that writer is live. Then
persist the shared profile and start it once:

```bash
npm run setup
npm run daemon:start
npm run doctor
```

```json
{
  "mcpServers": {
    "overwatch": {
      "type": "http",
      "url": "http://127.0.0.1:3000/mcp",
      "headers": { "Authorization": "Bearer <local setup token>" }
    }
  }
}
```

The `/mcp` endpoint requires a bearer token by default, even on loopback.
Setup writes it into the local `.mcp.json` and stores the same value `0600` in
`.overwatch-mcp-token`; daemon restarts reuse that file automatically. You can
still provide `OVERWATCH_MCP_TOKEN` explicitly while the daemon is stopped and
rerun setup; setup publishes that same authority to the token file and client
configuration so startup can prove they converge.

For a non-loopback dashboard, setup likewise stores the dashboard credential in
a `0600` token file and records only that file's path in the runtime profile.
Later `start`, `status`, `stop`, and `upgrade` commands retain remote
authentication without requiring the original setup shell environment.

| Variable | Default | Description |
|----------|---------|-------------|
| `OVERWATCH_HTTP_PORT` | `3000` | MCP HTTP port |
| `OVERWATCH_HTTP_HOST` | `127.0.0.1` | MCP bind address |
| `OVERWATCH_MCP_TOKEN` | *(auto-generated)* | Bearer token required on `/mcp` |

### Operate from the terminal — the `overwatch` CLI

With the daemon up, the **`overwatch` CLI** drives the same engagement over the `/api` surface on `:8384` — read commands (`status`, `frontier`, `findings`, `agents`, `approvals`) and write commands (`approve`, `deny`, `answer`, `deploy`, `dispatch`), with opt-in compact output. It's a Claude-independent operator surface: watch and steer from a second pane while the model works.

```bash
npm run overwatch -- status          # or, after `npm link`: overwatch status
```

The CLI talks to `:8384` (not the MCP port), which is loopback-open by default — protect it with `OVERWATCH_DASHBOARD_TOKEN`, and pass `--url` / `OVERWATCH_URL` (plus `--token`) to reach a remote daemon. Full command reference: [Terminal Operator CLI](cli.md).

---

## Advanced Setup

Skip this section unless you actually need it.

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

Runtime-profile changes are deliberate: run `npm run daemon:stop`, rerun setup
with the new variables, then `npm run daemon:start`. Setup refuses to change
ports or credentials underneath a live state owner.

Full feature list, keyboard shortcuts, and API endpoints in the [Dashboard Guide](dashboard.md).

### Set up an engagement conversationally (no hand-edited JSON)

You don't have to write `engagement.json` by hand. With a server running, just ask Claude to build one and it uses MCP tools to do it:

> **"Set up an engagement named Acme Q3 scoped to 10.10.0.0/16, objective 'reach Domain Admin', quiet OPSEC."**

Under the hood that's `create_engagement` (which validates scope/OPSEC and writes `engagements/<id>.json`, returning activation steps), plus `add_objective`, `set_opsec` (confirm-gated, warns when you loosen posture), and `update_scope`. See the [Engagement Setup tools](tools/index.md). New engagements activate on restart (create-then-start), so there's no live reload to reason about.

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
    - The default daemon entry has an `http://127.0.0.1:<port>/mcp` URL and a Bearer header.
    - `npm run daemon:status` reports the intended engagement and state path as READY.
    - For explicit solo stdio only, the entry runs `scripts/daemon-lifecycle.mjs run-stdio` with the absolute runtime-profile path.

??? failure "Claude hooks don't show up"
    Open `.claude/settings.json` and confirm:

    - It exists in this repo.
    - It contains the `"hooks"` block from `.claude/settings.example.json`.
    - You restarted Claude Code after editing it.
    - `/hooks` lists `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `SessionStart`, `PreCompact`, and `Stop`.

??? failure "Dashboard won't load"
    - Port conflict? Stop the verified owner, rerun setup with `OVERWATCH_DASHBOARD_PORT=<port>`, then start it again.
    - Blank page? Open browser console (F12) — the dashboard needs WebGL.
    - WebSocket disconnects? It reconnects with bounded 1/2/4/8/16/30-second backoff and falls back to HTTP polling. Check for a proxy/firewall blocking WS.

??? failure "Corrupted state file"
    Do not delete or rename the primary state, WAL, `.snapshots/`, config
    intents, migration intents, or quarantine files. Restart recovery evaluates
    all retained bases and replays only a contiguous valid WAL prefix; if it
    cannot prove a complete result, Overwatch stays inspectable and read-only.

    1. Stop target execution.
    2. Copy the complete engagement directory.
    3. Run `overwatch state migrate --check --state-file <path> --config-file <path>`
       against the stopped engagement or its copy.
    4. Inspect `overwatch recovery` when the daemon can start.
    5. Restore a verified migration backup or repair a copied bundle rather
       than reseeding over the original bytes.

??? tip "Starting fresh"
    Preserve the old engagement and select a genuinely new state path:

    ```bash
    cp -a /path/to/engagement /path/to/engagement-before-reset
    export OVERWATCH_STATE_FILE=/path/to/engagement/state-<id>-fresh-$(date +%Y%m%d%H%M%S).json
    # Restart Overwatch with the same validated engagement.json
    ```

    A new path creates a fresh graph without making the old state, WAL,
    snapshots, evidence, reports, or migration backups unreachable.
