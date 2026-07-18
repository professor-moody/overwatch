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
npm ci
npm run build
npm run setup
npm run daemon:start
npm run doctor
OVERWATCH_ENGAGEMENT_ACTIVE=1 claude
```

Requires **Node.js 20+** and the **Claude Code CLI** (`claude`).

You will also need the offensive tools you plan to use (nmap, nxc, certipy,
sqlmap, etc.) installed on PATH. See [Prerequisites](prerequisites.md) for
grouped install commands by engagement type — install only the group(s) you
need, then use the `check_tools` MCP tool as a preflight.

### 2. Create or preserve the active engagement

Plain `npm run setup` is the canonical path. On a genuinely fresh checkout it
creates the active `engagement.json`; on an established checkout it preserves
that file and refreshes machine-local wiring. Setup does not start the daemon.

If this is the first setup and you already know the initial scope, you can use
the following command **in place of** the plain `npm run setup` in step 1. It
selects the general-purpose **`ctf.json`** template and seeds it in the same
call:

```bash
npm run setup -- --template ctf --name "My Lab" --cidr 10.10.10.0/24
```

On a fresh checkout this creates a local `engagement.json` from the template,
fills in the CIDR, adds a fresh `engagement_nonce`, and writes an authenticated
HTTP `.mcp.json`, `.overwatch-mcp-token`, `.overwatch-runtime/profile.json`, and
`.claude/settings.json`. `npm run daemon:start` returns after the verified
daemon is ready, so you can open `http://127.0.0.1:8384` and start terminal
Claude in the same terminal. For engagement work, launch it as
`OVERWATCH_ENGAGEMENT_ACTIVE=1 claude`; a plain `claude` connects successfully
but leaves the engagement-only anti-drift hooks inactive. Re-running the
default `npm run setup` keeps an existing
`engagement.json`; it only refreshes the shared-client wiring. `--force` does
not override that safety rule. `--template`, `--name`, `--cidr`, and `--domain`
are fresh-creation inputs and do not edit an established engagement.

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

!!! tip "Configure the current engagement without editing JSON"
    After startup, tell Claude *"add 10.10.10.0/24 to the current scope, add the
    objective domain-admin, and use quiet OPSEC."* It uses
    [`update_scope`](tools/update-scope.md),
    [`add_objective`](tools/add-objective.md), and
    [`set_opsec`](tools/set-opsec.md). In the dashboard, use **Console → Add
    Targets** for scope and **Settings** for objectives and OPSEC. These active
    edits update the live engine, durable state, and `engagement.json` together.

??? info "Other templates (for a fresh real engagement)"
    Before the initial setup, choose the template that matches your engagement
    profile. Each one preconfigures sensible objectives, OPSEC posture, and the
    right `profile` field so preflight checks the right tools. Setup flags do
    not replace or retarget an engagement that already exists.

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
OVERWATCH_ENGAGEMENT_ACTIVE=1 claude
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

Terminal Claude connects to the already-running Overwatch engine. At runtime,
`get_system_prompt(role="primary")` is authoritative because it includes the
current engagement, OPSEC posture, and live tool registry.
[`AGENTS.md`](https://github.com/professor-moody/overwatch/blob/main/AGENTS.md)
is the offline fallback. The dashboard, CLI, Claude, and dispatched agents now
share the same durable commands, state, leases, and playbook ownership.

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

For the normal start/stop routine, concurrent clients, approval timeout
semantics, planner diagnosis, end-of-day choices, and safe backups, use the
[Daily Operation](daily-operations.md) guide.

---

## Shared daemon reference

The Quick Start already runs Overwatch as an **HTTP daemon** so the dashboard,
the [`overwatch` CLI](cli.md), terminal Claude, and dispatched sub-agents share
the same live engagement. Setup has already written the required profile, MCP
token, and client entry; normal starts do not need transient path overrides.

Lifecycle commands are identity-verified against the persisted runtime profile
and the daemon's state-family lease:

| Command | Behavior |
|---|---|
| `npm run daemon:start` | Detached start; exact READY daemon is a successful no-op |
| `npm run daemon:status` | Shows PID, lifecycle, engagement, state path, endpoints, build match, and recovery state |
| `npm run daemon:stop` | Verified graceful shutdown; interrupts managed workers/planners and aborts their pending approvals before durable flush |
| `npm run daemon:restart` | Verified stop with the same workload interruption semantics, freshness build if needed, detached start |
| `npm run daemon -- logs` | Shows the managed log path and recent output |
| `npm run start:daemon` | Foreground form for service managers or interactive diagnostics |
| `npm run upgrade` | Dependency/live state preflight, verified stop, authoritative frozen state/WAL preflight, `npm ci`, build, and detached restart after you pull |

For exact shutdown, interrupted-work, upgrade, and backup semantics, use
[Daily Operation](daily-operations.md). Closing the browser or terminal Claude
does not stop the daemon. An intentional stop preserves durable state and
artifacts but does not reconstruct a live model turn.

It binds two loopback ports:

| Port | Serves | Who connects |
|------|--------|--------------|
| `127.0.0.1:3000` | MCP endpoint (`POST /mcp`) | Claude Code, headless sub-agents |
| `127.0.0.1:8384` | Dashboard + `/api` | The browser dashboard, the `overwatch` CLI |

Every MCP client gets its own `mcp-session-id`, but they all use the **same**
graph, sessions, approvals, leases, and playbook ownership.

### Return from solo stdio mode

If you started with solo stdio mode, exit the terminal Claude session that owns
it before returning to the shared profile. Setup preserves the engagement while
rewriting machine-local runtime and client wiring:

```bash
npm run setup
npm run daemon:start
npm run doctor
```

The `/mcp` endpoint requires a bearer token by default, even on loopback.
Setup writes it into the local `.mcp.json` and stores the same value `0600` in
`.overwatch-mcp-token`; daemon restarts reuse that file automatically. Setup
and lifecycle commands verify the profile, token file, and client entry agree.

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

New engagements enable the hash-chained activity log by default; the chain is
tamper-evident even without a signing key. Checkpoint signing and JSON-RPC tape
recording remain opt-in. Prefer the dashboard's in-process Tape control for the
shared daemon; the standalone `overwatch-mcp-tape` proxy is only for an
intentional isolated stdio session.

Details in [Concepts — Audit Trail](concepts.md#audit-trail).

### Dashboard configuration

The dashboard is on by default at `http://localhost:8384`. To change the port or token-protect it:

| Variable | Default | Description |
|----------|---------|-------------|
| `OVERWATCH_DASHBOARD_PORT` | `8384` | Set to `0` to disable |
| `OVERWATCH_DASHBOARD_TOKEN` | *(none on loopback; generated for non-loopback)* | Optional setup-time override; remote browsers land with `?token=<value>` |

Runtime-profile changes are deliberate: run `npm run daemon:stop`, rerun setup
with the new variables, then `npm run daemon:start`. Setup refuses to change
ports or credentials underneath a live state owner.

Full feature list, keyboard shortcuts, and API endpoints in the [Dashboard Guide](dashboard.md).

### Create another engagement configuration

The dashboard's **New Engagement** flow and the `create_engagement` MCP tool can
build another validated configuration without hand-editing JSON:

> **"Set up an engagement named Acme Q3 scoped to 10.10.0.0/16, objective 'reach Domain Admin', quiet OPSEC."**

`create_engagement` validates scope and OPSEC and writes
`engagements/<id>.json`. The new configuration is **inactive**: it does not
replace or reload the current daemon's engagement. `list_engagements` can show
both configurations, but it does not switch between them, and dashboard
engagement switching is not currently supported. To change the current
engagement, use **Add Targets**, **Settings**, `update_scope`, `add_objective`,
or `set_opsec`. See the [Engagement Setup tools](tools/index.md).

## What should I see?

After the quick start:

- the dashboard at `http://127.0.0.1:8384` reports connected;
- terminal Claude and the dashboard name the same active engagement;
- scope added from **Add Targets** or `update_scope` appears on both surfaces;
- agents deployed from Claude or the dashboard appear in the same Fleet; and
- both surfaces share approvals, task leases, findings, and durable state.

### Writing engagement.json from scratch

If none of the templates fit, the full schema is in [Configuration](configuration.md). The fields you'll always need: `id`, `name`, `scope`, `objectives`, `opsec`. Everything else has sensible defaults.

---

## Troubleshooting

??? failure "Server won't start: Cannot find engagement config"
    Run `npm run setup` from the repository root. It creates a fresh config only
    when no engagement artifacts exist; otherwise it preserves recovery
    authority and tells you what must be selected or restored.

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
    An in-place graph reset is not a normal managed workflow. Export or stop and
    preserve the complete engagement, then initialize a separate clean
    workspace. Do not retarget the existing profile with a transient
    `OVERWATCH_STATE_FILE` or delete one state file while its WAL, snapshots,
    intents, evidence, and reports remain. See
    [Daily Operation](daily-operations.md#backup-and-relocation).
