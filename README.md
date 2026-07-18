# Overwatch

An offensive security engagement orchestrator built as an MCP server. The persistent state layer and reasoning substrate for LLM-powered penetration testing.

It runs as a **multi-agent operator cockpit**: a human operator drives a primary reasoning model, dispatches headless sub-agents, steers and talks to them in natural language, watches everything live, and answers questions agents escalate — all from the dashboard's Operator console. Every operator action routes through the same validated engine path, so OPSEC/scope/approval guards always apply. See [Operator Cockpit](docs/operator-cockpit.md).

## Quick Start

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

Use Node.js **20, 22, or 24**; Node 24 is recommended. Other majors are not
release-qualified, and `npm run doctor` reports them as unsupported.

> **Note:** `node-pty` is an optional native dependency used for local PTY sessions. It requires native build tools (Python 3, C++ compiler). If it fails to install, the rest of Overwatch works normally — only `local_pty` sessions will be unavailable.

`npm run setup` defaults to the shared daemon and creates local-only `.mcp.json`,
`.overwatch-mcp-token`, and `.claude/settings.json`. In a genuinely fresh
checkout it also creates `engagement.json` with a fresh engagement nonce. It
never replaces an existing engagement, including with `--force`. If the config
is missing but durable state, WAL, snapshots, migration backups, evidence, or
other engagement artifacts remain, setup preserves them: it wires one
unambiguous recovery state for read-only startup or stops and asks you to select
or restore the intended state. The live graph normally persists to
`state-<engagement-id>.json` beside the config unless `OVERWATCH_STATE_FILE` is
set.

If you run `npm run doctor` before the first start, its warning that the daemon
is not running is expected. `npm run daemon:start` starts the
verified daemon in the background, so the same terminal remains free. Open
`http://127.0.0.1:8384`, then run
`OVERWATCH_ENGAGEMENT_ACTIVE=1 claude` for engagement work or use the CLI. A
plain `claude` still connects to MCP, but intentionally leaves the
engagement-only anti-drift hooks inactive. You can run
`npm run doctor` again there to verify the live daemon and local build match.

Setup is initial selection and client wiring, not the way to edit a running
engagement. On a fresh checkout you may add `--template`, `--name`, `--cidr`, or
`--domain`; those values are used only when setup creates `engagement.json`.
Afterward, add scope from **Console → Add Targets** (or `update_scope`), edit
objectives and OPSEC in **Settings** (or `add_objective` / `set_opsec`), and let
the revisioned write-through service keep the live engine, durable state, and
active file aligned.

The dashboard's **New Engagement** flow and the `create_engagement` MCP tool
create another validated, inactive config. They do not switch the running
daemon away from its current engagement; dashboard engagement switching is not
currently supported.

There is exactly **one Overwatch runtime owner**. Terminal Claude connects to
that daemon over MCP; the browser dashboard and `overwatch` CLI use its API;
dashboard-deployed Claude workers connect back to it with task-specific MCP
credentials and leases. The workers do not inherit this checkout's project
Claude settings, hooks, MCP servers, or resumable terminal session. They keep
Claude's user settings only for authentication. This lets you keep using Claude
interactively in your terminal while the dashboard deploys agents, without
starting a second engine or mixing their sessions.

For routine start/stop, approvals, planner diagnosis, recovery, upgrades, and
backups, see [Daily Operation](docs/daily-operations.md).

After later pulls, `npm run upgrade` first checks dependency and state/WAL
migration readiness while the current daemon stays live, then stops the
identity-verified daemon and repeats the state/WAL check against frozen files.
It holds a cross-process reservation on that state family through the locked
dependency install and build, and releases it only after the replacement
runtime publishes its durable ownership. Only then can another writer start.
A failed frozen check attempts to restart the unchanged compiled daemon
without changing the engagement; if another physical owner claims the state in
that legacy-runtime handoff window, restart fails closed. See the [0.2.0 compatibility and
release contract](docs/compatibility.md). A normal start rebuilds stale output only when no daemon is live,
so an old dashboard or planner cannot silently run against replaced assets. If the
dashboard says **Disconnected**, a planner exits unexpectedly, or `doctor`
reports a build mismatch, stop the old daemon, rebuild, run `npm run doctor`,
start the daemon once, and hard-reload the browser.

If this checkout predates the persisted runtime profile
(`.overwatch-runtime/profile.json` is absent), stop the old foreground/stdio
owner first and run `npm run setup` once before using `npm run upgrade`.
Lifecycle commands intentionally refuse to guess which engagement state is
writable. That one-time setup preserves existing config, state, WAL, evidence,
and reports while recording their selected paths.

For the solo Claude-only compatibility mode, run `npm run setup:stdio` (or
`npm run setup -- --stdio`). That configuration lets one Claude session launch
and own Overwatch itself.

`npm run setup:stdio` writes the runtime profile and lifecycle-backed `.mcp.json`
entry together. If you must inspect or reproduce that entry manually, it uses
absolute paths and still goes through the ownership gate:

```json
{
  "mcpServers": {
    "overwatch": {
      "command": "node",
      "args": ["<path-to-overwatch>/scripts/daemon-lifecycle.mjs", "run-stdio"],
      "env": {
        "OVERWATCH_RUNTIME_PROFILE": "<path-to-overwatch>/.overwatch-runtime/profile.json"
      }
    }
  }
}
```

Do not hand-edit one side of this pair; rerun `npm run setup:stdio` to reconcile
it. Then run `OVERWATCH_ENGAGEMENT_ACTIVE=1 claude` for engagement work.
`.claude/settings.json` installs hooks that keep Claude using
Overwatch instead of drifting into raw target-facing Bash. See the full
[Getting Started](https://professor-moody.github.io/overwatch/getting-started/)
guide.

After pulling an update, the stable refresh path is:

```bash
git pull --ff-only origin main
npm run upgrade
npm run doctor
```

The upgrade command performs live and frozen preflights around the verified
stop before install/build/start. Its cross-process reservation prevents a
second checkout or runtime from claiming the engagement during that window. It
does not replace `engagement.json`, its state/WAL, evidence, or reports.

## Documentation

**[professor-moody.github.io/overwatch](https://professor-moody.github.io/overwatch/)** — architecture, configuration, the generated MCP tool inventory, graph model, inference rules, skills library, operator playbook, and development guide.

## Disclaimer

This tool is designed for authorized security testing only. Do not run against production systems without explicit written authorization.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
