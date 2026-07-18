# Daily Operation

This page is the routine operator lifecycle after the one-time
[`npm run setup`](getting-started.md) step. One managed daemon owns the current
active engagement; terminal Claude, the dashboard, the `overwatch` CLI,
planners, and deployed agents are clients of that owner.

## Start work

From the configured checkout:

```bash
npm run daemon:start
npm run doctor
OVERWATCH_ENGAGEMENT_ACTIVE=1 claude
```

Open <http://127.0.0.1:8384/> for the dashboard. `daemon:start` is idempotent
when the exact configured owner is already ready. `doctor` verifies the
persisted profile, daemon/build identity, ports, MCP token, and managed-worker
Claude flags without changing engagement data.

The profile at `.overwatch-runtime/profile.json` pins the selected config,
state family, endpoints, and token-file paths. Ordinary lifecycle commands use
that profile. Do not use transient `OVERWATCH_CONFIG` or
`OVERWATCH_STATE_FILE` overrides to retarget a managed daemon. Environment
selection belongs to a stopped setup operation or an explicitly isolated
developer/fixture process.

## Use the surfaces together

Keep one daemon running while you use any combination of:

- terminal Claude over authenticated HTTP MCP;
- the browser dashboard and its deployed agents;
- the `overwatch` terminal CLI; and
- planners, scripted runners, and credential playbooks.

Opening or closing a browser or terminal Claude does not start or stop the
daemon. Dashboard workers are separate headless Claude processes, but they use
the same durable tasks, frontier leases, command outcomes, approvals, findings,
and playbook-attempt ownership. They do not share the human terminal's Claude
session or project-local settings.

Do not run `npm run setup:stdio` or a direct `node dist/index.js` process beside
the managed daemon for the same state family. Stdio is a solo compatibility
mode in which one Claude process owns Overwatch.

## Approvals

The dashboard **Approvals** view contains only actions queued by the effective
approval policy:

- `auto-approve` does not queue actions;
- `approve-all` queues every action; and
- `approve-critical` queues actions only when the effective OPSEC policy says
  their noise, blacklist, defensive signals, or exhausted budget requires it.

A queued action waits for `approval_timeout_ms` (five minutes by default). If
the operator does not answer, the action is approved and executed as an
`unattended_execute`; this outcome is explicit in activity and retrospective
records. It is not a denial. Cancelling/reaping the owning task, disconnecting
the waiting request, or shutting down aborts the approval and does not execute
the action.

## Planner status and troubleshooting

Planner work is asynchronous and durable. The default planner lane runs one
planner at a time, so a second accepted command may remain `queued` until the
first finishes. Reloading or navigating away from the dashboard does not cancel
it, and the browser has no domain-level plan timeout.

Durable application-command states are `accepted`, `running`, `succeeded`,
`failed`, or `interrupted`; the dashboard presents an accepted planner waiting
for the lane as **queued**. A planner that exits without `propose_plan` finishes
with an explicit no-plan failure rather than a fabricated plan. Inspect command
truth through:

- `GET /api/commands/active` — all active durable planner commands;
- `GET /api/commands/{command_id}` — one stored command and outcome; and
- the Fleet task, its console/transcript, and `logs/agents/<task-id>.ndjson`.

For a planner that fails immediately, run `npm run doctor` and check the live
build identity, Claude CLI availability/worker flags, authentication, and
recovery writability. A queued or slow planner is not by itself a reason to
restart the daemon. If it reaches a terminal no-plan result, inspect its task
transcript and log before dispatching it again.

## Read-only recovery

When persistence cannot prove a safe writable state, Overwatch keeps inspection
available and rejects new durable target mutations. Check the exact condition
with any equivalent surface:

```bash
overwatch recovery
```

- MCP: `get_recovery_status`
- HTTP: `GET /api/recovery`
- Dashboard: the global banner and **Settings → Recovery**

For a config-only divergence, the active file and the durable config copy have
different semantics. This does not delete the graph, evidence, or reports.
Refresh recovery status, review both observed hashes, then choose only an
allowed resolution:

- `use_file` validates the active file and applies its semantic configuration;
- `use_state` restores the active file from durable-state authority.

Both modes require the exact current file and state hashes and advance all
representations to one revision. Config reconciliation cannot bypass a separate
WAL/state recovery failure. Never delete state, WAL, snapshots, intents,
evidence, or reports to force startup.

## End of day and shutdown

It is safe to close the dashboard and terminal Claude while leaving the daemon
running; managed agents and planners continue under their durable task
ownership.

If you intentionally stop, first inspect active agents, approvals, sessions,
and playbook attempts, then run:

```bash
npm run daemon:stop
```

Stop, restart, and the stop phase of `npm run upgrade` interrupt running or
pending headless agents and planners, mark their tasks/commands accordingly,
and abort their pending approvals. Durable graph state, evidence, findings,
submitted transcripts, and process/session descriptors remain. A live model
turn or live PTY/socket handle is not reconstructed; resume or redispatch
unfinished work after restart.

## Pull and upgrade

From a clean checkout with the managed profile already established:

```bash
git pull --ff-only origin main
npm run upgrade
npm run doctor
```

Upgrade performs live and frozen preflights, stops the verified owner, holds the
state-family reservation through install/build, and starts the replacement. It
does not replace the active config, state/WAL, evidence, or reports. A failed
durable shutdown or frozen recovery check fails closed for inspection.

## Backup and relocation

For a live portable capture, prefer `bundle_engagement`. It uses the engine's
artifact/state capture barrier and includes a checksummed manifest.

For a raw filesystem backup, stop the verified daemon first (or use a
filesystem snapshot that is consistent across the entire state family). Copy
the selected config and state plus every adjacent WAL, snapshot, write/migration
intent, migration backup, evidence, report, tape, and recovery artifact. The
config and state can be in different directories; use `npm run daemon:status`
or `npm run doctor` to identify the selected paths.

After moving a source checkout to another machine or path, leave the copied
engagement artifacts intact and rerun `npm run setup` while stopped. Setup
regenerates machine-local profile, token-path, MCP, and hook wiring without
replacing the engagement.

An in-place graph reset is not a normal managed workflow. Preserve/export the
current engagement and initialize a separate clean workspace when you truly
need a fresh state family.
