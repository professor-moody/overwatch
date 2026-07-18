# Runtime Model: One Daemon, Shared Surfaces

The most important runtime rule is simple: **start one Overwatch daemon and let
every operator surface connect to it**.

With the recommended daemon setup, terminal Claude, the `overwatch` CLI, the
browser dashboard, planner, scripted automation, and dashboard-deployed agents
all reach one `GraphEngine`. They share graph truth, durable command outcomes,
task leases, playbook ownership, approvals, and evidence. They do not maintain
separate copies that later need to be merged.

![Two surfaces, one engine](assets/two-surfaces-one-engine-light.svg#only-light)
![Two surfaces, one engine](assets/two-surfaces-one-engine-dark.svg#only-dark)

## Choose the right startup shape

The supported shapes are deliberately distinct:

- **Shared daemon (recommended and default):** `npm run setup`, then
  `npm run daemon:start`. The generated `.mcp.json` points terminal Claude at
  the daemon's HTTP MCP endpoint. The dashboard and CLI use the same daemon's
  HTTP/WebSocket API, and dispatched agents connect back to its MCP endpoint.
- **Stdio (solo fallback):** `npm run setup:stdio` configures one Claude session
  to launch and own one Overwatch
  process. Do not also start a daemon for the same engagement; that would be a
  second writer rather than another view of the same runtime.

The process-lifetime state-family lease rejects competing processes before
graph recovery, while writer/migration locks protect each filesystem boundary. The right operating
model is still one daemon—not one Overwatch process per terminal or browser.
See [Getting Started](getting-started.md) for the exact commands and `doctor`
checks.

## Shared surfaces

| Surface | Transport | Role |
|---|---|---|
| **Terminal Claude** | HTTP MCP `/mcp` in daemon mode | Primary reasoning loop, graph reads, validated execution, agent dispatch |
| **Terminal CLI** | Dashboard HTTP `/api/*` | Human-friendly status, approvals, dispatch, sessions, and playbook operations from another pane |
| **Dashboard** | HTTP + WebSocket | Live projections, approvals, questions, plans, deploy/steer controls, evidence and recovery views |
| **Headless agents** | Task-scoped HTTP MCP `/mcp` | Bounded reasoning work with an archetype/role tool allowlist |
| **Scripted runners** | In-process application commands | Deterministic work such as supported credential validation |

All mutating surfaces call the same transport-neutral application command
services. A command carries its actor, validated input, command/action/frontier
references, and idempotency identity; its outcome is durable. Consequently, a
dashboard retry cannot silently duplicate terminal work, and a playbook step
claimed in one surface is visibly owned in the others.

## Terminal Claude and deployed agents do not share Claude sessions

The daemon's headless `claude -p` workers are deliberately isolated from the
operator terminal's project-local Claude settings and MCP files. Each worker
receives a task-specific MCP configuration that contains only the daemon
endpoint and the tool surface allowed for its role or archetype. It does not
load the primary session's project hooks and does not add a resumable session to
the operator's Claude history.

Your terminal Claude continues to use the repository's `.claude/settings.json`
and daemon-mode `.mcp.json`. The workers and terminal therefore share
**Overwatch task state**, not Claude process identity. The engine's frontier
leases, durable command idempotency, playbook attempt ownership, and agent task
IDs are the conflict-control boundary.

## How a deployed agent loops back

When the terminal or dashboard dispatches an agent, the daemon first creates a
durable task. `TaskExecutionService` selects its backend:

- **scripted** — deterministic, no-model work;
- **headless_mcp** — an isolated `claude -p` worker connecting back to the same
  daemon with a scoped tool allowlist; or
- **manual** — the task remains available for a human operator.

The backend follows the work type as well as the selected archetype. For
example, supported token-validation frontier work uses the scripted path,
whereas discovery, path analysis, or CVE research can use a reasoning worker.

![Agent dispatch backends](assets/agent-dispatch-backends-light.svg#only-light)
![Agent dispatch backends](assets/agent-dispatch-backends-dark.svg#only-dark)

Findings, evidence, action outcomes, transcripts, and task lifecycle updates
land through the same command and transaction boundaries as terminal work.
They appear in the dashboard because the dashboard projects that engine state,
not because it scrapes the child process.

## Plans, approvals, and questions

Planner commands, action approvals, and agent questions are durable coordination
records rather than browser timers:

- A planner command remains queryable by command ID while its worker runs. The
  browser does not declare failure merely because a local polling deadline
  elapsed.
- Plans preserve owner, expiry, confirmation, acknowledgement, and execution
  outcome. A confirmed plan executes through application commands.
- Agent questions retain their original expiry. Answers are redelivered on
  heartbeat until the agent acknowledges the matching query ID.
- Approval resolution is shared: a terminal request can be approved or denied
  from the dashboard or CLI, and the waiting action observes that one durable
  resolution.

If an agent exits without producing the required plan or terminal result, the
task is finalized truthfully and its transcript/evidence remains available for
diagnosis. Restart does not invent a successful response.

![Approval and question round-trip](assets/approval-question-roundtrip-light.svg#only-light)
![Approval and question round-trip](assets/approval-question-roundtrip-dark.svg#only-dark)

## What survives restart

The persisted state contains graph/config truth and durable coordination:
agents, campaigns, approvals, directives, leases, plans, questions and answers,
application-command outcomes, playbook runs and attempts, process ownership,
and secret-free session descriptors. Original identities and absolute expiry
times are retained.

Live handles do not survive. PTYs, sockets, child-process objects, WebSocket
clients, database connections, terminal buffers, and unsaved browser state are
ephemeral. Startup reconciles their descriptors instead of pretending they are
still live:

- detached runtime runs are verified by PID/group/start identity, then marked
  interrupted or unknown as appropriate;
- PTY, SSH, and socket-connect sessions become interrupted; and
- rearm listeners become `resume_available` and require explicit
  `resume_session`, after which a new connection generation is created.

[`get_state`](tools/get-state.md) reconstructs an **operational briefing** after
model compaction or restart. It does not contain every activity record,
evidence byte, external artifact, terminal buffer, or other ephemeral handle.
Use the dedicated history, evidence, graph-export, recovery, session, and bundle
surfaces when full fidelity is required.

## One execution policy

Regardless of origin, target-facing work uses the same validated process or
session command path: scope checks, OPSEC policy, approval, action lifecycle,
evidence capture, parser ingestion, durable outcome, and audit linkage. The
transport adapter cannot bypass these policies by mutating graph or runtime
state directly.

The durability boundary is also shared. Application commands draft
`EngineTransaction` operations, journal complete committed transactions before
apply, and publish one engine update. A recovery/config/process-ownership issue
that makes durability uncertain puts this one daemon into degraded read-only
mode; no surface may continue target execution while another writes.

## Where to go next

- [Getting Started](getting-started.md) — one-daemon setup, build freshness, and
  connection checks.
- [Operator Cockpit](operator-cockpit.md) — dashboard plans, agent types,
  steering, approvals, and questions.
- [Architecture](architecture.md) — application commands, transactions,
  recovery, and state taxonomy.
- [Deployment Architecture](deployment-architecture.md) — why transports are
  adapters rather than independent executors.
- [Terminal CLI](cli.md) — operate the same daemon from another terminal pane.
