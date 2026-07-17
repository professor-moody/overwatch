# Deployment Architecture: One Engine, Many Adapters

> **Status:** Accepted and implemented for the shared-daemon, stdio, dashboard,
> CLI, planner, and runner paths (updated July 2026).
>
> This is the decision record for transport ownership. For the operator-facing
> startup and coexistence model, see the [Runtime Model](runtime-model.md).

## Context

Overwatch has several callers with different ergonomics:

- an operator's Claude session using MCP;
- the browser dashboard using HTTP and WebSockets;
- the `overwatch` terminal CLI using HTTP;
- daemon-managed headless Claude workers using task-scoped MCP;
- deterministic scripted runners; and
- planner and automation workflows that may retry after a disconnect.

Those callers must not become independent executors or writers. If each owned
its own graph state, timeout policy, or retry semantics, terminal work and
dashboard-deployed work could race, duplicate target actions, or report
different recovery truth.

## Decision

1. **The engine and its persistence layer are the system of record.** A
   deployment has one writable `GraphEngine` for an engagement.
2. **Transports are adapters.** MCP, dashboard HTTP/WS, CLI, planner, scripted
   runners, and headless runners parse requests and format responses. They do
   not own durable mutation logic.
3. **Mutations use transport-neutral application commands.** Domain command
   services validate input, attach actor and action/frontier references, enforce
   actor-scoped idempotency, record durable outcomes, and draft the underlying
   state changes.
4. **`EngineTransaction` V2 is the mutation boundary.** A complete transaction
   is journaled and `fsync`ed before the canonical applier changes live state.
   Recovery uses the same operation semantics.
5. **The shared HTTP daemon is the recommended multi-surface deployment.**
   Terminal Claude, the CLI, browser, planner, and deployed agents connect to
   that one process. MCP stdio remains a supported solo fallback, not a second
   process to run beside the daemon for the same engagement.

## Shipped adapters

| Adapter | Route into the engine | Intended use |
|---|---|---|
| **MCP HTTP** | Streamable HTTP `/mcp` → registered tools → application commands/queries | Terminal Claude and daemon-managed headless agents sharing one daemon |
| **MCP stdio** | stdio MCP → registered tools → application commands/queries | One Claude session owning a solo process |
| **Dashboard** | HTTP contract registry + three WebSocket channels | Browser projections, plans, approvals, questions, dispatch, sessions, playbooks, recovery |
| **Terminal CLI** | `/api/*` through the same dashboard contract surface | Human operation from a second terminal pane |
| **Planner** | Durable planner application command + restricted worker | Natural-language proposal; confirmation executes ordinary commands |
| **Headless runner** | Isolated `claude -p` → task-scoped MCP HTTP | Archetype/role-bounded reasoning work |
| **Scripted runner** | In-process command services | Deterministic automation without a reasoning worker |

The dashboard WebSockets are projection/event channels, not alternate write
stores. Dashboard mutations use HTTP application commands. Likewise, the CLI is
not a parallel engine; it is another client of the daemon API.

## Shared command contract

Every durable command record identifies:

- command kind and validated input hash;
- command ID and actor-scoped idempotency key;
- origin transport and actor task;
- optional action, frontier item, and plan linkage;
- accepted/running/terminal status; and
- stored result or structured error plus affected entity references.

If the same actor retries the same key with identical input, the adapter returns
the original outcome. Reusing the key for different input is an idempotency
conflict. In-progress work remains queryable by command ID, which lets a browser
or CLI reconnect without converting a local polling timeout into a false domain
failure.

The command service then composes one or more deterministic engine operations.
The WAL records a complete checksum-protected transaction before those
operations apply. If journal commit succeeds and apply fails, the writable
service stops; another adapter cannot continue against partial memory.

## Deployment shapes

### Shared daemon (recommended)

`npm run setup` writes an HTTP MCP client configuration for terminal
Claude. `npm run start:daemon` starts the MCP endpoint, dashboard/API, task
execution service, and WebSocket hubs around one engine. Dashboard-deployed
workers receive their own isolated MCP configuration pointing back to this
daemon.

This is the supported shape when any two of terminal Claude, dashboard, CLI,
planner, or dispatched agents are used together. The filesystem writer lease
also rejects an accidental second writer.

### Stdio solo fallback

With explicit `npm run setup:stdio` (or `npm run setup -- --stdio`), Claude can
spawn Overwatch over stdio. That process may
serve the dashboard associated with the solo runtime, but it remains owned by
that one Claude launch. Do not separately start the daemon against the same
engagement directory.

### Remote daemon

The same engine shape can bind beyond loopback. MCP and dashboard/API
authentication remain separate configured bearer-token boundaries. The browser
transport captures a landing token into session storage, removes it from the
visible URL/history, and applies it to HTTP, protected blobs/downloads, and all
WebSocket channels. A reverse proxy does not change command or durability
ownership.

## Headless worker isolation

Launching `claude -p` is local process management; the worker's tool return path
uses the daemon's HTTP MCP adapter. The worker receives a generated task-specific
MCP configuration and allowed-tool set. It does not load the operator terminal's
project MCP configuration, hooks, or resumable Claude session identity.

That separation lets terminal Claude and dashboard-deployed agents run
concurrently without fighting over Claude configuration. Coordination occurs in
Overwatch through durable task identity, leases, directives, questions,
application-command idempotency, and playbook attempt ownership.

## No-MCP environments

The human `overwatch` CLI and dashboard already operate without being MCP
clients; they call the daemon API. A future policy-constrained **reasoning
worker** could be restricted to that CLI instead of MCP, but this model-driver
variant is not required by or implemented in the current runtime. If added, it
must call the same application commands and pass parity tests for validation,
approval, evidence, audit events, idempotency, and transaction recovery. It may
not introduce a second executor.

An embedded provider-native tool loop is also outside the current deployment
contract. The architecture does not assume control of Bedrock or another
provider's model request settings.

## Consequences

- **One recovery truth.** WAL, config convergence, process ownership, and
  session reconciliation expose one status to every adapter.
- **One policy path.** Scope, OPSEC, approval, evidence capture, and audit
  linkage do not vary by transport.
- **Safe coexistence.** Terminal and dashboard work share leases and durable
  ownership rather than relying on browser timers or process-local memory.
- **Retryable clients.** Disconnects can replay completed command outcomes
  without repeating the mutation.
- **Adapter simplicity.** New transports must map to existing commands and
  contracts; they do not gain permission to mutate `GraphEngine` internals.
- **Explicit live-state limits.** Process and session descriptors may survive
  restart, but live handles do not. Recovery reports interrupted, unknown, or
  resume-available state rather than fabricating liveness.

## Non-goals

- Removing or deprecating MCP.
- Running multiple writable engines over one engagement.
- Persisting PTYs, sockets, process objects, WebSocket clients, or model session
  identity.
- Adopting LangGraph, Temporal, A2A, or a provider-specific orchestration layer
  as part of this decision.

## See also

- [Runtime Model](runtime-model.md) — one-daemon operator workflow and worker
  isolation.
- [Architecture](architecture.md) — command, transaction, persistence, and state
  taxonomy.
- [Getting Started](getting-started.md) — daemon and stdio startup paths.
- [Terminal CLI](cli.md) — the human shell adapter.
- [Operator Cockpit](operator-cockpit.md) — planner and deployed-agent behavior.
- [Bedrock Integration Plan](bedrock-integration-plan.md) — enterprise model
  integration considerations.
