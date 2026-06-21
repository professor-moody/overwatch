# Runtime Model: Two Surfaces, One Engine

The single most important thing to understand about Overwatch's runtime: **there is one engine, and everything else is a driver routing into it.**

A persistent `GraphEngine` process holds *all* engagement state — the graph, the activity log, pending approvals, agent tasks, sessions, evidence. You operate that engine through **two surfaces** that are different views of the *same* live state:

1. **The terminal** — a human operator + a primary Claude (Claude Code, or a `claude -p` sub-agent) talking to Overwatch over the **MCP** protocol (stdio, or HTTP `/mcp`).
2. **The dashboard** — a React UI over **HTTP + WebSocket**.

An action taken on either surface is visible on the other, live. Approve a command in the dashboard and the terminal agent that was blocked on it resumes. Report a finding from the terminal and it appears in the dashboard graph within a frame. They are not two copies kept in sync — they are one engine with two front doors.

![Two surfaces, one engine](assets/two-surfaces-one-engine-light.svg#only-light)
![Two surfaces, one engine](assets/two-surfaces-one-engine-dark.svg#only-dark)

## Why this matters

LLM context windows are finite; engagements are not. If state lived in the prompt, a compaction, a restart, or a handoff to a sub-agent would lose it. Overwatch moves state **out of the context window** into the engine, so:

- the primary model can compact and reconstruct everything with one `get_state()`;
- many agents can work in parallel against one consistent graph;
- the operator can watch and steer from the dashboard without the model knowing or caring whether anyone is watching.

The engine is also the **single executor**: every target-facing action — whether it arrived from the terminal or was triggered from the dashboard — routes through the same `validate_action → approve → execute → capture evidence → log` lifecycle (`runInstrumentedProcess`). Scope checks, OPSEC budget, the approval gate, evidence capture, and the tamper-evident audit log apply **uniformly**, regardless of how the action arrived. (See [Drivers (Decision Record)](deployment-architecture.md) for the "one engine, many drivers" rationale and the planned internal CLI driver.)

## The three drivers

| Driver | Transport | Who/what | What it does |
|--------|-----------|----------|--------------|
| **Operator + primary Claude** | MCP stdio (or HTTP `/mcp`) | The human + their reasoning model in the terminal | Drives the engagement: scores the frontier, executes through the lifecycle, dispatches sub-agents |
| **Headless sub-agents** | MCP HTTP `/mcp` | `claude -p` processes the daemon spawns | Bounded, tool-scoped work (recon, web, CVE research, …) connecting **back** to the same engine |
| **Dashboard** | HTTP + WebSocket | The operator's browser | Watch the graph live, approve/deny actions, answer agent questions, deploy + steer agents, review findings |

All three hold a reference to **one** `GraphEngine`, persist to **one** state file, and append to **one** activity log.

## How a sub-agent loops back

When the primary dispatches a sub-agent (`register_agent` / `dispatch_agents`, or the dashboard's quick-deploy), the daemon resolves an execution backend and — for reasoning work — spawns a headless `claude -p` that connects **back** to the daemon's own `/mcp` endpoint as an MCP client. It then drives itself through the real Overwatch tools (scoped to its archetype's `--allowedTools`), so its findings land in the same graph the operator is watching.

![Agent dispatch backends](assets/agent-dispatch-backends-light.svg#only-light)
![Agent dispatch backends](assets/agent-dispatch-backends-dark.svg#only-dark)

- **scripted** — deterministic, no-LLM work (e.g. credential/token validation). Fast, runs in-process.
- **headless_mcp** — a real reasoning sub-agent (`claude -p`) over `/mcp`. Only when an HTTP endpoint is bound (daemon mode); otherwise the task defers to manual.
- **manual** — a human drives it from the dashboard.

The backend is chosen by the *frontier item type*, not the archetype label: a `credential_test` item is always claimed by the deterministic scripted handler; open-ended work (discovery, pivots, CVE research) goes to a reasoning agent.

## The approval & question round-trip

This is the clearest demonstration that the two surfaces are tied to one engine. A terminal agent's target-facing call **blocks** in the engine's pending-action queue; the operator resolves it from the dashboard; the agent resumes. The same shape carries agent → operator questions.

![Approval and question round-trip](assets/approval-question-roundtrip-light.svg#only-light)
![Approval and question round-trip](assets/approval-question-roundtrip-dark.svg#only-dark)

The engine hardens this path:

- An approval that is never answered **auto-fires on timeout** (default `opsec.approval_timeout_ms` = 300s, configurable) — loud, tagged `unattended_execute` in the OPSEC log and retrospective, never a silent approval. (Note the asymmetry: timeout auto-*approves*; to stop an action you must explicitly [`deny_action`](tools/deny-action.md).)
- If the requesting agent is **reaped, cancelled, or times out**, its blocked approval is **aborted** (never executed) and its OS process is killed — a dead agent can't run a command.
- Pending approvals are **persisted**; on a daemon restart they're reconciled to `aborted` rather than left un-actionable.

(See the [Operator Cockpit](operator-cockpit.md) for the operator-facing "Needs you" strip and escalation UX.)

## Shared-state touchpoints

What concretely makes the two surfaces *one* system:

- **One `GraphEngine` instance** is constructed once and passed to the MCP server (stdio + every HTTP session), the dashboard server, the session manager, and the task-execution service.
- **One `EngineContext`** holds the mutable state (graph, agents, approvals, agent questions, activity log) — all modules reference this object, not copies.
- **One state file** per engagement; the terminal and dashboard both read and write it.
- **One activity log** records every action from either surface; the dashboard subscribes to engine updates and broadcasts deltas over WebSocket.

The only deliberately ephemeral, in-memory state is short-lived by design — planner proposals and unanswered agent questions expire on a TTL (a question outliving the agent that asked it is dead weight). Everything that matters across a restart is in the state file.

## Where to go next

- [Operator Cockpit](operator-cockpit.md) — the dashboard's console-first workflow, agent types, NL command bar, and escalation.
- [Architecture Overview](architecture.md) — the component decomposition and the deterministic-vs-LLM split.
- [Drivers (Decision Record)](deployment-architecture.md) — why MCP is a driver, not the platform, and what other drivers are planned.
- [Key Concepts](concepts.md) — the frontier, inference, OPSEC, compaction, and the action lifecycle in depth.
