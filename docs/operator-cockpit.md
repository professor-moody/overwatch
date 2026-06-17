# Operator Cockpit

Overwatch is operated as a **multi-agent cockpit**: a human operator drives a primary reasoning model, dispatches headless sub-agents, steers and talks to them, and watches everything live from the dashboard's **Operator** panel. This page explains the runtime and the operator surfaces.

## Safety invariant

> **The cockpit never invents a new mutation path.** Every operator action — a typed command, a per-agent steering button, a fleet control, a confirmed plan — routes through an existing **validated engine method** (`issueAgentDirective`, `updateScope`, the approval queue, `registerAgent`). The single dashboard-side execution function is [`executeOps`](#operatorop) in `command-interpreter.ts`. So OPSEC, scope, frontier-lease, and approval guards apply to everything, and nothing mutates engagement state without an explicit operator confirm (or a single deliberate click that maps 1:1 to one validated op).

## The headless multi-agent runtime

- **Dispatch.** `register_agent` / `dispatch_agents` / `dispatch_subnet_agents` / `dispatch_campaign_agents` create `AgentTask`s. `TaskExecutionService` routes each to a backend: `scripted` (deterministic in-process), `headless_mcp` (a real `claude -p` reasoning sub-agent connected back to this daemon's `/mcp`), or `manual`.
- **Liveness.** Sub-agents call [`agent_heartbeat`](tools/agent-heartbeat.md); the watchdog reaps silent tasks past `heartbeat_ttl_seconds` (120s) and a per-task wall-clock timeout (30 min) bounds runaways. Concurrency is capped (default 3 headless agents).
- **Reporting.** Agents record work with `report_finding` / `log_thought` / `parse_output` and close out with `submit_agent_transcript` + `update_agent`.

### Roles {#roles}

A headless sub-agent's tool allowlist is selected by role (`allowedToolsFor` in `headless-mcp-runner.ts`):

- `default` — the full Overwatch MCP surface (target-facing `run_bash`/`run_tool`/sessions included).
- `research` — `WebSearch`/`WebFetch` + graph-read + `research_cve`; **no** target execution.
- `planner` — graph-read + [`propose_plan`](tools/propose-plan.md) only; read-only/propose-only, never executes.

## Natural-language command bar

The operator types plain English in the cockpit; `POST /api/commands` is a **two-phase preview → confirm** flow (`command-interpreter.ts`):

1. **Grammar fast-path.** `interpretCommand` deterministically resolves high-frequency verbs against live state — `pause|resume|stop <agent>`, `tell <agent> <text>`, `scan <cidr/ip/domain>`, `approve|deny <action>`, `pause all` — into `OperatorOp`s. It returns a preview `plan_id`; the operator confirms; `executeOps` runs it.
2. **Planner fallback.** A command the grammar can't resolve is handed to a headless **`planner`** sub-agent, which reasons over state and submits a plan via [`propose_plan`](tools/propose-plan.md). The operator confirms the proposed plan through the **same** confirm path.

### OperatorOp {#operatorop}

`executeOps(engine, ops, 'operator')` is the one place dashboard mutations execute. The `OperatorOp` union has four variants, each mapped to a validated engine method:

| `op` | Maps to |
|------|---------|
| `directive` | `engine.issueAgentDirective` (pause/resume/stop/narrow_scope/skip_types/prioritize/instruct) |
| `scope` | `engine.updateScope` |
| `approve` / `deny` | `PendingActionQueue.approve` / `deny` → `resolveApprovalRequest` |

`ProposedPlanStore` (engine-owned, in-memory, 10-min TTL) is the hand-off between the `propose_plan` tool and the dashboard confirm path. `propose_plan` rejects a plan if **any** op fails to resolve, so a confirmed plan can never silently no-op.

## Steering — talking to a specific agent {#steering}

The directive substrate ([`manage_agent_directive`](tools/manage-agent-directive.md)) is delivered on the agent's heartbeat as `pending_directive`; the agent calls [`acknowledge_agent_directive`](tools/acknowledge-agent-directive.md) and honors it. The cockpit surfaces it as:

- **Per-agent** Pause / Resume / Stop buttons + a free-text box (`instruct`) on the agent context panel — `POST /api/agents/:id/directive` builds one directive op and runs it through `executeOps`.
- **Fleet-wide** Pause/Resume/Stop all (optionally one campaign) — `POST /api/fleet/directive` fans out directive ops over the running set.

## Seeing everything

The **Operator** panel is the primary surface: a roster (each running agent shows a live `doing: …` line derived from its most recent activity), a center console stream (primary + sub-agent events, filterable by Primary/Subagents/Commands/Thoughts/Actions/Findings/Approvals/Sessions/Errors), and a detail panel. The live WS push carries source attribution so primary reasoning and operator commands appear inline as they happen.

## Escalation — agents asking the operator {#escalation}

A running agent at a genuine fork calls [`ask_operator`](tools/ask-operator.md) and waits by heartbeating. The question lands in `AgentQueryStore` and surfaces in the cockpit's **Agent Questions** inbox; the operator answers (`POST /api/agent-queries/:id/answer`) and the answer is delivered on the agent's next heartbeat as `pending_answer` (at-least-once; the agent dedups by `query_id`). A task's questions are expired when it goes terminal, so a dead agent's question never lingers.

## Dashboard endpoints

| Endpoint | Purpose |
|----------|---------|
| `POST /api/commands` | NL command — preview (`{command}`) / confirm (`{confirm,plan_id}`) / deny (`{deny,plan_id}`) |
| `GET /api/plans` | Open planner-proposed plans awaiting confirmation |
| `POST /api/agents/:id/directive` | Steer one agent (one validated directive op) |
| `POST /api/fleet/directive` | Fleet-wide pause/resume/stop (optionally by campaign) |
| `GET /api/agent-queries` · `POST /api/agent-queries/:id/answer` | The agent-question inbox |
| `POST /api/agents/dispatch` | Dispatch a sub-agent (`{ target_node_ids, skill?, campaign_id?, frontier_item_id? }`) |

## See Also

- [Dashboard](dashboard.md) — the full panel + endpoint reference.
- [Architecture](architecture.md#component-overview) — `CommandInterpreter`, `ProposedPlanStore`, `AgentQueryStore`.
- Tools: [`propose_plan`](tools/propose-plan.md), [`ask_operator`](tools/ask-operator.md), [`manage_agent_directive`](tools/manage-agent-directive.md).
