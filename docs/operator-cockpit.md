# Operator Cockpit

Overwatch is operated as a **multi-agent cockpit**: a human operator drives a primary reasoning model, dispatches headless sub-agents, steers and talks to them, and watches everything live from the dashboard's **Console** (the home of a console-first IA — see [Dashboard](dashboard.md#operator-console-cockpit)). This page explains the runtime and the operator surfaces.

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

### Grammar reference {#grammar}

The deterministic fast-path (`interpretCommand`) recognizes these verbs (case-insensitive). Anything else falls through to the planner. The same grammar backs the command bar and the typed-command surfaces.

| Intent | Syntax | Notes |
|--------|--------|-------|
| Steer one agent | `pause` / `resume` / `stop` / `halt` `<agent>` | `halt` aliases `stop`. `<agent>` matches a label or task id. |
| Steer the fleet | `pause` / `resume` / `stop` `all` (or `everything`, `all agents`) | Fans out over every running agent. |
| Talk to an agent | `tell <agent> [to] <text>` · `instruct <agent> [to] <text>` | Delivered as an `instruct` directive on the agent's next heartbeat. |
| Add scope | `scan <targets>` · `add scope <targets>` · `add to scope <targets>` · `target <targets>` | Targets are whitespace/comma-separated CIDRs, IPs (→`/32`), or domains (lowercased); IPv6/junk is rejected. Same parsing as the Console's **Add Targets** modal. |
| Resolve an action | `approve [action] <id> [reason]` · `deny [action] <id> [reason]` | The optional `action` keyword is accepted; the trailing text is the reason. |

Each resolves to one or more `OperatorOp`s, previews, and runs through `executeOps` on confirm — never a separate mutation path.

## Steering — talking to a specific agent {#steering}

The directive substrate ([`manage_agent_directive`](tools/manage-agent-directive.md)) is delivered on the agent's heartbeat as `pending_directive`; the agent calls [`acknowledge_agent_directive`](tools/acknowledge-agent-directive.md) and honors it. The cockpit surfaces it as:

- **Per-agent** Pause / Resume / Stop buttons + a free-text box (`instruct`) on the agent context panel — `POST /api/agents/:id/directive` builds one directive op and runs it through `executeOps`.
- **Fleet-wide** Pause/Resume/Stop all (optionally one campaign) — `POST /api/fleet/directive` fans out directive ops over the running set.

## Seeing everything

The **Console** is the primary surface, laid out as a focused master-detail workspace:

- a pinned **command bar** (the NL command line above);
- a **"Needs you" strip** that surfaces what's waiting on the operator — pending **approvals** (inline Approve / Deny+reason) and agent **questions** (inline Answer) — and hides itself when nothing needs attention;
- a **Fleet** roster on the left: select an agent to *focus* it, and the main column becomes that agent's detail + steering + its own activity stream; with nothing selected the main column is a fleet overview over the full primary/sub-agent stream;
- the activity stream is filterable by Primary/Subagents/Commands/Thoughts/Actions/Findings/Approvals/Sessions/Errors.

The live WS push carries source attribution so primary reasoning and operator commands appear inline as they happen. Resolved approvals clear off the `action_resolved` push. The standalone **Approvals** view is the deep triage queue and shares the same approve/deny path.

## Escalation — agents asking the operator {#escalation}

A running agent at a genuine fork calls [`ask_operator`](tools/ask-operator.md) and waits by heartbeating. The question lands in `AgentQueryStore` and surfaces in the cockpit's **Agent Questions** inbox; the operator answers (`POST /api/agent-queries/:id/answer`) and the answer is delivered on the agent's next heartbeat as `pending_answer` (at-least-once; the agent dedups by `query_id`). A task's questions are expired when it goes terminal, so a dead agent's question never lingers.

## Agent types & deploy {#agent-types}

Sub-agents are **typed** (data-driven archetypes in `agent-archetypes.ts`), each a real bundle of a tool surface (a genuine `--allowedTools` boundary), a backend, a default skill/objective, and a scope strategy:

| Agent type | What it does | Tool surface |
|------------|-------------|--------------|
| `recon_scanner` | host/service discovery, enumeration | execute + scope; **no** sessions/credentials |
| `web_tester` | web app testing | execute + sessions |
| `credential_operator` | validate/spray/expand credentials & tokens | execute + credential tools; no sessions |
| `post_exploit` | work from a foothold: sessions, lateral movement | execute + sessions + credentials |
| `cve_researcher` | web CVE/PoC research | web research only — **no** target execution |
| `pathfinder` | read-only attack-path analysis → proposes plans | read-only + `propose_plan` |
| `report_scribe` | draft report sections from confirmed state | read-only + `generate_report` |
| `default` | the generic full-surface agent (fallback) | full `mcp__overwatch` |

The system **recommends** a type for a target (`recommendArchetype`, mirroring the frontier→strategy mapping), and the operator can **override** it from the catalog. Deploy two ways:

- **Ad-hoc / real-time** — the console **Deploy** button (or `POST /api/agents/quick-deploy`): paste an IP/CIDR/domain → it's added to scope (canonical `updateScope`, so the agent's actions stay in-scope) and the recommended (or chosen) agent is dispatched at it, in one step. No engagement-setup ritual.
- **At existing nodes** — Deploy with node IDs, or `dispatch_agents`, passing an `archetype`.

The engagement/scope/OPSEC substrate is unchanged — ad-hoc deploy just removes the setup friction.

## Dashboard endpoints

| Endpoint | Purpose |
|----------|---------|
| `POST /api/commands` | NL command — preview (`{command}`) / confirm (`{confirm,plan_id}`) / deny (`{deny,plan_id}`) |
| `GET /api/plans` | Open planner-proposed plans awaiting confirmation |
| `POST /api/agents/:id/directive` | Steer one agent (one validated directive op) |
| `POST /api/fleet/directive` | Fleet-wide pause/resume/stop (optionally by campaign) |
| `GET /api/agent-queries` · `POST /api/agent-queries/:id/answer` | The agent-question inbox |
| `POST /api/actions/:id/approve` · `POST /api/actions/:id/deny` | Resolve a pending action inline (canonical `resolveApprovalRequest`) |
| `POST /api/config/scope/preview` · `PATCH /api/config/scope` | Add Targets — read-only impact dry-run, then apply via `updateScope` |
| `GET /api/agent-archetypes` | The agent-type catalog for the Deploy picker |
| `POST /api/agents/quick-deploy` | Ad-hoc deploy — scope a raw IP/CIDR/domain + dispatch the recommended/chosen type |
| `POST /api/agents/dispatch` | Dispatch a sub-agent (`{ target_node_ids, archetype?, skill?, campaign_id?, frontier_item_id? }`) |

## See Also

- [Dashboard](dashboard.md) — the full panel + endpoint reference.
- [Architecture](architecture.md#component-overview) — `CommandInterpreter`, `ProposedPlanStore`, `AgentQueryStore`.
- Tools: [`propose_plan`](tools/propose-plan.md), [`ask_operator`](tools/ask-operator.md), [`manage_agent_directive`](tools/manage-agent-directive.md).
