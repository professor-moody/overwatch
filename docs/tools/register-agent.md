# register_agent

Register a new sub-agent task.

**Read-only:** No

## Description

Called by the primary session when dispatching sub-agents for parallel work. Provide the frontier item the agent should work on and optionally the relevant node IDs for its scoped subgraph view. The agent can then call `get_agent_context` with its task ID to receive its scoped view.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent_label` | `string` | Conditional | Canonical human-readable label. Supply this or the legacy `agent_id`. |
| `agent_id` | `string` | Conditional | Legacy alias for `agent_label`, retained for one minor release. If both are supplied they must match. |
| `frontier_item_id` | `string` | No | ID of the frontier item this agent should work on |
| `subgraph_node_ids` | `string[]` | No | Node IDs relevant to this agent's task. Leave empty to auto-compute from the frontier item. |
| `skill` | `string` | No | Skill/methodology to apply |
| `archetype` | `string` | No | Agent-type override (e.g. `recon_scanner`, `web_tester`, `credential_operator`, `post_exploit`, `cve_researcher`). When omitted, the archetype is **auto-selected** from the frontier item type + seed node type so the agent gets the right tool surface instead of the full-surface `default`. An unknown value is ignored (falls back to auto-selection). |

## Returns

On success:

| Field | Type | Description |
|-------|------|-------------|
| `task_id` | `string` | Unique task ID (use this for `get_agent_context`, `update_agent`, and `agent_heartbeat`) |
| `agent_label` | `string` | Canonical human-readable label |
| `id` | `string` | Legacy alias for `task_id` |
| `agent_id` | `string` | Legacy alias for `agent_label` |
| `status` | `string` | Initial status (`running`) |
| `archetype` | `string` | The resolved agent type (explicit override, else auto-selected) — drives the agent's tool surface + mission |
| `scope_node_count` | `number` | Number of seed nodes snapshotted for the agent's subgraph |
| `scope_warning` | `string?` | Present when auto-scoped seeds resolved to zero nodes |
| `message` | `string` | Confirmation |

On lease conflict (P1.4):

```json
{
  "ok": false,
  "error": "frontier_lease_conflict",
  "frontier_item_id": "fi-...",
  "existing_task_id": "task-already-claimed",
  "existing_agent_id": "agent-already-running",
  "message": "Frontier item ... is already leased by task ... Pick a different item."
}
```

(Tool returns `isError: true` on the conflict path so the caller can branch cleanly.)

## Frontier Lease (P1.4)

Each registration takes a **TTL lease** on the frontier item. While the lease is active, a different task cannot claim the same item — `register_agent` returns `lease_conflict` instead of racing.

- Default lease TTL: 600 seconds.
- Heartbeats from `agent_heartbeat` extend the lease for another full TTL window.
- Terminal status (`completed` / `failed` / `interrupted`) releases the lease immediately.
- The watchdog reaps expired leases on a 30-second interval, even when the owning task hasn't been touched.

For long-running agents, call [`agent_heartbeat`](agent-heartbeat.md) every 30–60 seconds to prevent the lease (and the task itself) from being reaped as stale.

## AgentTask Lifecycle Fields

The `AgentTask` returned from this tool, available later via `get_state` or `update_agent`, carries:

| Field | Type | Description |
|-------|------|-------------|
| `task_id` | `string` | Canonical durable task ID |
| `agent_label` | `string` | Canonical human-readable label |
| `id` | `string` | Legacy alias for `task_id` |
| `agent_id` | `string` | Legacy alias for `agent_label` |
| `assigned_at` | `string` | ISO timestamp set at registration |
| `status` | `"pending" \| "running" \| "completed" \| "failed" \| "interrupted"` | Current state |
| `frontier_item_id` | `string?` | Linked frontier item |
| `subgraph_node_ids` | `string[]` | Snapshotted seed nodes |
| `skill` | `string?` | Methodology hint |
| `completed_at` | `string?` | ISO timestamp on terminal status |
| `result_summary` | `string?` | Filled in by `update_agent` / `submit_agent_transcript` |
| `heartbeat_at` | `string?` | Most recent heartbeat (P0.3) |
| `heartbeat_ttl_seconds` | `number?` | Watchdog cutoff (default 120) |

Tasks that **never** heartbeat are exempt from watchdog reaping — preserves backward-compat for tools that complete in a single MCP turn.

## Usage Notes

- The `task_id` returned is what agents use to get their scoped context.
- Labels are display names and may repeat. Every relationship uses `task_id`; a legacy label is resolved only when exactly one task has it.
- If `subgraph_node_ids` is empty, the server **eagerly snapshots** seed nodes from the frontier item at registration time, so the scope survives frontier changes between registration and `get_agent_context`.
- For `network_discovery` tasks, scope is always empty (CIDR context is provided instead).
- If auto-scoping resolves to zero nodes, a `scope_warning` is returned so the operator can provide explicit scope or investigate.
- Set `skill` to guide the agent toward a specific methodology.
- Use `update_agent` to mark the task as completed or failed when done.
- For long-running tasks, call `agent_heartbeat` periodically to keep the lease alive.

## See Also

- [`agent_heartbeat`](agent-heartbeat.md) — keep the lease alive
- [`update_agent`](update-agent.md) — terminal state transitions (releases the lease)
- [`dispatch_agents`](dispatch-agents.md) — batch registration
- [Concepts → Frontier Leases / Agent Heartbeat](../concepts.md#agent-heartbeat-and-watchdog)
