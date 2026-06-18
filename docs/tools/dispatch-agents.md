# dispatch_agents

Batch-register sub-agents from the current filtered frontier.

**Read-only:** No

## Description

Computes the live frontier (same path as [`next_task`](next-task.md)), filters out items that already have a running agent or an active [frontier lease](../concepts.md#agent-heartbeat-and-watchdog) held by a different task, and registers up to `count` running agent tasks with auto-computed subgraph scopes. Returns the list of dispatched task IDs and the items skipped (with reasons).

This is the generic batch-dispatch tool. For campaign-aware dispatch (strategy-specific scope, campaign progression), use [`dispatch_campaign_agents`](dispatch-campaign-agents.md). For subnet-specific dispatch with CIDR scoping, use [`dispatch_subnet_agents`](dispatch-subnet-agents.md).

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `count` | `number` | No | 4 | Number of agents to dispatch (1–20) |
| `strategy` | `"top_priority" \| "by_type"` | No | `"top_priority"` | How to select frontier items |
| `hops` | `number` | No | 2 | Subgraph scope depth around each frontier seed (1–5) |
| `skill` | `string` | No | — | Optional skill override applied to all dispatched agents |
| `archetype` | `string` | No | — | Optional agent-type override applied to every dispatched agent. When omitted, each agent's archetype is **auto-selected** from its frontier item type + seed node type (so a webapp item gets `web_tester`, a credential item gets `credential_operator`, etc.) instead of the full-surface `default`. |
| `agent_id_prefix` | `string` | No | `"sub"` | Prefix for synthesized `agent_id`s |

**Strategies:**

- `top_priority` — picks the top-N items by frontier score
- `by_type` — picks one item per frontier item type (`incomplete_node`, `untested_edge`, `inferred_edge`, …) to keep the dispatch diverse

## Returns

```json
{
  "dispatched": [
    {
      "task_id": "task-abc-123",
      "agent_id": "sub-1",
      "frontier_item_id": "fi-host-10-10-10-5",
      "scope_node_count": 5
    }
  ],
  "skipped": [
    {
      "frontier_item_id": "fi-host-10-10-10-6",
      "reason": "already has running agent"
    },
    {
      "frontier_item_id": "fi-host-10-10-10-7",
      "reason": "frontier_lease_conflict",
      "existing_task_id": "task-other-456"
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `dispatched[]` | `array` | Successfully registered agent tasks |
| `skipped[]` | `array` | Items intentionally skipped, with reason |

## Lease Conflict Behavior (P1.4)

Each registration takes a TTL lease on the frontier item (default 600s). When two `dispatch_agents` calls compete for the same item, the second one gets `lease_conflict` and the item lands in `skipped`. The lease is released when the agent's status transitions to `completed` / `failed` / `interrupted`, or when its TTL elapses without a heartbeat (the [watchdog](../concepts.md#agent-heartbeat-and-watchdog) handles this).

For long-running agents, ensure they call [`agent_heartbeat`](agent-heartbeat.md) periodically to prevent the lease from expiring.

## Usage Notes

- `dispatch_agents` is idempotent in spirit: running it twice in succession will skip items already claimed by the first run.
- For finer control over which frontier items are dispatched, fetch with [`next_task`](next-task.md) and call [`register_agent`](register-agent.md) per item.
- The dispatched agents' subgraph is captured at registration time — if the frontier moves between dispatch and the agent's `get_agent_context` call, the agent still sees its original scope.

## See Also

- [`register_agent`](register-agent.md) — per-item registration
- [`dispatch_campaign_agents`](dispatch-campaign-agents.md) — campaign-aware dispatch
- [`dispatch_subnet_agents`](dispatch-subnet-agents.md) — subnet-scoped dispatch
- [`agent_heartbeat`](agent-heartbeat.md) — keep leases alive
