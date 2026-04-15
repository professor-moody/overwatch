# dispatch_campaign_agents

Dispatch sub-agents for each item in a campaign, using campaign-aware scoping.

**Read-only:** No

## Description

Activates the campaign if it is in draft status, then registers one agent per frontier item (up to `max_agents`). Scope computation is strategy-aware:

- **credential_spray** — credential node + target services + parent hosts
- **post_exploitation** — host + all connected nodes
- **enumeration / network_discovery / custom** — N-hop subgraph from frontier seeds

Skips items that already have a running agent.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `campaign_id` | `string` | Yes | ID of the campaign to dispatch agents for |
| `max_agents` | `number` | No | Maximum number of agents to dispatch (1–20, default 8) |
| `hops` | `number` | No | Hops for subgraph scope computation (1–5, default 2) |
| `skill` | `string` | No | Optional skill override applied to each dispatched agent |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `campaign_id` | `string` | The campaign identifier |
| `strategy` | `string` | Campaign strategy (`credential_spray`, `enumeration`, etc.) |
| `requested` | `number` | Number of agents the caller requested |
| `total_items` | `number` | Total items in the campaign |
| `dispatched` | `array` | List of successfully dispatched agent registrations |
| `skipped` | `array` | List of items skipped (already have a running agent) |
| `warning` | `string` | Present when some items could not be dispatched |
| `error` | `string` | Present when the campaign could not be dispatched |

## Usage Notes

- The campaign must exist and not be in `paused`, `aborted`, or `completed` state
- Draft campaigns are automatically activated before dispatch
- Each dispatched agent receives a scope tailored to its campaign strategy, so agents get relevant context without the overhead of the full graph
- Use `manage_campaign` to check campaign status before dispatching
- After dispatch, monitor agents with `get_state()` and mark them complete with `update_agent`
- Set `skill` to guide all dispatched agents toward a specific methodology (e.g., `netexec` for credential spray campaigns)
