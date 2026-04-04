# register_agent

Register a new sub-agent task.

**Read-only:** No

## Description

Called by the primary session when dispatching sub-agents for parallel work. Provide the frontier item the agent should work on and optionally the relevant node IDs for its scoped subgraph view. The agent can then call `get_agent_context` with its task ID to receive its scoped view.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent_id` | `string` | Yes | Unique identifier for the agent |
| `frontier_item_id` | `string` | Yes | ID of the frontier item this agent should work on |
| `subgraph_node_ids` | `string[]` | No | Node IDs relevant to this agent's task. Leave empty to auto-compute from the frontier item. |
| `skill` | `string` | No | Skill/methodology to apply |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `task_id` | `string` | Unique task ID (use this for `get_agent_context` and `update_agent`) |
| `agent_id` | `string` | The agent identifier |
| `status` | `string` | Initial status (`running`) |
| `scope_node_count` | `number` | Number of seed nodes snapshotted for the agent's subgraph |
| `scope_warning` | `string` | Present when auto-scoped seeds resolved to zero nodes |
| `message` | `string` | Confirmation |

## Usage Notes

- The `task_id` returned is what agents use to get their scoped context
- If `subgraph_node_ids` is empty, the server **eagerly snapshots** seed nodes from the frontier item at registration time, so the scope survives frontier changes between registration and `get_agent_context`
- For `network_discovery` tasks, scope is always empty (CIDR context is provided instead)
- If auto-scoping resolves to zero nodes, a `scope_warning` is returned so the operator can provide explicit scope or investigate
- Set `skill` to guide the agent toward a specific methodology
- Use `update_agent` to mark the task as completed or failed when done
