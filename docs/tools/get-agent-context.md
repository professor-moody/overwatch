# get_agent_context

Returns the scoped subgraph view for a registered agent.

**Read-only:** Yes

## Description

Agents call this to receive only the nodes and edges relevant to their task, plus N-hop neighbors for context. Automatically includes credentials and services connected to hosts in the subgraph. This keeps agent context focused and prevents scope creep.

If the agent was registered without explicit `subgraph_node_ids`, the subgraph is auto-computed from the frontier item's target node(s).

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `task_id` | `string` | — | Task ID returned from `register_agent` (required) |
| `hops` | `integer` | `2` | Number of hops from seed nodes to include (1–5) |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `task_id` | `string` | Task identifier |
| `agent_id` | `string` | Agent identifier |
| `frontier_item_id` | `string` | Associated frontier item |
| `skill` | `string` | Assigned skill (if any) |
| `subgraph` | `ExportedGraph` | Scoped nodes and edges |
| `message` | `string` | Summary of subgraph size |

## Usage Notes

- Call this at the start of every sub-agent session to get scoped context
- Increase `hops` if the agent needs broader context (at the cost of a larger subgraph)
- The subgraph includes credential and service nodes connected to any host in scope — agents don't need to query for these separately
