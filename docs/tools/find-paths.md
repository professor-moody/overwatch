# find_paths

Find paths through the graph from current access to objectives or between specific nodes.

**Read-only:** Yes

## Description

Use this to:

- Find the shortest path from compromised hosts to an objective
- Evaluate if a newly discovered credential opens a path
- Compare multiple potential attack routes by confidence

Returns paths with per-hop confidence scores and total path confidence.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `objective_id` | `string` | — | Find paths to this objective node |
| `from_node` | `string` | — | Find paths from this specific node |
| `to_node` | `string` | — | Find paths to this specific node |
| `max_paths` | `integer` | `5` | Maximum paths to return (1–20) |

## Behavior

- If `objective_id` is provided: finds paths from compromised hosts to that objective
- If `from_node` and `to_node` are provided: finds paths between those two nodes
- If neither is provided: finds paths to **all** active (unachieved) objectives

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `paths_found` | `number` | Number of paths discovered |
| `paths` | `array` | Path objects with nodes, edges, and confidence |

Each path includes:

| Field | Type | Description |
|-------|------|-------------|
| `nodes` | `string[]` | Ordered node IDs in the path |
| `edges` | `EdgeType[]` | Edge types along the path |
| `total_confidence` | `number` | Product of all edge confidences |
| `objective` | `string` | Objective description (when searching all objectives) |

## Usage Notes

- Path confidence is the product of individual edge confidences — a path through low-confidence edges will have a low total confidence
- Use this after discovering new credentials or access to evaluate what new paths opened
- Compare multiple paths to choose the most reliable or stealthiest route
