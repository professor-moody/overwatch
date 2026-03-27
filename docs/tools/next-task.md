# next_task

Returns frontier items (candidate next actions) with graph context attached.

**Read-only:** No (triggers frontier computation)

## Description

The deterministic layer has already filtered out:

- Out-of-scope targets
- Duplicate/already-tested actions
- Actions exceeding OPSEC hard noise limits
- Dead hosts

Everything else passes through for the LLM's analysis. Each item includes graph metrics (hops to objective, fan-out estimate, node degree, confidence, OPSEC noise rating).

The LLM's job is to:

1. Score and rank these by overall value
2. Spot multi-step attack chains across items
3. Consider sequencing (what should happen first)
4. Assess likely defenses and risks
5. Recommend specific actions for the top items

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_items` | `integer` | `20` | Maximum frontier items to return (1–50) |
| `include_filtered` | `boolean` | `false` | Also return items that were filtered out, with reasons |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `candidate_count` | `number` | Total candidates after filtering |
| `candidates` | `FrontierItem[]` | Frontier items with graph metrics |
| `filtered_count` | `number` | Number filtered out (if `include_filtered`) |
| `filtered` | `array` | Filtered items with reasons (if `include_filtered`) |

### FrontierItem

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Unique frontier item ID |
| `type` | `string` | `incomplete_node`, `untested_edge`, or `inferred_edge` |
| `description` | `string` | Human-readable description |
| `graph_metrics.hops_to_objective` | `number\|null` | Shortest path to any objective |
| `graph_metrics.fan_out_estimate` | `number` | How many new nodes this could expose |
| `graph_metrics.node_degree` | `number` | Connected edges |
| `graph_metrics.confidence` | `number` | Current confidence |
| `opsec_noise` | `number` | Estimated noise (0.0–1.0) |
| `staleness_seconds` | `number` | Time since last update |
| `community_id` | `number` | Louvain community this node belongs to |
| `community_unexplored_count` | `number` | Unexplored frontier items in the same community |

## Usage Notes

- Call this to decide what to do next — the core of the engagement loop
- Set `include_filtered: true` to understand what was rejected and why
- Pair with `validate_action` before executing any chosen task
