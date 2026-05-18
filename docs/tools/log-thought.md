# log_thought

Persist agent reasoning into the activity log.

**Read-only:** No

## Description

Records plans, hypotheses, decisions, rejections, observations, reflections, or notes as structured `thought` events. These entries make post-engagement retrospectives and compaction recovery explainable without mutating the graph.

Always include `frontier_item_id` when the thought concerns a specific candidate from [`next_task`](next-task.md).

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `thought` | string | required | The reasoning text. |
| `kind` | enum | `note` | `plan`, `hypothesis`, `observation`, `decision`, `rejection`, `reflection`, or `note`. |
| `agent_id` | string? | | Agent or session producing the thought. |
| `frontier_item_id` | string? | | Frontier item this thought concerns. |
| `action_id` | string? | | Action associated with the thought. |
| `related_action_ids` | string[]? | | Related actions. |
| `target_node_ids` | string[]? | | Graph nodes this thought concerns. |
| `considered_alternatives` | string[]? | | Alternatives weighed for decisions or rejections. |
| `confidence` | number? | | Subjective confidence from 0.0 to 1.0. |
| `tags` | string[]? | | Free-form filter tags. |
