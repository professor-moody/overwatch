# log_action_event

Record a structured action lifecycle event for work Overwatch cannot observe directly.

**Read-only:** No

## Description

Ties together what was planned, what tool actually ran, which targets were involved, and whether the action succeeded or failed. This creates an auditable execution trace.

Recommended flow:

1. `action_planned` — before major execution
2. `action_started` — when a real tool launches
3. `action_completed` or `action_failed` — when the action resolves

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `event_type` | `string` | Yes | `action_planned`, `action_started`, `action_completed`, or `action_failed` |
| `description` | `string` | Yes | Human-readable description of the action event |
| `action_id` | `string` | No* | Stable action ID. **Required** for non-planned events. |
| `agent_id` | `string` | No | Agent or session responsible |
| `tool_name` | `string` | No | Tool actually used (e.g., `nmap`, `nxc`) |
| `technique` | `string` | No | Technique category (e.g., `password-spray`, `smb-enum`) |
| `target_node_ids` | `string[]` | No | Primary graph node IDs targeted |
| `frontier_item_id` | `string` | No | Frontier item this action came from |
| `linked_agent_task_id` | `string` | No | Associated agent task ID |
| `result_classification` | `string` | No | `success`, `failure`, `partial`, or `neutral` |
| `details` | `object` | No | Additional structured context |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `event_id` | `string` | Unique event identifier |
| `action_id` | `string` | The action ID used |
| `event_type` | `string` | Event type recorded |
| `frontier_type` | `string` | Frontier item type (if linked) |
| `tool_name` | `string` | Tool name (if provided) |
| `result_classification` | `string` | Outcome classification (if provided) |

## Usage Notes

- `action_id` is auto-generated for `action_planned` events if not provided
- For all other event types, `action_id` is required (links back to the planned/validated action)
- These events feed into `get_history` and `run_retrospective`
- Use `result_classification` on `action_completed`/`action_failed` for retrospective analysis
- **Collision guard:** The server tracks which `agent_id` established each `action_id` → `frontier_item_id` mapping. If a different agent reuses the same `action_id`, the auto-threading is suppressed and an `instrumentation_warning` is logged instead of silently overwriting the mapping
