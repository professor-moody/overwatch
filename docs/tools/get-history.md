# get_history

Full engagement activity log for retrospectives.

**Read-only:** Yes

## Description

Returns the full activity log for the engagement. Use during retrospectives to review all actions taken, findings reported, inference rules fired, and objectives achieved — with timestamps and agent IDs.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | `integer` | `100` | Maximum entries to return (1–1000) |
| `agent_id` | `string` | — | Filter by specific agent |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `total_entries` | `number` | Total history entries |
| `entries` | `array` | Activity log entries (most recent `limit`) |

Each entry includes: `event_id`, `timestamp`, `description`, `agent_id`, `action_id`, `event_type`, `tool_name`, `result_classification`.

## Usage Notes

- Returns the most recent entries up to `limit`
- Filter by `agent_id` to review a specific agent's work
- Used by `run_retrospective` to generate post-engagement analysis
