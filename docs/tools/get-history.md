# get_history

Paginated engagement activity log for retrospectives.

**Read-only:** Yes

## Description

Returns paginated activity log entries for the engagement. Use during retrospectives to review all actions taken, findings reported, inference rules fired, and objectives achieved — with timestamps and agent IDs.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | `integer` | `100` | Maximum entries per page (1–1000) |
| `agent_id` | `string` | — | Filter by specific agent |
| `event_type` | `string` | — | Filter by event type (e.g. `action_validated`, `finding_reported`) |
| `cursor` | `string` | — | `event_id` cursor — fetch entries after this event |
| `direction` | `"oldest_first"` \| `"newest_first"` | `"oldest_first"` | Traversal direction |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `total_entries` | `number` | Total matching entries in the retained log |
| `returned` | `number` | Entries in this page |
| `has_more` | `boolean` | Whether more entries exist after this page |
| `next_cursor` | `string?` | Pass as `cursor` to fetch the next page |
| `direction` | `string` | The direction used |
| `entries` | `array` | Activity log entries for this page |

Each entry includes: `event_id`, `timestamp`, `description`, `agent_id`, `action_id`, `event_type`, `tool_name`, `result_classification`.

## Usage Notes

- Omit `cursor` to start from the beginning (oldest_first) or end (newest_first)
- Pass `next_cursor` from the response as `cursor` to fetch subsequent pages
- Filter by `agent_id` to review a specific agent's work
- Filter by `event_type` to narrow to specific event categories
- Used by `run_retrospective` to generate post-engagement analysis

## Pagination Example

```
# First page
get_history({ limit: 200 })
# → { has_more: true, next_cursor: "evt-abc-123", entries: [...] }

# Next page
get_history({ limit: 200, cursor: "evt-abc-123" })
# → { has_more: false, entries: [...] }
```
