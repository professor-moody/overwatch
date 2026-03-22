# check_processes

List tracked processes and their current status.

**Read-only:** Yes

## Description

Automatically checks if running PIDs are still alive and updates status. Use this to see if scans have completed before parsing their output.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `active_only` | `boolean` | `false` | Only show currently running processes |
| `process_id` | `string` | — | Check a specific tracked process by ID |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `active` | `number` | Number of running processes |
| `completed` | `number` | Number of completed processes |
| `processes` | `array` | Process details (filtered by params) |

Each process includes: `id`, `pid`, `command`, `description`, `status`, `agent_id`, `target_node`, `started_at`, `completed_at`.

## Usage Notes

- Call before attempting to parse output from a tracked scan
- Status is refreshed on each call — no need for manual polling
- Use `active_only: true` to see only what's still running
