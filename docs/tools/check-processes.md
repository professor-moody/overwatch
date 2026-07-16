# check_processes

List tracked processes and their current status.

**Read-only:** Yes

## Description

Verifies that each running PID still has the same physical start identity and
process group recorded at registration. Use this to see whether scans are still
provably live before parsing their output.

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

Each process includes: `id`, `pid`, `command`, `description`, `status`,
ownership/identity metadata, `task_id`, `action_id`, `agent_id`, `target_node`,
`started_at`, `completed_at`, and an optional `recovery_warning`.

## Usage Notes

- Call before attempting to parse output from a tracked scan
- Status is refreshed on each call — no need for manual polling
- Use `active_only: true` to see only what's still running
- PID existence alone is insufficient because operating systems reuse PIDs
- Disappearance, reuse, or unverifiable identity becomes `unknown`; only the launcher can report `completed` or `failed`
