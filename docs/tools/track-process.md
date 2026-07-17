# track_process

Register a long-running scan or process for tracking.

**Read-only:** No

## Description

Use this after launching a scan (nmap, bloodhound-python, certipy, etc.) to track its PID. The orchestrator will monitor whether the process is still running and report its status.

This helps coordinate async work — agents can check if their scans are done before attempting to parse output.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pid` | positive `integer` | Yes | Process ID of the running scan |
| `command` | `string` | Yes | Command that was executed |
| `description` | `string` | Yes | Human-readable description |
| `agent_id` | `string` | No | Agent that launched this process |
| `target_node` | `string` | No | Node ID being targeted |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `process_id` | `string` | Overwatch tracking ID |
| `run_id` | `string` | Durable runtime ownership ID (same value as `process_id`) |
| `pid` | `number` | System PID |
| `status` | `string` | `running` only when the physical identity is verifiable; otherwise `unknown` |
| `ownership_mode` | `string` | `external_adopted` |
| `signal_scope` | `string` | `none` |
| `message` | `string` | Confirmation |

## Usage Notes

- Track any long-running scan to coordinate with `check_processes`
- The tracking descriptor is persisted and its physical identity is reverified after restart
- Associate with `target_node` for graph context
- `task_id` and `action_id` can link the process to canonical coordination and action records
- Adopted processes are observed, not owned: Overwatch never signals them after restart
- A dead PID, reused PID, or unverifiable identity is reported as `unknown`, never as successful completion
