# track_process

Register a long-running scan or process for tracking.

**Read-only:** No

## Description

Use this after launching a scan (nmap, bloodhound-python, certipy, etc.) to track its PID. The orchestrator will monitor whether the process is still running and report its status.

This helps coordinate async work — agents can check if their scans are done before attempting to parse output.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pid` | `integer` | Yes | Process ID of the running scan |
| `command` | `string` | Yes | Command that was executed |
| `description` | `string` | Yes | Human-readable description |
| `agent_id` | `string` | No | Agent that launched this process |
| `target_node` | `string` | No | Node ID being targeted |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `process_id` | `string` | Overwatch tracking ID |
| `pid` | `number` | System PID |
| `status` | `string` | Initial status (`running`) |
| `message` | `string` | Confirmation |

## Usage Notes

- Track any long-running scan to coordinate with `check_processes`
- Process state is persisted — survives server restarts
- Associate with `target_node` for graph context
