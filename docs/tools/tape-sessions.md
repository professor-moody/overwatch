# register_tape_session

Register an external JSON-RPC tape.

**Read-only:** No

## Description

Registers a tape captured by the standalone `overwatch-mcp-tape` proxy. The tape stays on disk outside the server; this tool records a pointer and a small manifest in the activity log so retrospectives can locate it.

Large tapes are streamed for line counts and fingerprinting. The contents are not loaded into the graph by this call.

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `tape_path` | string | Absolute or workspace-relative path to the tape JSONL file. |
| `session_id` | string | Human-readable identifier for the captured session. |
| `upstream_command` | string? | Command wrapped by the tape proxy. |
| `notes` | string? | Operator notes. |

## Returns

Returns the emitted event ID, resolved tape path, size, line count, and head/tail fingerprint.
