# Session Management Tools

Persistent interactive sessions maintained server-side across MCP tool calls. Supports SSH, local PTY, and TCP socket (bind/reverse shell) transports.

## Architecture

Sessions are long-lived bidirectional I/O channels owned by the Overwatch server process. They survive across individual MCP tool calls but are ephemeral across server restarts (PTY file descriptors cannot be serialized).

**I/O model:** `write_session` (raw bytes) and `read_session` (cursor-based) are the foundation. `send_to_session` is convenience sugar built on top.

**Adapter model:** Transport is decoupled from TTY capability. A reverse shell starts as `tty_quality: 'dumb'` and can be upgraded after `python3 -c 'import pty; ...'` + stty.

## Tools

### `open_session`

Create a new persistent session.

| Parameter | Type | Description |
|-----------|------|-------------|
| `kind` | `ssh \| local_pty \| socket` | Session transport type |
| `title` | string | Human-readable label |
| `host` | string? | Target host (required for ssh, socket connect) |
| `port` | number? | Target port (required for socket) |
| `user` | string? | SSH username |
| `key_path` | string? | Path to SSH private key |
| `password` | string? | SSH password (via sshpass — prefer keys) |
| `ssh_options` | string[]? | Additional SSH `-o` options |
| `shell` | string? | Shell for local_pty (default: `$SHELL` or `/bin/bash`) |
| `cwd` | string? | Working directory for local_pty |
| `mode` | `connect \| listen`? | Socket mode |
| `cols` | number? | Terminal columns (default: 120) |
| `rows` | number? | Terminal rows (default: 30) |
| `agent_id` | string? | Owning agent (sets `claimed_by`) |
| `target_node` | string? | Graph node ID this session targets |

Returns session metadata + initial output as `SessionReadResult`.

> **Scope check:** If `host` resolves to an out-of-scope address, the session is still created but the response includes a `scope_warning` field. This is advisory — sessions are never blocked by scope.

### `write_session`

Write raw bytes to a session. The I/O primitive.

| Parameter | Type | Description |
|-----------|------|-------------|
| `session_id` | string | Session to write to |
| `data` | string | Data to write |
| `append_newline` | boolean? | Append `\n` after data (default: false) |
| `agent_id` | string? | Checked against `claimed_by` |
| `force` | boolean? | Override ownership check |

Returns `{ session_id, end_pos }`.

### `read_session`

Cursor-based read from session output buffer.

| Parameter | Type | Description |
|-----------|------|-------------|
| `session_id` | string | Session to read from |
| `from_pos` | number? | Absolute buffer position (for incremental reads) |
| `tail_bytes` | number? | Read last N bytes when `from_pos` omitted (default: 4096) |

Returns `SessionReadResult`: `{ session_id, start_pos, end_pos, text, truncated }`.

**Cursor pattern:** Track `end_pos` from each read. Pass it as `from_pos` on the next read to get only new output.

### `send_to_session` *(experimental)*

Convenience: write command + wait for output to settle + return captured output.

| Parameter | Type | Description |
|-----------|------|-------------|
| `session_id` | string | Session ID |
| `command` | string | Command (newline appended automatically) |
| `timeout_ms` | number? | Max wait (default: 10000) |
| `idle_ms` | number? | Return after this much silence (default: 500) |
| `wait_for` | string? | Regex — return immediately on match |
| `agent_id` | string? | Checked against `claimed_by` |
| `force` | boolean? | Override ownership check |

For password prompts, REPLs, or streaming tools (`tail -f`, `tcpdump`), use `write_session` + `read_session` directly.

### `list_sessions`

List sessions with metadata.

| Parameter | Type | Description |
|-----------|------|-------------|
| `active_only` | boolean? | Only pending/connected (default: false) |
| `session_id` | string? | Get details for one session |
| `agent_id` | string? | Filter to sessions claimed by this agent (or unclaimed) |

### `update_session`

Update session metadata after changes (e.g., shell upgrade).

| Parameter | Type | Description |
|-----------|------|-------------|
| `session_id` | string | Session to update |
| `tty_quality` | `none \| dumb \| partial \| full`? | Updated TTY quality |
| `supports_resize` | boolean? | Whether resize now works |
| `supports_signals` | boolean? | Whether signals now work |
| `title` | string? | New title |
| `claimed_by` | string? | Transfer ownership |
| `notes` | string? | Operational notes |
| `agent_id` | string? | Checked against `claimed_by` |
| `force` | boolean? | Override ownership check |

### `resize_session`

Resize terminal dimensions (PTY sessions only).

| Parameter | Type | Description |
|-----------|------|-------------|
| `session_id` | string | Session ID |
| `cols` | number | New column count |
| `rows` | number | New row count |
| `agent_id` | string? | Checked against `claimed_by` |
| `force` | boolean? | Override ownership check |

### `signal_session`

Send a signal to the session process (PTY sessions only).

| Parameter | Type | Description |
|-----------|------|-------------|
| `session_id` | string | Session ID |
| `signal` | `SIGINT \| SIGTERM \| SIGKILL \| SIGTSTP \| SIGCONT` | Signal to send |
| `agent_id` | string? | Checked against `claimed_by` |
| `force` | boolean? | Override ownership check |

### `close_session`

Close and destroy a session.

| Parameter | Type | Description |
|-----------|------|-------------|
| `session_id` | string | Session to close |
| `agent_id` | string? | Checked against `claimed_by` |
| `force` | boolean? | Override ownership check |

Returns final output snapshot + session summary (duration, total bytes).

## Session States

```
pending → connected → closed
                   → error
```

- **pending**: Socket session waiting for connection (listen/connect mode)
- **connected**: Active session, I/O available
- **closed**: Session terminated (normal exit or operator close)
- **error**: Adapter failure

## TTY Quality Levels

| Level | Description | Resize | Signals | Example |
|-------|-------------|--------|---------|---------|
| `none` | No terminal | ✗ | ✗ | Non-interactive exec |
| `dumb` | Raw I/O | ✗ | ✗ | Raw reverse shell |
| `partial` | Line editing | ✗ | ✗ | After `python3 -c 'import pty; ...'` |
| `full` | Full PTY | ✓ | ✓ | SSH, local shell, fully upgraded shell |

## Ownership

Sessions have a `claimed_by` field (agent ID). Only the claiming agent can write or control the session. Any agent can read. Use `update_session` to transfer ownership or `force: true` to override.

## Examples

### SSH session
```
open_session(kind="ssh", title="target-dc01", host="10.10.110.5", user="admin", key_path="/root/.ssh/id_rsa")
→ session.id = "abc-123"

send_to_session(session_id="abc-123", command="whoami")
→ { text: "admin\n$", end_pos: 42 }
```

### Reverse shell catch
```
open_session(kind="socket", title="revshell-web01", mode="listen", port=4444)
→ state: "pending"

# Target connects back...
list_sessions(session_id="abc-456")
→ state: "connected", tty_quality: "dumb"

write_session(session_id="abc-456", data="python3 -c 'import pty; pty.spawn(\"/bin/bash\")'", append_newline=true)
read_session(session_id="abc-456", from_pos=0)

update_session(session_id="abc-456", tty_quality="partial")
```

### Incremental reads
```
write_session(session_id="abc-123", data="nmap -sV 10.10.110.0/24", append_newline=true)
→ { end_pos: 100 }

# Poll for output
read_session(session_id="abc-123", from_pos=100)
→ { text: "Starting Nmap...", end_pos: 200, truncated: false }

read_session(session_id="abc-123", from_pos=200)
→ { text: "...scan complete", end_pos: 500, truncated: false }
```
