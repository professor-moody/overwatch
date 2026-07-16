# Session Management Tools

Persistent interactive sessions maintained server-side across MCP tool calls. Supports SSH, local PTY, and TCP socket (bind/reverse shell) transports.

## Architecture

Sessions are long-lived bidirectional I/O channels owned by the Overwatch
server process. Live PTYs, sockets, buffers, secrets, and process handles are
ephemeral. Secret-free descriptors survive restart: owner, targets, validation
defaults, capabilities, listener intent, and accepted-connection generations.

A rearmed socket listener is restored as `resume_available` and remains inert
until the operator explicitly resumes it. Each accepted connection has a fresh
generation identity and its own `HAS_SESSION` liveness reference.

**I/O model:** `write_session` (raw bytes) and `read_session` (cursor-based) are the low-level primitives. `send_to_session` is the audited command path: it writes a command, waits for output, persists captured evidence, and emits action lifecycle events.

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
| `principal_node` | string? | Principal associated with the session, when known |
| `credential_node` | string? | Credential used for the session, when known |
| `action_id` | string? | Existing action ID to associate with the session open |
| `frontier_item_id` | string? | Frontier item associated with the session open |
| `default_validation` | object? | Baseline `technique`, `target_ip`, `target_url`, `target_node`, `allow_unverified_scope`, and `noise_estimate` inherited by later `send_to_session` calls |
| `mock_service_purpose` | enum? | When opening a `socket`/`listen` session, auto-register it as an operator-controlled `mock_service`. See [`register_mock_service`](register-mock-service.md). |
| `mock_service_protocol` | string? | Wire protocol of the mock service (defaults to socket protocol). |
| `mock_service_notes` | string? | Free-form notes carried onto the `mock_service` node. |

Returns `{ session, initial_output, mock_service? }` — `session` is the full session metadata object and `initial_output` is a `SessionReadResult` with the first bytes of output. When `mock_service_purpose` is set the response also contains `mock_service: { mock_service_id, new }` and the session's `capabilities.serves_mock_service_id` is stamped, enabling dashboard pivot session ↔ listener.

> **Scope check:** Remote sessions (SSH and socket connect mode) are **scope-enforced and fail closed**. If `host` resolves to an out-of-scope address, the request is rejected with an error containing `scope_reason: "host_out_of_scope"`. Local PTY and socket listen sessions are not scope-checked.

> **Default validation:** For SSH and socket-connect sessions, pass `default_validation` when opening the session. Later `send_to_session` calls inherit it and can run the full validate → started → evidence → completed lifecycle without repeating target metadata on every command.

### `write_session`

Write raw bytes to a session. The I/O primitive.

| Parameter | Type | Description |
|-----------|------|-------------|
| `session_id` | string | Session to write to |
| `data` | string | Data to write |
| `append_newline` | boolean? | Append `\n` after data (default: false) |
| `agent_id` | string? | Checked against `claimed_by` |
| `force` | boolean? | Override ownership check |
| `connection_id` | string? | Expected live generation ID; rejects if the listener reconnected |
| `connection_generation` | number? | Expected generation number |

Returns `{ session_id, connection_id, connection_generation, end_pos }`.

### `read_session`

Cursor-based read from session output buffer.

| Parameter | Type | Description |
|-----------|------|-------------|
| `session_id` | string | Session to read from |
| `from_pos` | number? | Absolute buffer position (for incremental reads) |
| `tail_bytes` | number? | Read last N bytes when `from_pos` omitted (default: 4096) |
| `connection_id` | string? | Expected live generation ID |
| `connection_generation` | number? | Expected generation number |

Returns `SessionReadResult`: `{ session_id, connection_id,
connection_generation, start_pos, end_pos, text, truncated, cursor_reset? }`.

**Cursor pattern:** Track `end_pos`, `connection_id`, and
`connection_generation` from each read. Pass them on the next read to get only
new output and reject a stale generation. Positions remain monotonic across
same-process listener reconnects. `cursor_reset: true` means a supplied cursor
was ahead of the current retained generation buffer and the read restarted at
its first available byte.

### `send_to_session`

Instrumented command send: validate scope, write command, wait for output to settle, persist captured output as evidence, and record action lifecycle events.

Uses a two-phase wait: first waits for any output to arrive after the command is written (up to `timeout_ms`), then uses idle settling — returns once no new output has arrived for `idle_ms` consecutive milliseconds. This prevents early empty returns on slow-starting commands.

| Parameter | Type | Description |
|-----------|------|-------------|
| `session_id` | string | Session ID |
| `command` | string | Command (newline appended automatically) |
| `timeout_ms` | number? | Max wait (default: 10000) |
| `idle_ms` | number? | Return after this much silence *after first output* (default: 500) |
| `wait_for` | string? | Regex — return immediately on match |
| `agent_id` | string? | Checked against `claimed_by` |
| `force` | boolean? | Override ownership check |
| `technique` | string? | Per-command technique override. Required when no session `default_validation.technique` exists |
| `target_ip` | string? | Per-command target IP override |
| `target_url` | string? | Per-command target URL override |
| `target_node` | string? | Per-command target node override |
| `allow_unverified_scope` | boolean? | Allow intentional commands whose target cannot be verified |
| `noise_estimate` | number? | Per-command OPSEC noise estimate |
| `frontier_item_id` | string? | Frontier item for attribution |
| `action_id` | string? | Existing action ID to continue |

Returns the captured text and cursor positions plus action metadata such as `action_id`, `evidence_id`, `validation_result`, and `completion_reason`.

For password prompts, REPL navigation, or streaming tools (`tail -f`, `tcpdump`), use `write_session` + `read_session` directly because those are partial I/O operations rather than command-shaped actions.

### `list_sessions`

List sessions with metadata. Always returns an envelope `{ total, active, sessions }`, even for single-session lookups via `session_id`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `active_only` | boolean? | Only pending/connected (default: false) |
| `session_id` | string? | Get details for one session |
| `agent_id` | string? | Filter to sessions claimed by this agent (or unclaimed) |

The additive metadata includes `listener_id`, `connection_generation`,
`connection_id`, `last_connection_id`, `last_connection_state`, and
`resume_policy`. `active` counts only actually bound waiting listeners and live
connections (`pending` and `connected`); `resume_available` is actionable but
not live.

### `resume_session`

Explicitly rebind a recovered rearm socket listener.

| Parameter | Type | Description |
|-----------|------|-------------|
| `session_id` | string | Listener descriptor in `resume_available` state |
| `agent_id` | string? | Checked against `claimed_by` |
| `force` | boolean? | Override ownership check |

Returns `{ resumed: true, session }`. The stable listener/session ID and
generation counter are preserved. The result is `pending`; it becomes
`connected` only after a new target connects. Duplicate or invalid-state resume
requests fail with a conflict and never create a second listener.

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

```text
resume_available --resume_session--> pending --accept--> connected
                                            ^              |
                                            |--disconnect--|

connected --restart/shutdown--> interrupted       (non-listener)
connected --restart/shutdown--> resume_available  (rearm listener)
pending   --restart/shutdown--> resume_available  (rearm listener)
any live state --operator close / idle reap--> closed
adapter or cleanup failure --> error
```

- **pending**: A listener is actually bound and waiting for a connection
- **connected**: Active session, I/O available
- **resume_available**: Durable listener intent exists, but no socket is bound;
  explicit Resume is required
- **interrupted**: A non-resumable connection existed before restart/shutdown;
  no live handle or graph access is claimed
- **closed**: Session terminated (normal exit or operator close)
- **error**: Adapter failure

Disconnecting a rearmed listener closes only the current connection generation
and its `HAS_SESSION` reference. The listener returns to `pending`. Reconnect
increments `connection_generation`, creates a fresh buffer, and opens a fresh
generation-bound graph reference.

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
open_session(
  kind="ssh",
  title="target-dc01",
  host="10.10.110.5",
  user="admin",
  key_path="/root/.ssh/id_rsa",
  default_validation={ technique="ssh_command", target_ip="10.10.110.5" }
)
→ session.id = "abc-123"

send_to_session(session_id="abc-123", command="whoami")
→ { action_id: "act_...", evidence_id: "ev_...", text: "admin\n$", end_pos: 42 }
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
