# Tape Recording (JSON-RPC)

Overwatch can capture every JSON-RPC frame exchanged between the MCP client (your IDE / Claude / Codex CLI) and the Overwatch server, writing them to a JSONL **tape**. Tapes are the source of truth for retrospective analysis: they let you replay decisions, audit tool calls, and drive `run_retrospective` with full wire fidelity.

There are two ways to capture, and they coexist:

| Mode | Lives | When to use |
|------|-------|-------------|
| **In-process recorder** (default-off) | Inside the MCP server | Day-to-day operations; toggleable from the dashboard; auto-registers tape sessions with the engagement |
| **Standalone proxy** (`overwatch-mcp-tape`) | Wraps the server externally | Belt-and-suspenders capture; safe even if the server crashes; works against any build |

Both modes write the same JSONL format and are interchangeable for retrospective tooling.

## In-Process Recorder

The in-process recorder is **off by default**. Three independent switches can turn it on; the order of precedence is **env > config > dashboard**. Startup auto-enable applies to both stdio MCP and HTTP MCP transports.

### Enabling at startup

Environment variables:

```bash
# Force on (any truthy value: 1, true, on)
OVERWATCH_TAPE=1 npx overwatch-mcp

# Optional: override default tape directory (defaults to ./tapes)
OVERWATCH_TAPE_DIR=/var/log/overwatch/tapes OVERWATCH_TAPE=1 npx overwatch-mcp

# Optional: pin a single explicit file (overrides directory auto-naming)
OVERWATCH_TAPE_FILE=/var/log/overwatch/tapes/today.jsonl OVERWATCH_TAPE=1 npx overwatch-mcp
```

Engagement config (`engagement.json`):

```json
{
  "tape": {
    "enabled": true,
    "dir": "./tapes",
    "file": null
  }
}
```

`OVERWATCH_TAPE=0` (or `false`/`off`) **forces the recorder off** even when `tape.enabled` is true in the config — useful for ephemeral debugging without editing the engagement file.

When recording starts, Overwatch records why it started:

| `started_by` | Meaning |
|--------------|---------|
| `env` | `OVERWATCH_TAPE=1`, `true`, or `on` enabled recording at startup. |
| `config` | `engagement.tape.enabled: true` enabled recording at startup. |
| `dashboard` | The operator clicked the dashboard Tape toggle or called `POST /api/tape/toggle`. |

### Toggling at runtime (dashboard)

The operator dashboard toolbar shows a **Tape** pill in the top bar:

- Grey: recorder is off.
- Red (pulsing): recorder is on; the pill shows the source and live frame count when available.
- Hover for the active tape file path.

Click to flip state. The toggle calls `POST /api/tape/toggle` (with mutation auth applied for non-loopback dashboards).

### REST API

```
GET  /api/tape           → { enabled, path, session_id, frame_count, started_at, started_by }
POST /api/tape/toggle    → flip state, returns updated status
                         body: { action?: "enable" | "disable",
                                 dir?, file?, session_id? }
```

### Activity log integration

Every enable/disable pair emits a matched `tape_session_started` / `tape_session_stopped` event under `provenance: system`. Both events include `started_by`; the stop event records the `frame_count` and links back to the start event id, so retrospectives can reconstruct exact recording windows from the activity log alone.

## Standalone Proxy

The `overwatch-mcp-tape` binary is the original capture path and lives outside the server process. Use it when you need recording even if the server crashes mid-engagement, or when you want to capture against a build that predates the in-process recorder.

```bash
# Wrap any MCP server invocation. --tape and --out are aliases.
npx overwatch-mcp-tape --tape ./tapes/run.jsonl -- node ./dist/index.js
```

After the run, register the tape with the engagement so `run_retrospective` can find it:

```js
register_tape_session({
  tape_path: "./tapes/run.jsonl",
  session_id: "manual-2026-03-21",
  capture_mode: "proxy",
});
```

The in-process recorder calls this automatically.

### Wiring through your MCP client

To run an entire Claude Code / Codex / IDE session through the proxy, point the client at `overwatch-mcp-tape` instead of `node dist/index.js` and pass the real server as the upstream argv. Example `.mcp.json` (project-scoped):

```json
{
  "mcpServers": {
    "overwatch": {
      "command": "npx",
      "args": [
        "overwatch-mcp-tape",
        "--tape", "/abs/path/overwatch/tapes/session.jsonl",
        "--",
        "node", "/abs/path/overwatch/dist/index.js"
      ],
      "env": {
        "OVERWATCH_CONFIG": "/abs/path/overwatch/engagement.json",
        "OVERWATCH_SKILLS": "/abs/path/overwatch/skills"
      }
    }
  }
}
```

The proxy is a pure passthrough — every JSON-RPC frame the client sends still reaches the server, every response reaches the client. The recording is a side-effect.

### Mode selection

Use the in-process recorder unless you have a specific reason not to. It's lower-friction (toggleable from the dashboard, no extra process), free when disabled, and auto-registers tape sessions with the engagement. Reach for the standalone proxy when:

- The server might crash and you still want the tape (proxy keeps writing as long as the proxy itself stays up).
- You're capturing against a build that predates the in-process recorder.
- You want belt-and-suspenders capture during a sensitive engagement and are willing to pay the ~5–10ms per-frame latency cost of routing through a second process.

Both modes can run simultaneously. The retrospective tooling de-duplicates frames by JSON-RPC `id` so you won't see double counts.

## Tape Format

JSON Lines. One JSON object per frame:

```json
{
  "ts": "2026-03-20T14:22:11.804Z",
  "direction": "client_to_server",
  "parsed": { "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": { ... } }
}
```

Direction values:

- `client_to_server` — request or notification from the IDE/operator.
- `server_to_client` — response, notification, or progress event from Overwatch.

Frames may also include `raw` (when the wire bytes failed to parse cleanly) and `parse_error`. The proxy always includes `raw`; the in-process recorder includes `parsed` because it captures already-decoded `JSONRPCMessage` objects.

### Sample frames

A representative slice of a real tape (formatted across lines for readability — the on-disk form is one JSON object per line):

```jsonc
// Client calls a tool.
{
  "ts": "2026-03-20T14:22:11.804Z",
  "direction": "client_to_server",
  "parsed": {
    "jsonrpc": "2.0", "id": 7,
    "method": "tools/call",
    "params": { "name": "validate_action", "arguments": { "technique": "recon", "target_ip": "10.10.10.5" } }
  }
}

// Server responds.
{
  "ts": "2026-03-20T14:22:11.812Z",
  "direction": "server_to_client",
  "parsed": {
    "jsonrpc": "2.0", "id": 7,
    "result": { "content": [ { "type": "text", "text": "{\"valid\":true,\"action_id\":\"act_…\"}" } ] }
  }
}

// Server-side notification (no id).
{
  "ts": "2026-03-20T14:22:11.815Z",
  "direction": "server_to_client",
  "parsed": {
    "jsonrpc": "2.0",
    "method": "notifications/progress",
    "params": { "progressToken": "...", "progress": 50 }
  }
}

// Bytes that didn't parse — preserved verbatim with the parse_error.
{
  "ts": "2026-03-20T14:22:12.001Z",
  "direction": "client_to_server",
  "raw": "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/cal",
  "parse_error": "unterminated_frame_at_close"
}
```

When debugging an empty or malformed tape, compare your file against this shape: every line should be a single complete JSON object, frames should alternate directions during a request/response pair, and `parse_error` lines indicate either a buggy upstream or the proxy was killed mid-write.

## Retrospectives

Both modes feed the same tooling:

```js
run_retrospective({ since: "2026-03-20T00:00:00Z" });
```

If the active tape was registered (automatic for in-process), the retrospective links each action and finding back to the JSON-RPC frames that produced them.

### Replay-for-retrospective walkthrough

`run_retrospective` is read-only. Given a registered tape and the engagement's activity log, it:

1. Walks the activity log entries in order.
2. For each `action_*` event, finds the matching JSON-RPC frames in the tape (matched by `action_id` carried in the request payload, or by `id` of the `tools/call` request that produced the action).
3. Returns a retrospective object that lists, per action, the wire-level call that produced it, the response the server sent back, and the graph mutation it produced. Findings are linked the same way.

In the dashboard's retrospective panel, this surfaces as a per-action expandable view: action description on top, the JSON-RPC request/response pair underneath, the graph mutation at the bottom. Operators use it to answer "did Claude actually call validate_action before this run_bash, or did the run land directly?"

Note that `run_retrospective` doesn't *execute* anything — it doesn't replay the tape against a live server. See **Replay Semantics** below for why.

## Replay Semantics

Tapes are **audit artifacts, not re-execution scripts**. Replaying a recorded tape against a live target would re-run every action — including destructive ones — because the JSON-RPC frames carry the original commands. For that reason:

- Tapes are read-only by design when consumed by retrospective and audit tooling.
- Golden-master regression tests use **synthetic fixtures**, not recorded tapes against live targets. See `src/__tests__/golden-master/fixtures/` for the canonical shape: a typed list of operations + pinned timestamps. The replay harness asserts byte-identical state hashes across runs (depends on [`engagement_nonce`](configuration.md#durable-transactions-deterministic-ids-and-replay) for deterministic IDs and `withClock` for pinned timestamps).
- For engagements with `engagement_nonce`, the JSON-RPC tape combined with the engagement's config and the activity log is sufficient to reconstruct an audit trail bit-for-bit. Without the nonce (legacy engagements), tapes are still useful for retrospective narration but not for byte-equality checks.

### Tapes vs golden-master fixtures

There are two artifacts in the repo that share the word "tape" but model different things — calling them out so the terminology overlap doesn't trip operators up:

| Artifact | What it is | Used by |
|---|---|---|
| **JSON-RPC tape** (this doc) | Recorded wire frames between MCP client and server. Captures the historical session. | `run_retrospective`, audit |
| **Golden-master fixture** (`src/__tests__/golden-master/fixtures/`) | Synthetic, hand-authored list of typed graph operations + pinned timestamps + expected state hash. | CI determinism check |

A JSON-RPC tape can be sanitized into a fixture for regression tests, but the formats are not interchangeable. See [Determinism and replay](configuration.md#durable-transactions-deterministic-ids-and-replay) for how the golden-master harness uses the engagement nonce.
