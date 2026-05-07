# Tape Recording (JSON-RPC)

Overwatch can capture every JSON-RPC frame exchanged between the MCP client (your IDE / Claude / Codex CLI) and the Overwatch server, writing them to a JSONL **tape**. Tapes are the source of truth for retrospective analysis: they let you replay decisions, audit tool calls, and drive `run_retrospective` with full wire fidelity.

There are two ways to capture, and they coexist:

| Mode | Lives | When to use |
|------|-------|-------------|
| **In-process recorder** (default-off) | Inside the MCP server | Day-to-day operations; toggleable from the dashboard; auto-registers tape sessions with the engagement |
| **Standalone proxy** (`overwatch-mcp-tape`) | Wraps the server externally | Belt-and-suspenders capture; safe even if the server crashes; works against any build |

Both modes write the same JSONL format and are interchangeable for retrospective tooling.

## In-Process Recorder

The in-process recorder is **off by default**. Three independent switches can turn it on; the order of precedence is **env > config > dashboard**.

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

### Toggling at runtime (dashboard)

The operator dashboard toolbar shows a **Tape** pill in the top bar:

- Grey: recorder is off.
- Red (pulsing): recorder is on; the pill shows the live frame count.
- Hover for the active tape file path.

Click to flip state. The toggle calls `POST /api/tape/toggle` (with mutation auth applied for non-loopback dashboards).

### REST API

```
GET  /api/tape           → { enabled, path, session_id, frame_count, started_at }
POST /api/tape/toggle    → flip state, returns updated status
                         body: { action?: "enable" | "disable",
                                 dir?, file?, session_id? }
```

### Activity log integration

Every enable/disable pair emits a matched `tape_session_started` / `tape_session_stopped` event under `provenance: system`. The stop event records the `frame_count` and links back to the start event id, so retrospectives can reconstruct exact recording windows from the activity log alone.

## Standalone Proxy

The `overwatch-mcp-tape` binary is the original capture path and lives outside the server process. Use it when you need recording even if the server crashes mid-engagement, or when you want to capture against a build that predates the in-process recorder.

```bash
# Wrap any MCP server invocation
npx overwatch-mcp-tape --out ./tapes/run.jsonl -- npx overwatch-mcp
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

## Retrospectives

Both modes feed the same tooling:

```js
run_retrospective({ since: "2026-03-20T00:00:00Z" });
```

If the active tape was registered (automatic for in-process), the retrospective links each action and finding back to the JSON-RPC frames that produced them.

## Replay Semantics

Tapes are **audit artifacts, not re-execution scripts**. Replaying a recorded tape against a live target would re-run every action — including destructive ones — because the JSON-RPC frames carry the original commands. For that reason:

- Tapes are read-only by design when consumed by retrospective and audit tooling.
- Golden-master regression tests use **synthetic fixtures**, not recorded tapes against live targets. See `src/__tests__/golden-master/fixtures/` for the canonical shape: a typed list of operations + pinned timestamps. The replay harness asserts byte-identical state hashes across runs (depends on [`engagement_nonce`](configuration.md#deterministic-id-and-replay) for deterministic IDs and `withClock` for pinned timestamps).
- For engagements with `engagement_nonce`, the JSON-RPC tape combined with the engagement's config and the activity log is sufficient to reconstruct an audit trail bit-for-bit. Without the nonce (legacy engagements), tapes are still useful for retrospective narration but not for byte-equality checks.
