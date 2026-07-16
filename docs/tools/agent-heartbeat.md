# agent_heartbeat

Sub-agent liveness ping for the watchdog.

**Read-only:** No (mutates `heartbeat_at` on the task and extends the task's frontier lease)

## Description

Long-running sub-agents call `agent_heartbeat` periodically to signal they're still working. The runtime watchdog ([`AgentWatchdog`](../architecture.md#component-overview)) walks running tasks on an interval and marks any whose `heartbeat_at` is older than `heartbeat_ttl_seconds` (default 120) as `interrupted`, releasing their frontier leases at the same moment.

Tasks that **never** heartbeat are exempt from the watchdog. Tools that complete in a single MCP turn don't need to call this.

Recommended cadence: every 30–60 seconds for any sub-agent that runs longer than the configured TTL.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `task_id` | `string` | yes | Task ID returned from `register_agent` |
| `acknowledged_query_id` | `string` | no | Answer query ID already received and acted on; stops subsequent redelivery |

## Returns

On success:

```json
{
  "ok": true,
  "task_id": "task-abc-123",
  "agent_label": "recon-east",
  "id": "task-abc-123",
  "agent_id": "recon-east",
  "heartbeat_at": "2026-05-07T00:00:00.000Z",
  "heartbeat_ttl_seconds": 120,
  "pending_answer": {
    "query_id": "query-123",
    "question": "Continue with the noisy branch?",
    "answer": "Use the quiet branch"
  }
}
```

After acting on the answer, acknowledge it on a later heartbeat:

```json
{
  "task_id": "task-abc-123",
  "acknowledged_query_id": "query-123"
}
```

On unknown task or terminal state:

```json
{
  "ok": false,
  "error": "task is already in terminal state: completed"
}
```

(Tool returns `isError: true` on the failure path.)

## Side Effects

- Updates `heartbeat_at` on the `AgentTask`.
- Extends the task's frontier lease (P1.4) — a fresh TTL window starts from the heartbeat timestamp.
- Marks `acknowledged_query_id` acknowledged when it belongs to this task, and records delivery of the next pending answer.
- Emits a `heartbeat` activity event with `provenance: 'agent'`. **Heartbeat events are excluded from the hash chain** (high-volume, low-stakes) per `shouldChainEntry` in `activity-chain.ts`.

## Usage Notes

- Call from sub-agents only. The primary agent doesn't need to heartbeat — its liveness is the MCP session itself.
- The watchdog runs on a 30-second interval by default. A heartbeat older than `ttl_seconds` will cause the task to be reaped on the next tick.
- `pending_answer` is redelivered until explicitly acknowledged; match it by `query_id`, act once, then acknowledge on a later heartbeat.
- After `submit_agent_transcript`/`update_agent`, further heartbeats return `{ ok: false }` — the task is already terminal.

## See Also

- [`register_agent`](register-agent.md) — sets up the task.
- [`update_agent`](update-agent.md) — terminal state transitions.
- [Concepts → Agent Heartbeat and Watchdog](../concepts.md#agent-heartbeat-and-watchdog).
