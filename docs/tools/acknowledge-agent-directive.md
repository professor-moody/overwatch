# acknowledge_agent_directive

A sub-agent confirms it received an operator steering directive.

**Read-only:** No (marks the directive acknowledged)

## Description

Operator directives are delivered to a running sub-agent on its [`agent_heartbeat`](agent-heartbeat.md) response as `pending_directive`. After seeing one, the sub-agent calls `acknowledge_agent_directive` to confirm receipt, then acts on it (pause, resume, narrow scope, follow a free-text `instruct`, …). Acknowledging marks the directive so it isn't re-delivered on every subsequent heartbeat.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `task_id` | `string` | yes | Your agent task id |
| `directive_id` | `string` | yes | The directive id from `agent_heartbeat.pending_directive` |

## Returns

```json
{ "ok": true, "task_id": "task-abc", "directive_id": "dir-123", "status": "acknowledged" }
```

## Usage Notes

- Acknowledge promptly, then honor the directive — see the kind table in [`manage_agent_directive`](manage-agent-directive.md).
- `pending_answer` (the reply to an [`ask_operator`](ask-operator.md) question) is **not** acknowledged this way — it is delivered at-least-once and the agent dedups by `query_id`.

## See Also

- [`manage_agent_directive`](manage-agent-directive.md) — how the operator issues directives.
- [`agent_heartbeat`](agent-heartbeat.md) — delivers `pending_directive`.
