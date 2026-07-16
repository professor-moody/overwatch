# ask_operator

A running sub-agent escalates a decision to the human operator and waits for an answer.

**Read-only:** No (records a question; the answer is delivered back on the agent's heartbeat)

## Description

When a sub-agent hits a genuine fork it can't resolve — an ambiguous path, a risky/irreversible step, missing context — it calls `ask_operator` and then **waits by heartbeating**. There is no new blocking transport: the question is recorded in the engine-owned `AgentQueryStore`, the operator answers it in the **Agent Questions** inbox in the cockpit, and the answer is delivered on the agent's next [`agent_heartbeat`](agent-heartbeat.md) response as `pending_answer`.

Delivery is **at-least-once**: the answer is re-offered on every heartbeat (a dropped heartbeat self-heals), so the agent must match `pending_answer.query_id` to the `query_id` this call returned, act on a given answer **once**, then pass that query ID as `acknowledged_query_id` on a later heartbeat.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `task_id` | `string` | yes | Your agent task id |
| `question` | `string` | yes | The question for the operator — specific and self-contained |
| `agent_id` | `string` | no | Your agent id (attribution) |
| `options` | `string[]` | no | Suggested answers the operator can pick from |

## Returns

```json
{ "ok": true, "query_id": "uuid", "status": "open",
  "note": "Keep heartbeating; after acting on pending_answer, acknowledge it with acknowledged_query_id." }
```

The answer arrives later, on a heartbeat:

```json
{ "ok": true, "task_id": "task-abc", "pending_answer": { "query_id": "uuid", "question": "...", "answer": "stay quiet" } }
```

After acting:

```json
{ "task_id": "task-abc", "acknowledged_query_id": "uuid" }
```

## Side Effects

- Records an open question in the durable `AgentQueryStore` with an absolute 30-minute TTL.
- Emits an `agent_query` activity event and a WS `agent_query` push so the operator inbox lights up live.
- The question and its answer/acknowledgement outcome survive restart. Running steps do not regain time: recovery keeps the original expiry.
- Still-actionable questions are **marked expired automatically** when the asking task reaches a terminal state (completed / reaped by the heartbeat watchdog / wall-clock timeout), so a dead agent's question never lingers in the inbox.

## Usage Notes

- Only escalate real forks — not routine decisions.
- Bound your wait to a few minutes of heartbeats; if no answer arrives, make the safest reasonable choice and note that you proceeded without one.
- Available to the `default`, `research`, and `planner` roles.

## See Also

- [Operator Cockpit](../operator-cockpit.md#escalation) — the escalation flow and inbox.
- [`agent_heartbeat`](agent-heartbeat.md) — carries `pending_answer` back to the agent.
