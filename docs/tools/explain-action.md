# explain_action

"Why did the agent do X?" — full causality chain for any action_id.

**Read-only:** Yes

## Description

Aggregates everything the engine knows about a single `action_id` into one answer-shaped record:

- The frontier item that motivated it
- The agent's `log_thought` chain on that action
- Alternatives the agent claimed to consider (lifted from `details.considered_alternatives`)
- Prior `action_id`s the thoughts referenced (causal chain via `details.related_action_ids`)
- Validation result (errors, warnings)
- Approval result (when queued through the gate)
- Terminal outcome (`completed` / `failed` with classification)

All data already lives in the activity log; this tool just projects it into a structured answer. Self-references (an action's thoughts referencing its own id) are filtered out of `prior_actions_referenced`.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `action_id` | `string` | yes | The action to explain. Comes from any node/edge's `discovered_by_action_id`, from a [`get_decision_log`](get-decision-log.md) entry, or from `get_history` |

## Returns

```json
{
  "action_id": "act_a1b2c3d4e5f6",
  "found": true,
  "agent_id": "sub-recon-1",
  "frontier_item_id": "fi-host-10-10-10-5",
  "frontier_item": { "id": "fi-host-10-10-10-5", "type": "incomplete_node", "..." },
  "log_thought_chain": [
    {
      "event_id": "evt_...",
      "timestamp": "2026-05-07T00:00:01.000Z",
      "kind": "decision",
      "description": "Going with nmap -sV before brute-forcing — quieter and confirms version.",
      "confidence": 0.7
    }
  ],
  "considered_alternatives": ["nmap -sV", "enum4linux", "rpcclient"],
  "prior_actions_referenced": ["act_prev1", "act_prev2"],
  "validation": {
    "event_id": "evt_...",
    "timestamp": "2026-05-07T00:00:02.000Z",
    "validation_result": "valid",
    "errors": [],
    "warnings": []
  },
  "approval": {
    "event_id": "evt_...",
    "timestamp": "2026-05-07T00:00:02.000Z",
    "approval_status": "approved",
    "auto_approved": false
  },
  "outcome": {
    "event_id": "evt_...",
    "timestamp": "2026-05-07T00:01:00.000Z",
    "classification": "success",
    "description": "Completed: nmap -sV 10.10.10.5"
  }
}
```

If the action_id is unknown, returns `{"found": false, …}` with empty arrays. The tool also returns `isError: true` in that case so callers can distinguish "no data" from "successfully empty."

## Field Notes

| Field | Notes |
|-------|-------|
| `frontier_item` | Best-effort: the frontier-item snapshot at registration is not persisted, so this is the **current** frontier-item record. May be `undefined` if the item has since been pruned. |
| `log_thought_chain` | Ordered oldest-first |
| `considered_alternatives` | Deduplicated across all thoughts on this action_id |
| `prior_actions_referenced` | Self-references filtered out |
| `validation` | The most recent `action_validated` event for this action_id — usually exactly one |
| `approval` | Present only when validation went through the queue; carries `approval_status`, `auto_approved`, `operator_notes`, `reason` |
| `outcome` | The latest `action_completed` / `action_failed` event |

## Usage Notes

- Pair with [`get_decision_log`](get-decision-log.md): list decisions, then drill into one with `explain_action`.
- The tool is read-only and pure — calling it many times with the same `action_id` always returns the same shape.
- For "what was true at time T" rather than "why did this action happen", use [`get_timeline`](get-timeline.md).

## See Also

- [`log_thought`](../concepts.md#action-lifecycle) — what feeds the `log_thought_chain`
- [`get_decision_log`](get-decision-log.md) — multi-decision view
- [`get_history`](get-history.md) — raw event timeline
