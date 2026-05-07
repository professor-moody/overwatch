# get_decision_log

Derived per-decision timeline over the activity log.

**Read-only:** Yes

## Description

Returns the engagement's **decision log** — one entry per decision, with the decision's full chain of stages: `frontier_emitted → agent_picked → log_thought → validated → approved/denied → started → completed/failed`.

Use this to answer "what did the agent do, and why?" Each `DecisionEntry` references the underlying activity events by `event_id` (`stages[i].details_ref`); call [`get_history`](get-history.md) or [`explain_action`](explain-action.md) to drill into individual stages.

The decision log is a **pure derivation** — no separate persistence. Each call walks the activity log + frontier-linkage state and rebuilds the view.

## Parameters

All filters are optional; combining them ANDs the conditions.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `frontier_item_id` | `string` | — | Filter to decisions that touched this frontier item |
| `action_id` | `string` | — | Filter to a specific action_id |
| `agent_id` | `string` | — | Filter to decisions made by this agent |
| `outcome` | `"completed" \| "failed" \| "denied" \| "dropped" \| "open"` | — | Filter by terminal outcome |
| `limit` | `integer` | `50` | Max entries (newest first by `opened_at`); 1–500 |

## Returns

```json
{
  "count": 3,
  "decisions": [
    {
      "decision_id": "act:act_a1b2c3d4e5f6",
      "frontier_item_id": "fi-recon-host-10-10-10-5",
      "action_id": "act_a1b2c3d4e5f6",
      "agent_id": "sub-recon-1",
      "opened_at": "2026-05-07T00:00:00.000Z",
      "closed_at": "2026-05-07T00:01:30.000Z",
      "outcome": "completed",
      "stages": [
        { "stage": "agent_picked", "timestamp": "...", "details_ref": "evt_..." },
        { "stage": "log_thought", "timestamp": "...", "details_ref": "evt_..." },
        { "stage": "validated", "timestamp": "...", "details_ref": "evt_..." },
        { "stage": "started", "timestamp": "...", "details_ref": "evt_..." },
        { "stage": "completed", "timestamp": "...", "details_ref": "evt_..." }
      ]
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `decision_id` | `string` | Stable id: `act:<action_id>` for actions, `fi:<frontier_item_id>` for frontier items that were emitted but never claimed |
| `frontier_item_id` | `string?` | Frontier item the decision is tied to |
| `action_id` | `string?` | Action_id (when the decision produced one) |
| `agent_id` | `string?` | Agent that authored the decision |
| `opened_at` / `closed_at` | `string` | ISO timestamps of first / last stage |
| `outcome` | `string` | Terminal outcome — `open` while still in progress |
| `stages[]` | `array` | Ordered stages |

Each stage:

| Field | Type | Description |
|-------|------|-------------|
| `stage` | `string` | One of `frontier_emitted`, `agent_picked`, `log_thought`, `validated`, `approved`, `denied`, `started`, `completed`, `failed`, `dropped` |
| `timestamp` | `string` | ISO timestamp |
| `details_ref` | `string?` | `event_id` of the underlying activity event |
| `summary` | `string?` | Short human-readable summary lifted from the event description |

## Frontier-Item-Only Entries

When a frontier item is emitted by `next_task` but no agent ever claims it, it shows up as a single-stage entry (`frontier_emitted`, possibly followed by `dropped`). This makes "the agent ignored item X" visible in the same view as "the agent pursued item Y to completion."

## Usage Notes

- Sort order: newest `opened_at` first.
- For per-action drill-down, use [`explain_action`](explain-action.md) — same data, projected for one action_id with extra fields (alternatives considered, prior actions referenced).
- For state-over-time queries (e.g., "what was true at this moment?"), use [`get_timeline`](get-timeline.md).

## See Also

- [`explain_action`](explain-action.md) — single-action introspection
- [`get_timeline`](get-timeline.md) — per-node/edge "what was true at time T"
- [Concepts → Audit Trail](../concepts.md#audit-trail)
