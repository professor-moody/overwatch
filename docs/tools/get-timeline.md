# get_timeline

Per-node and per-edge "what was true at time T" view.

**Read-only:** Yes

## Description

Returns a `TimelineEntry` for each node and edge in the engagement graph, capturing:

- `became_true_at` — when the entity was first observed (`first_seen_at`, falling back to `confirmed_at` / `discovered_at`)
- `became_false_at` — when the entity stopped being true (if known)
- `last_observed_at` — most recent observation
- `evidence_refs[]` — activity-log `event_id`s that touched this entity
- `superseding_id` / `invalidation_reason` — provenance of any invalidation

Used to answer "what did the operator know at time T?" — pass `at` to filter to entities known-true at that moment.

## Invalidation Signals

The timeline derives invalidation from existing graph properties (no new persistence). An entity is marked `became_false_at` when:

- **Credential nodes**: `credential_status ∈ {expired, rotated, stale}`, OR `valid_until` is in the past → reason: `valid_until_elapsed` / `rotated` / `expired` / `stale`
- **`HAS_SESSION` edges**: `session_live === false` (e.g., imported BloodHound sessions) → reason: `session_not_live`
- **Any node**: `identity_status === 'superseded'` or explicit `superseded_by` → reason: `superseded`, `superseding_id` set

Future passes will add explicit `invalidation` activity events for richer scrubbing; today's view is graph-property-driven.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `entity_id` | `string` | — | Filter to a specific node or edge id |
| `kind` | `"node" \| "edge"` | — | Filter to nodes-only or edges-only |
| `at` | `string` (ISO) | — | Return only entries known-true at this timestamp |
| `since` | `string` (ISO) | — | Return only entries that became true at-or-after this timestamp |
| `limit` | `integer` | `200` | Max entries (newest `became_true_at` first); 1–2000 |

## Returns

```json
{
  "count": 2,
  "entries": [
    {
      "entity_id": "host-10-10-10-5",
      "kind": "node",
      "became_true_at": "2026-05-07T00:00:00.000Z",
      "last_observed_at": "2026-05-07T00:05:00.000Z",
      "evidence_refs": ["evt_abc", "evt_def"]
    },
    {
      "entity_id": "cred-admin-acme",
      "kind": "node",
      "became_true_at": "2026-05-07T00:00:30.000Z",
      "became_false_at": "2026-05-07T01:00:00.000Z",
      "last_observed_at": "2026-05-07T00:05:00.000Z",
      "evidence_refs": ["evt_xyz"],
      "invalidation_reason": "rotated"
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `entity_id` | `string` | Node id or edge id |
| `kind` | `"node" \| "edge"` | Discriminator |
| `became_true_at` | `string` | ISO timestamp |
| `became_false_at` | `string?` | ISO timestamp; absent if still true |
| `last_observed_at` | `string?` | ISO timestamp |
| `evidence_refs` | `string[]` | Activity log `event_id`s referencing this entity |
| `superseding_id` | `string?` | Replacement entity (when superseded) |
| `invalidation_reason` | `string?` | `valid_until_elapsed` / `rotated` / `expired` / `stale` / `session_not_live` / `superseded` |

## Filter Semantics

- `at: T` — keeps entries where `became_true_at <= T && (became_false_at === undefined || became_false_at > T)`. Time-travel scrubber view.
- `since: T` — keeps entries where `became_true_at >= T`. "What's new since" view.
- Without filters: every entity in the current graph, ordered by `became_true_at` descending.

## Usage Notes

- The dashboard timeline panel will consume this in a follow-up. The MCP tool is the structured introspection surface today.
- Sort is `became_true_at DESC` so newest entries come first; combine with `limit` for paging.
- `evidence_refs` come from activity events with `target_node_ids` or `target_edge` referencing this entity. Edges are keyed by `(source|target|type)` when an explicit edge_id isn't present.

## See Also

- [`explain_action`](explain-action.md) — drill into a specific action_id
- [`get_decision_log`](get-decision-log.md) — per-decision timeline
- [Concepts → Audit Trail](../concepts.md#audit-trail)
