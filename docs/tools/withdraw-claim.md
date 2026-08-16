# withdraw_claim

Durably clear a node or edge's `promote_claim` judgment, reverting the claim to its derived standing (claim lifecycle Phase 2b).

**Read-only:** No

## Description

[`promote_claim`](promote-claim.md) records a **durable** operator/agent judgment that overrides the derived `claim_state`. `withdraw_claim` **removes** that judgment: it clears the effective promotion so the evidence-derived standing governs the claim again.

Use it to undo a mistaken or superseded promotion. For example, you refuted an `ADMIN_TO` edge, then later confirmed the access really does work — rather than stacking a second explicit verdict (`validated`) on top, you withdraw the refutation so the graph's own signals decide.

What a withdrawal does:

- **Clears the effective promotion.** The claim reverts to the state derived from its signals (confidence, tests, inference, credential status). The clear is durable — it survives a restart and WAL replay.
- **Retains the promotion history.** Every promotion ever applied stays recorded in the element's append-only `claim_promotion_history`; withdrawal does not erase it. A hash-chained `claim_withdrawn` event records who/why for the timeline.
- **Re-reconciles objectives in both directions.** Withdrawing a `refuted` / `stale` verdict can **re-complete** an objective that verdict had blocked; withdrawing a positive (`observed` / `validated` / `exploited`) verdict can **un-complete** an objective it had completed if the derived state is no longer mature.

Target exactly one of `node_id` or `edge_id`. This is **not** a discovery or structural-repair path — use [`promote_claim`](promote-claim.md) to record a judgment and [`correct_graph`](correct-graph.md) to change the graph's structure.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reason` | `string` | Yes | Why — the judgment behind withdrawing this promotion; required for auditability |
| `node_id` | `string` | No | Target node id (exactly one of `node_id` / `edge_id`) |
| `edge_id` | `string` | No | Target edge id (exactly one of `node_id` / `edge_id`) |
| `agent_id` | `string` | No | If an agent is withdrawing, its id (attributes the withdrawal to that agent); omit for an operator |
| `action_id` | `string` | No | Action ID to link this withdrawal to a triggering workflow |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `target_kind` | `"node" \| "edge"` | Which element was affected |
| `target_id` | `string` | The affected element's id |
| `claim_state` | `ClaimState` | The resulting derived `claim_state` after clearing the promotion |
| `withdrew` | `ClaimState \| null` | The standing that was withdrawn (`null` if the element had no effective promotion) |

## Usage Examples

### Undo a refutation you now believe was wrong

```json
{
  "edge_id": "user-jsmith->host-10-10-10-5:ADMIN_TO",
  "reason": "Earlier refutation was premature — re-tested with the captured hash and access succeeded; let the derived state govern"
}
```

### Retract a validation on a node

```json
{
  "node_id": "cred-ntlm-jsmith",
  "reason": "Validation was recorded against the wrong host; clearing it pending a clean re-test",
  "agent_id": "agent-cred-tester-1"
}
```
