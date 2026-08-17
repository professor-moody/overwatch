# promote_claim

Durably record an explicit operator/agent judgment about a node or edge's standing (claim lifecycle Phase 2b).

**Read-only:** No

## Description

`claim_state` — how well-established a claim is (`candidate` → `observed` → `validated` → `exploited`, plus terminal `refuted` / `stale`) — is normally *derived* from the signals a node or edge already carries. `promote_claim` records a **durable** judgment that overrides that derivation: it lets an operator (or an agent) assert a standing that the graph's signals do not, and have it persist across the engagement rather than being recomputed each time.

Use it to:

- **correct** a mis-derived claim (e.g. an inferred `ADMIN_TO` that a rule guessed but you have disproven);
- **record a verification outcome** (you tested a credential and it worked, or it didn't).

The promotion is stored on the target element and a hash-chained `claim_promoted` event records who/why for the timeline.

### Precedence

- **`refuted` / `stale`** are **authoritative** — they override any derived positive standing.
- **`observed` / `validated` / `exploited`** set a **floor** — a stronger *real* signal (an actual exploitation) can still raise the standing above a positive promotion.

Objective and path evaluation honor the promotion: path-finding stops routing through a refuted access edge immediately, and a `validated` promotion can complete a not-yet-achieved objective. **Refuting** the claim that completed an objective **un-achieves** it — a refutation says the access was never truly established, so the milestone is revoked. **Staling** is different: it is decay, not disproof, so the settled milestone (`achieved` / `achieved_at`) is **preserved** and only the live `currently_satisfied` state drops — the engagement still records that the objective *was* reached, and flags that its supporting access needs re-validation.

A promotion can carry `valid_until`; once elapsed the positive standing decays and the claim reads `stale` until re-validated (a `refuted` verdict is terminal and does not expire).

Target exactly one of `node_id` or `edge_id`. This is **not** a discovery path — use [`report_finding`](report-finding.md) and [`parse_output`](parse-output.md) for new observations, and [`correct_graph`](correct-graph.md) to change the graph's structure.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `state` | `"observed" \| "validated" \| "exploited" \| "refuted" \| "stale"` | Yes | The promoted standing |
| `reason` | `string` | Yes | Why — the judgment behind this promotion; required for auditability |
| `node_id` | `string` | No | Target node id (exactly one of `node_id` / `edge_id`) |
| `edge_id` | `string` | No | Target edge id (exactly one of `node_id` / `edge_id`) |
| `agent_id` | `string` | No | If an agent is promoting, its id (attributes the promotion to that agent); omit for an operator |
| `valid_until` | `string` | No | Optional ISO timestamp after which the claim decays to `stale` |
| `action_id` | `string` | No | Action ID to link this promotion to a triggering workflow |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `target_kind` | `"node" \| "edge"` | Which element was promoted |
| `target_id` | `string` | The promoted element's id |
| `claim_state` | `ClaimState` | The resulting `claim_state` after applying the promotion |

## Usage Examples

### Refute an inferred access edge

```json
{
  "edge_id": "user-jsmith->host-10-10-10-5:ADMIN_TO",
  "state": "refuted",
  "reason": "Rule-inferred local-admin; tested with the captured hash and access was denied"
}
```

### Record a validated credential

```json
{
  "edge_id": "cred-ntlm-jsmith->svc-10-10-10-5-445:VALID_ON",
  "state": "validated",
  "reason": "Authenticated successfully over SMB with this credential",
  "agent_id": "agent-cred-tester-1"
}
```

### Mark a node stale with an expiry

```json
{
  "node_id": "cred-ntlm-jsmith",
  "state": "stale",
  "reason": "Credential rotated during the engagement",
  "valid_until": "2026-09-01T00:00:00Z"
}
```
