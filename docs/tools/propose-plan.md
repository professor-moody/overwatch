# propose_plan

Submit a plan of operator operations for the human operator to confirm.

**Read-only:** No (records a proposed plan; it does **not** mutate engagement state — the operator must confirm it)

## Description

`propose_plan` is the single write available to the read-only **`planner`** role. When a free-form operator command can't be resolved by the deterministic grammar (see [Operator Cockpit](../operator-cockpit.md)), the dashboard dispatches a headless planner sub-agent. The planner reads engagement state and calls `propose_plan` with a list of [`OperatorOp`](../operator-cockpit.md#operatorop)s. The plan lands in the engine-owned `ProposedPlanStore`; the operator confirms it in the command bar, and it executes through the **same validated `executeOps` path** the grammar uses.

The planner **proposes**, the operator **confirms**, the dashboard **executes** — the planner never touches targets or mutates the graph.

Every op is validated against live state before the plan is stored. If **any** op can't be resolved (a directive targeting a non-running task, an approve/deny of a non-pending action, an empty scope op), the **whole plan is rejected** so a confirmed plan can never silently no-op.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `summary` | `string` | yes | One-line human-readable summary of the plan |
| `ops` | `OperatorOp[]` | yes | The ops to propose (at least one). Variants: `directive`, `scope`, `approve`, `deny` |
| `agent_id` | `string` | no | Your agent id (attribution) |
| `task_id` | `string` | no | Your planner task id (correlation — the dashboard polls for the plan by `source_task_id`) |
| `command` | `string` | no | The operator command this plan answers (logged with the plan) |
| `rationale` | `string` | no | Why these ops accomplish the command |

## Returns

On success:

```json
{ "ok": true, "plan_id": "uuid", "ops_count": 1, "summary": "pause the apache agent" }
```

When the plan contains a **scope** op, the result also carries a `scope_preview` (see [Scope-Impact Preview](#scope-impact-preview)):

```json
{ "ok": true, "plan_id": "uuid", "ops_count": 1, "summary": "add 10.0.0.0/24 to scope",
  "scope_preview": {
    "newly_in_scope_count": 3,
    "newly_excluded_count": 0,
    "newly_in_scope": [{ "id": "host:10.0.0.7", "label": "10.0.0.7" }],
    "newly_excluded": []
  } }
```

On rejection (returns `isError: true`):

```json
{ "ok": false, "error": "1 op(s) could not be resolved against live state",
  "rejected": [{ "op": { "op": "directive", "task_id": "ghost", "kind": "pause" }, "reason": "no agent task with id \"ghost\"" }] }
```

## Scope-Impact Preview

A scope op doesn't ingest anything, but it **reshapes what's in play**: existing graph nodes transition in or out of scope, which is what drives the frontier. When a proposed plan contains a scope op, `propose_plan` runs a pure dry-run — no mutation — of that transition and includes a `scope_preview` in the result **and** on the stored `ProposedPlan.scope_preview`. *See the impact before you confirm.*

The preview merges the net scope change across **all** scope ops in the plan, then evaluates every existing node — including cold-store hosts — against the current scope versus the plan's post-confirm scope:

| Field | Type | Description |
|-------|------|-------------|
| `newly_in_scope` | `{ id, label }[]` | Sample of nodes that would come **into** scope (capped) |
| `newly_excluded` | `{ id, label }[]` | Sample of nodes that would drop **out of** scope (capped) |
| `newly_in_scope_count` | `number` | **Exact** count of nodes coming into scope |
| `newly_excluded_count` | `number` | **Exact** count of nodes dropping out of scope |

The sample lists are capped for payload size; the counts are always exact. Nodes without an `ip` or `hostname` have no scope identity and are ignored. Plans without a scope op carry no `scope_preview`.

## Side Effects

- Stores the plan in the durable `ProposedPlanStore`, keyed by a minted `plan_id`, with its original absolute 10-minute decision window.
- Persists canonical owner task/label, confirmation or denial, acknowledgement, and the eventual execution outcome. Restart never extends the decision window.
- Emits a `plan_proposed` activity event, surfaced in the operator console as a planner card.

## Usage Notes

- Reference **only** the exact `task_id` / `action_id` values given in your objective; stale ids are rejected.
- If the command can't be expressed as the allowed ops, do **not** propose — finish with `submit_agent_transcript` explaining why.
- Confirmation/execution happens via `POST /api/commands { confirm: true, plan_id }` — see [Operator Cockpit](../operator-cockpit.md).

## See Also

- [Operator Cockpit](../operator-cockpit.md) — the NL command → planner → confirm → execute flow.
- [`manage_agent_directive`](manage-agent-directive.md) — the directive ops a plan can carry.
