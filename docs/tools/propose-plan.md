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

On rejection (returns `isError: true`):

```json
{ "ok": false, "error": "1 op(s) could not be resolved against live state",
  "rejected": [{ "op": { "op": "directive", "task_id": "ghost", "kind": "pause" }, "reason": "no agent task with id \"ghost\"" }] }
```

## Side Effects

- Stores the plan in `ProposedPlanStore` (in-memory, 10-min TTL) keyed by a minted `plan_id`.
- Emits a `plan_proposed` activity event, surfaced in the operator console as a planner card.

## Usage Notes

- Reference **only** the exact `task_id` / `action_id` values given in your objective; stale ids are rejected.
- If the command can't be expressed as the allowed ops, do **not** propose — finish with `submit_agent_transcript` explaining why.
- Confirmation/execution happens via `POST /api/commands { confirm: true, plan_id }` — see [Operator Cockpit](../operator-cockpit.md).

## See Also

- [Operator Cockpit](../operator-cockpit.md) — the NL command → planner → confirm → execute flow.
- [`manage_agent_directive`](manage-agent-directive.md) — the directive ops a plan can carry.
