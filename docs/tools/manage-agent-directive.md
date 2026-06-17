# manage_agent_directive

Steer a running sub-agent by issuing a directive.

**Read-only:** No (records a directive on the task; delivered to the agent on its next heartbeat)

## Description

Issues an operator steering directive to a running sub-agent. The engine only **records** the directive; it is delivered on the agent's next [`agent_heartbeat`](agent-heartbeat.md) as `pending_directive`, and the agent calls [`acknowledge_agent_directive`](acknowledge-agent-directive.md) and honors it. A new directive **supersedes** any still-pending one for the task (latest instruction wins).

`stop` is the one kind executed by the runtime (`TaskExecutionService` kills the headless process and marks the task interrupted); the rest are agent-observed.

The dashboard exposes this same substrate two ways: per-agent **Pause / Resume / Stop** buttons + a free-text box (`POST /api/agents/:id/directive`), and fleet-wide **Pause/Resume/Stop all** (`POST /api/fleet/directive`). Both route through the validated `executeOps` path — see [Operator Cockpit](../operator-cockpit.md).

## Kinds

| Kind | Effect |
|------|--------|
| `pause` / `resume` | Halt / continue the agent (it keeps heartbeating while paused) |
| `stop` | Wrap up and exit; the runtime kills the process and marks the task interrupted |
| `narrow_scope` | Restrict the agent to `node_ids` |
| `skip_types` | Ignore frontier items of `frontier_types` |
| `prioritize` | Do `frontier_types` first |
| `instruct` | Free-text steer — the operator's instruction is in `note`; the agent reads and honors it |

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `task_id` | `string` | yes | Agent task id to steer |
| `kind` | `enum` | yes | One of the kinds above |
| `node_ids` | `string[]` | no | `narrow_scope`: node ids to restrict to |
| `frontier_types` | `string[]` | no | `skip_types` / `prioritize`: frontier item types |
| `note` | `string` | no | `instruct`: the free-text instruction; otherwise an optional note |
| `issued_by` | `string` | no | Operator id (defaults to `primary`) |

## See Also

- [`acknowledge_agent_directive`](acknowledge-agent-directive.md) — the sub-agent's confirmation.
- [Operator Cockpit](../operator-cockpit.md#steering) — per-agent + fleet steering UI.
