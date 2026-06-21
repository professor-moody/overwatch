# approve_action

Approve a currently pending Overwatch action by `action_id`, resolving the live approval gate that `validate_action` / `run_bash` / `run_tool` block on.

**Read-only:** No (resolves the approval and records it)

## Description

When an action requires operator approval, the executing tool call blocks on a live approval gate while a durable approval record is written. `approve_action` resolves that gate so the original tool call proceeds.

If the durable approval record exists but the **live waiter is gone** (e.g. the original tool call already timed out or its agent was reaped), the tool returns `approval_not_live` so the operator knows the original call cannot be resumed. If no record exists at all, it returns `approval_not_found`.

This is the same resolution path the dashboard Actions page and the cockpit "Needs you" queue use — answering from any surface resumes the waiting agent.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `action_id` | `string` | Yes | Pending action ID to approve |
| `notes` | `string` | No | Optional operator notes recorded with the approval |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `action_id` | `string` | The action that was approved |
| `approved` | `boolean` | `true` on success; `false` with an `error` otherwise |
| `approval` | `object?` | The resolved approval record (on success) |
| `error` | `string?` | `approval_not_live` (record exists, no live waiter) or `approval_not_found` (no record) |
| `message` | `string?` | Human-readable explanation when `approved` is `false` |

## Usage Notes

- Pairs with [`deny_action`](deny-action.md); both resolve the same live gate created by [`validate_action`](validate-action.md) / [`run_bash`](run-bash.md) / [`run_tool`](run-tool.md).
- A pending approval left unanswered past `opsec.approval_timeout_ms` (default 300s) **auto-fires** — it is approved automatically and stamped `unattended_execute: true` so the unattended execution is visible in OPSEC logs and retrospectives. See [Runtime Model → Approval round-trip](../runtime-model.md).
- An `approval_not_live` result is expected when the original tool call has already moved on; nothing is executed.
