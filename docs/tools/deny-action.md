# deny_action

Deny a currently pending Overwatch action by `action_id`, resolving the live approval gate that `validate_action` / `run_bash` / `run_tool` block on.

**Read-only:** No (resolves the approval and records it)

## Description

When an action requires operator approval, the executing tool call blocks on a live approval gate while a durable approval record is written. `deny_action` resolves that gate as a denial so the original tool call aborts instead of proceeding.

If the durable approval record exists but the **live waiter is gone**, the tool returns `approval_not_live`; if no record exists at all, it returns `approval_not_found`.

This is the same resolution path the dashboard Actions page and the cockpit "Needs you" queue use.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `action_id` | `string` | Yes | Pending action ID to deny |
| `reason` | `string` | No | Optional operator reason recorded with the denial |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `action_id` | `string` | The action that was denied |
| `denied` | `boolean` | `true` on success; `false` with an `error` otherwise |
| `approval` | `object?` | The resolved (denied) approval record (on success) |
| `error` | `string?` | `approval_not_live` (record exists, no live waiter) or `approval_not_found` (no record) |
| `message` | `string?` | Human-readable explanation when `denied` is `false` |

## Usage Notes

- Pairs with [`approve_action`](approve-action.md); both resolve the same live gate created by [`validate_action`](validate-action.md) / [`run_bash`](run-bash.md) / [`run_tool`](run-tool.md).
- Denying is the safe default for a risky pending action — the blocked tool call returns a denial and does not execute.
- Note the asymmetry with the timeout path: a pending approval left unanswered past `opsec.approval_timeout_ms` (default 300s) **auto-approves** (stamped `unattended_execute`), it does not auto-deny. Deny explicitly when you want an action stopped. See [Runtime Model → Approval round-trip](../runtime-model.md).
