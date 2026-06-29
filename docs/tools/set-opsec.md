# set_opsec

Update the **active** engagement's OPSEC policy — no hand-edited config.

## When to use

- Tighten or loosen the noise ceiling, switch the approval mode, set a time
  window, or adjust the technique blacklist mid-engagement.

## Confirmation gate

`set_opsec` mutates the **live** engine and can *loosen* policy, so it mirrors
[`update_scope`](update-scope.md)'s two-phase workflow:

1. **Preview** (`confirm: false`, default) — returns a `before`/`after` diff plus
   `weakening_warnings` for any loosening change (higher `max_noise`, enforcement
   disabled, switching to `auto-approve`). No state is mutated.
2. **Apply** (`confirm: true`) — applies the change in place, persists, and logs a
   `system` activity event with the `reason` and full diff for attribution.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `max_noise` | `number` (0.0–1.0) | No | Noise ceiling |
| `enabled` | `boolean` | No | Enable/disable OPSEC enforcement |
| `approval_mode` | `auto-approve \| approve-critical \| approve-all` | No | Operator-approval policy |
| `approval_timeout_ms` | `number` (≥1000) | No | Approval wait before auto-resolve |
| `time_window` | `{ start_hour, end_hour } \| null` | No | Allowed hours window; `null` clears it |
| `blacklisted_techniques` | `string[]` | No | Techniques that are always vetoed |
| `reason` | `string` | **Yes** | Why (recorded in the activity log) |
| `confirm` | `boolean` | No | `true` to apply; `false` (default) for dry-run diff |

## Examples

### Preview going louder (returns a weakening warning)

```json
{ "max_noise": 0.9, "reason": "Time-boxed — accept more noise", "confirm": false }
```

### Apply an approval-mode change

```json
{ "approval_mode": "auto-approve", "reason": "Isolated lab, no operator gate", "confirm": true }
```

## Behavior notes

- Only the fields you pass change; the rest of the OPSEC policy is preserved
  (in-place merge, the same path as the dashboard settings endpoint).
- `weakening_warnings` flag changes that *reduce* safety so the operator sees the
  impact before confirming.
- For scope changes use [`update_scope`](update-scope.md); for objectives use
  [`add_objective`](add-objective.md).
