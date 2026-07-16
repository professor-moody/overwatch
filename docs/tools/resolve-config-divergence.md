# resolve_config_divergence

Reconcile an active config divergence by explicitly choosing file or durable
state authority.

**Read-only:** No

## Safety model

This is a recovery-only mutation. It cannot bypass an incomplete WAL/state
recovery, and it is unavailable when a known config write intent is incomplete.
Both exact hashes from the latest `get_recovery_status` observation are
required, so an out-of-band change between inspection and resolution fails
closed.

- **`use_file`** validates the active file, preserves immutable engagement
  identity fields, assigns a new revision/hash, and applies the file's semantic
  configuration to runtime and durable state.
- **`use_state`** assigns a new revision/hash to durable-state authority and
  atomically restores the active config file from it.

Both modes audit the authority choice and return only after file, runtime, and
durable state share the resulting revision/hash.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `resolution` | `"use_file" \| "use_state"` | Yes | Representation to treat as authoritative |
| `expected_file_hash` | 64-character lowercase SHA-256 | Yes | Exact observed file hash from recovery status |
| `expected_state_hash` | 64-character lowercase SHA-256 | Yes | Exact durable-state hash from recovery status |

## Example

```json
{
  "resolution": "use_state",
  "expected_file_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "expected_state_hash": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
}
```

## Returns

```json
{
  "resolved": true,
  "mode": "use_state",
  "config": {
    "config_revision": 8,
    "config_hash": "<resulting canonical config hash>"
  },
  "recovery": {
    "status": "recovered",
    "resolution_required": false,
    "last_resolution": "use_state"
  }
}
```

Common failures:

- Hash conflict: refresh `get_recovery_status` and review the new observations.
- Invalid/missing file: only `use_state` is allowed.
- Known interrupted write: restart so Overwatch can resume the checksummed
  write intent; do not choose a new authority.
- Underlying persistence recovery incomplete: repair/recover the WAL/state base
  first. Config reconciliation never discards that recovery tail.

## Equivalent operator surfaces

- HTTP: `POST /api/recovery/config/resolve`
- CLI: `overwatch config reconcile <use_file|use_state> --file-hash SHA256 --state-hash SHA256`

See [`get_recovery_status`](get-recovery-status.md) and
[Configuration recovery](../configuration.md#active-configuration-ownership-and-recovery).
