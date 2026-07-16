# get_recovery_status

Inspect persistence recovery, state-format migration, and
active-configuration convergence.

**Read-only:** Yes

## When to use

- At startup when Overwatch reports degraded or read-only operation
- Before choosing file or durable-state authority for a config divergence
- After a WAL/snapshot recovery, persistence write failure, or config write interruption
- When startup reports a legacy migration backup or an unsupported newer format
- To capture the exact hashes required by `resolve_config_divergence`

The tool remains available while durable mutations are disabled.

## Parameters

None.

## Returns

The response contains a `recovery` object with the combined persistence and
configuration status:

| Field | Description |
|-------|-------------|
| `outcome` | `clean`, `recovered`, `incomplete`, or `reinitialized` |
| `source` | Selected recovery base: `fresh`, `state`, `snapshot`, or `config` |
| `complete` / `writable` | Whether recovery completed and durable mutations may proceed |
| `reason` | Combined operator-facing explanation when recovery is degraded |
| `persistence_reason` | Underlying WAL/state reason when config recovery is also blocked |
| `base_checkpoint` | Contiguous checkpoint stored by the selected base |
| `highest_allocated_seq` | Highest mutation sequence allocated by this engagement |
| `highest_on_disk_seq` | Highest sequence observed in the journal |
| `highest_contiguous_applied_seq` | Highest sequence applied without a gap or failure |
| `consecutive_persistence_failures` | Current durable-write failure streak |
| `journal` | Format version, path, read/attempted/applied/skipped/failed counts, and malformed/preserved flags |
| `state_migration` | Supported/observed state and journal versions, migration status, backup path/checksum, and blocker |
| `config_recovery` | File/runtime/state revisions, hashes, intent state, and allowed resolutions |

`config_recovery.status` is one of `unmanaged`, `in_sync`, `recovered`,
`diverged`, or `write_incomplete`. A divergence exposes
`allowed_resolutions`; an interrupted known write exposes no authority choice
and must be completed by restart.

## Example

```json
{}
```

An abridged divergence response:

```json
{
  "recovery": {
    "outcome": "incomplete",
    "source": "state",
    "complete": false,
    "writable": false,
    "reason": "The active config file and durable state contain different configuration semantics.",
    "highest_allocated_seq": 14,
    "highest_on_disk_seq": 14,
    "highest_contiguous_applied_seq": 14,
    "state_migration": {
      "status": "current",
      "supported_state_version": 1,
      "supported_journal_version": 1,
      "observed_state_version": 1,
      "observed_journal_version": 1,
      "migration_required": false
    },
    "config_recovery": {
      "status": "diverged",
      "resolution_required": true,
      "intent_present": false,
      "file_revision": 7,
      "state_revision": 6,
      "file_hash": "<64-character observed file hash>",
      "state_hash": "<64-character durable-state hash>",
      "allowed_resolutions": ["use_file", "use_state"]
    }
  }
}
```

Treat the hashes as short-lived observations. Refresh status immediately before
reconciliation; changing either representation makes a previously inspected
request fail with a conflict instead of applying stale authority.

## Equivalent operator surfaces

- HTTP: `GET /api/recovery`
- CLI: `overwatch recovery`

See [Configuration recovery](../configuration.md#active-configuration-ownership-and-recovery).
