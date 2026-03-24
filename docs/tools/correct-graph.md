# correct_graph

Repair existing graph state explicitly and transactionally.

**Read-only:** No

## Description

Use this tool for cleanup and remediation when the graph already contains bad data. This is **not** a normal reporting path — use [`report_finding`](report-finding.md) and [`parse_output`](parse-output.md) for new discoveries.

Supported operations:

- **`drop_edge`** — Remove a stale or invalid edge
- **`replace_edge`** — Replace an edge with the correct type, source, target, or properties
- **`patch_node`** — Update or remove node properties (including normalized credential fields)

All operations in a single call are applied **transactionally** — if any operation fails, none are applied.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reason` | `string` | Yes | Operator-provided reason for the correction batch |
| `action_id` | `string` | No | Action ID to link this correction to a triggering workflow |
| `operations` | `array` | Yes | Array of correction operations (min 1) |

### Operation: `drop_edge`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kind` | `"drop_edge"` | Yes | Operation type |
| `source_id` | `string` | Yes | Source node ID |
| `edge_type` | `EdgeType` | Yes | Edge type to drop |
| `target_id` | `string` | Yes | Target node ID |

### Operation: `replace_edge`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kind` | `"replace_edge"` | Yes | Operation type |
| `source_id` | `string` | Yes | Current source node ID |
| `edge_type` | `EdgeType` | Yes | Current edge type |
| `target_id` | `string` | Yes | Current target node ID |
| `new_source_id` | `string` | No | New source node ID |
| `new_edge_type` | `EdgeType` | No | New edge type |
| `new_target_id` | `string` | No | New target node ID |
| `confidence` | `number` | No | New confidence (0.0–1.0) |
| `properties` | `object` | No | Additional edge properties to set |

### Operation: `patch_node`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kind` | `"patch_node"` | Yes | Operation type |
| `node_id` | `string` | Yes | Node to patch |
| `set_properties` | `object` | No | Properties to set or update |
| `unset_properties` | `string[]` | No | Property keys to remove |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `action_id` | `string` | Action ID (if provided) |
| `reason` | `string` | Correction reason |
| `applied` | `number` | Number of operations applied |
| `skipped` | `number` | Number of operations skipped (e.g., edge not found) |
| `details` | `array` | Per-operation results |

## Usage Examples

### Drop a stale POTENTIAL_AUTH edge

```json
{
  "reason": "Credential was rotated, auth edge is no longer valid",
  "operations": [
    {
      "kind": "drop_edge",
      "source_id": "cred-ntlm-jsmith",
      "edge_type": "POTENTIAL_AUTH",
      "target_id": "svc-10-10-10-5-445"
    }
  ]
}
```

### Fix a mistyped edge

```json
{
  "reason": "Edge should be ADMIN_TO not HAS_SESSION",
  "operations": [
    {
      "kind": "replace_edge",
      "source_id": "user-corp-local-admin",
      "edge_type": "HAS_SESSION",
      "target_id": "host-10-10-10-5",
      "new_edge_type": "ADMIN_TO",
      "confidence": 1.0
    }
  ]
}
```

### Patch credential properties

```json
{
  "reason": "Credential confirmed expired after re-test",
  "operations": [
    {
      "kind": "patch_node",
      "node_id": "cred-ntlm-jsmith",
      "set_properties": { "credential_status": "expired" },
      "unset_properties": ["cred_usable_for_auth"]
    }
  ]
}
```
