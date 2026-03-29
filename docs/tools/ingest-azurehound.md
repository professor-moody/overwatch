# ingest_azurehound

Parse and ingest AzureHound or ROADtools JSON output into the engagement graph.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | `string` | *(required)* | Path to AzureHound JSON file or directory containing JSON files |
| `max_files` | `number` | `20` | Maximum number of JSON files to process from a directory (1–50) |

## Input

Accepts either:

- **A directory** containing AzureHound JSON files (`users.json`, `groups.json`, etc.) — files are sorted alphabetically and capped at `max_files`
- **A single JSON file**

## Object Mapping

| AzureHound Object | Graph Node Type | Key Properties |
|--------------------|-----------------|----------------|
| Users | `cloud_identity` | `provider: azure`, `principal_type: user` |
| Groups | `group` | `provider: azure` |
| Apps | `cloud_identity` | `principal_type: app` |
| Service Principals | `cloud_identity` | `principal_type: service_account` |
| Role Assignments | `cloud_policy` | + `HAS_POLICY` edges to assignees |
| App Role Assignments | — | `ASSUMES_ROLE` edges |

## Output

Returns a JSON summary:

```json
{
  "files_processed": 3,
  "total_nodes": 142,
  "total_edges": 87,
  "files": ["groups.json", "users.json", "role-assignments.json"],
  "errors": ["optional array of per-file errors"]
}
```

## Behavior

- Files are validated through `prepareFindingForIngest` before ingestion — schema-invalid nodes/edges are rejected with per-file error messages
- After ingestion, inference rules fire on all new nodes (e.g., overprivileged policy detection, cross-account role assumptions)
- Idempotent on node IDs — re-ingesting the same data merges properties rather than creating duplicates

## Example

```
ingest_azurehound({ path: "/tmp/azurehound-output/" })
ingest_azurehound({ path: "/tmp/azurehound-output/users.json" })
```

## See Also

- [`ingest_bloodhound`](ingest-bloodhound.md) — for SharpHound/bloodhound-python AD collections
- [Graph Model — Cloud Infrastructure](../graph-model.md#cloud-infrastructure) — cloud edge types
- [Graph Model — Cloud Identity Properties](../graph-model.md#cloud-identity-properties) — cloud node properties
