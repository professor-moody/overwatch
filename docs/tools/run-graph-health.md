# run_graph_health

Full graph integrity report.

**Read-only:** Yes

## Description

Runs read-only graph integrity checks across the current engagement graph. Returns categorized issues such as:

- Split host identities across multiple node IDs
- Unresolved BloodHound fallback identities
- Edge type/source/target violations
- Stale inferred edges whose trigger conditions no longer hold

Use this when you want the full health report instead of the summarized warnings included in `get_state`.

## Parameters

None.

## Returns

A `HealthReport` object:

| Field | Type | Description |
|-------|------|-------------|
| `status` | `"healthy"` \| `"warning"` \| `"critical"` | Overall health |
| `counts_by_severity` | `object` | Count of warnings and critical issues |
| `issues` | `HealthIssue[]` | Detailed issue list with severity, check name, message, and affected node/edge IDs |

## Usage Notes

- `get_state` includes a summarized version (`warnings` field) — use this tool for the full detail
- Run after bulk ingestion (BloodHound, large nmap scans) to check for data quality issues
- Useful for debugging when the frontier seems incorrect or paths are missing
