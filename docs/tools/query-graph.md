# query_graph

Direct access to the engagement graph for open-ended analysis.

**Read-only:** Yes

## Description

Use this to explore relationships the frontier might not surface:

- "Show me all credentials and what services they're valid on"
- "What's connected to host X within 3 hops?"
- "Find all ADCS-related edges"
- "Show me every node with unconstrained delegation"

This gives the FULL graph — no filtering, no scoring. Use it when the frontier items don't capture a pattern you're seeing, or when you want to reason about graph structure directly.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node_type` | `NodeType` | — | Filter nodes by type |
| `node_filter` | `object` | — | Filter nodes by property values (e.g., `{"service_name": "smb"}`) |
| `edge_type` | `EdgeType` | — | Filter edges by type |
| `edge_filter` | `object` | — | Filter edges by property values |
| `from_node` | `string` | — | Start traversal from this node ID |
| `direction` | `string` | `"both"` | Traversal direction: `outbound`, `inbound`, or `both` |
| `max_depth` | `integer` | `2` | Max traversal depth (1–10) |
| `limit` | `integer` | `100` | Max results to return (1–500) |

## Returns

A `GraphQueryResult` object:

| Field | Type | Description |
|-------|------|-------------|
| `nodes_found` | `number` | Total matching nodes |
| `edges_found` | `number` | Total matching edges |
| `nodes` | `array` | Nodes with full properties |
| `edges` | `array` | Edges with source, target, and full properties |

## Examples

Find all SMB services with signing disabled:
```json
{ "node_type": "service", "node_filter": { "service_name": "smb", "smb_signing": false } }
```

Traverse 3 hops from a specific host:
```json
{ "from_node": "host-10-10-10-5", "max_depth": 3, "direction": "outbound" }
```

Find all credential-related edges:
```json
{ "edge_type": "VALID_ON" }
```

## Usage Notes

- Combine `node_type` + `node_filter` for precise queries
- Use `from_node` + `max_depth` for neighborhood exploration
- Results include full properties by default
- The `limit` caps the result set — increase it for large queries
