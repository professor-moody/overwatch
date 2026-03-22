# export_graph

Export the complete engagement graph.

**Read-only:** Yes

## Description

Export the complete engagement graph with all nodes, edges, and properties. Used for retrospectives and reporting.

## Parameters

None.

## Returns

An `ExportedGraph` object:

| Field | Type | Description |
|-------|------|-------------|
| `nodes` | `ExportedGraphNode[]` | All nodes with full properties |
| `edges` | `ExportedGraphEdge[]` | All edges with source, target, and full properties |

## Usage Notes

- Returns the entire graph — can be large for complex engagements
- Used by `run_retrospective` as input for analysis
- Useful for external tooling, custom reporting, or graph visualization
