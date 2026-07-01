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

## Source-trust labels

Every graph element can carry a derived `source_trust` label for report honesty — distinguishing tool-observed from target-asserted from rule-inferred:

| Label | Meaning |
|-------|---------|
| `observed` | Tool-confirmed (e.g. `confidence ≥ 1.0`, `confirmed_at`, tested-success) |
| `asserted` | Recorded but unverified (conservative default) |
| `inferred` | A rule's hypothesis (`inferred_by_rule`) |

The label is **derived on read**, never stored — there is no migration and the canonical export is unchanged. It is opt-in: the `export_graph` tool omits it, while the `/api/graph/export` endpoint includes it (the engine call is `exportGraph({ sourceTrust: true })`).

## Usage Notes

- Returns the entire graph — can be large for complex engagements
- Used by `run_retrospective` as input for analysis
- Useful for external tooling, custom reporting, or graph visualization
- For a portable archive that includes evidence, reports, a bundle manifest, and the mutation journal, use [`bundle_engagement`](bundle-engagement.md)
