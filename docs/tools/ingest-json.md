# ingest_json

Import JSON or JSONL into graph nodes.

**Read-only:** No

## Description

Generic ingestion path for structured data that does not have a dedicated parser. The caller supplies mappings that identify arrays, node IDs, labels, properties, and optional parent relationships.

Inputs may be raw JSON, raw JSONL, or a file path. If an `array_path` matches no records, the response includes a warning instead of silently claiming useful ingestion.

## Mapping Fields

| Field | Description |
|-------|-------------|
| `node_type` | Graph node type to create. |
| `array_path` | Optional path to the array of records inside the JSON document. |
| `id_field` | Field used to build node IDs. |
| `id_prefix` | Prefix applied to generated node IDs. |
| `label_field` | Field used as node label. |
| `property_fields` | Fields copied onto the node properties. |
| `parent_field` | Optional field containing a full parent node ID. |
| `parent_edge_type` | Edge type created from parent to child when `parent_field` is present. |

## Usage Notes

`parent_field` should contain the full parent node ID. If source data only has a local key, normalize it before ingestion or choose an `id_prefix` scheme that produces compatible IDs.
