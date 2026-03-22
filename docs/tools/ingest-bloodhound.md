# ingest_bloodhound

Parse and ingest SharpHound or bloodhound-python JSON output into the engagement graph.

**Read-only:** No

## Description

Accepts either a directory path containing BloodHound JSON files or a single JSON file path. Maps BloodHound objects to Overwatch graph nodes and edges:

| BloodHound | Overwatch |
|------------|-----------|
| Computer | `host` node |
| User | `user` node |
| Group | `group` node |
| Domain | `domain` node |
| OU | `ou` node |
| GPO | `gpo` node |
| ACEs, Members, Sessions, LocalAdmins | Corresponding edge types |

After ingestion, inference rules fire on all new nodes. This is the fastest way to populate the graph with Active Directory structure.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | `string` | — | Path to BloodHound JSON file or directory (required) |
| `max_files` | `integer` | `20` | Maximum JSON files to process from a directory (1–50) |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `files_processed` | `number` | Number of files successfully processed |
| `total_new_nodes` | `number` | Total new nodes created |
| `total_new_edges` | `number` | Total new edges created |
| `total_inferred_edges` | `number` | Edges created by inference rules |
| `per_file` | `array` | Per-file breakdown of nodes, edges, and inferred |
| `errors` | `string[]` | Any errors encountered |
| `message` | `string` | Summary |

## Usage Notes

- Point to the directory containing SharpHound output (e.g., `computers.json`, `users.json`, `groups.json`)
- SIDs are resolved across files — process the full collection together
- Run `run_graph_health` after ingestion to check for data quality issues
- Large collections may produce many inferred edges — review the frontier after ingestion
