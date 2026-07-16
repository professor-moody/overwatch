# bundle_engagement

Create a portable engagement archive.

**Read-only:** No. The tool writes an archive and records an audit event.

## Description

Builds a `.tar.gz` bundle for the current engagement. The archive includes the current state file, evidence blobs, generated reports, `bundle-manifest.json`, and the mutation journal when one is present. The manifest records `state_version` and `journal_version` so a recipient can choose a compatible binary before opening it. Registered JSON-RPC tapes are referenced in the manifest but are not copied into the bundle.

The dashboard `/api/bundle` endpoint uses the same bundle preparation path, so CLI and dashboard downloads have matching contents.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `output_path` | string? | generated path | Optional destination path for the archive. |
| `include_snapshots` | boolean? | false | Include persisted state snapshots when available. |

## Usage Notes

- Use this when moving an engagement to another machine or preserving an audit-ready archive.
- Use [`export_graph`](export-graph.md) when you only need the graph JSON, not evidence or reports.
- The manifest records included files and tape pointers so recipients can see what is and is not packaged.
