# bundle_engagement

Create a portable engagement archive.

**Read-only:** No. The tool writes an archive and records an audit event.

## Description

Builds a `.tar.gz` bundle from one artifact-first/state capture barrier. The archive includes the current state file, active config, evidence blobs, generated reports, registered JSON-RPC tapes, `bundle-manifest.json`, and the mutation journal when one is present. Exact active intents, conflict archives, migration backups, rollback intents, and nonstandard recovery journals are copied under `recovery-artifacts/`. Manifest v2 records the state/journal versions, contiguous checkpoint, independent config identities, recovery-authority inventory, and SHA-256 plus byte size for each captured file.

The dashboard `/api/bundle` endpoint uses the same capture path. It completes and validates the archive before returning HTTP 200, then supplies `Content-Length` and `Content-Digest`; the browser rejects truncated or digest-mismatched downloads. Diagnostic bundles remain available while recovery is read-only, are explicitly marked incomplete, and stage/default to the OS temp directory rather than writing under the engagement root.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `output_path` | string? | generated path | Optional destination path for the archive. |
| `include_snapshots` | boolean? | false | Include persisted state snapshots when available. |
| `include_tapes` | boolean? | true | Include registered JSON-RPC tapes. Active/changing tapes are captured as a complete newline-terminated prefix and marked `live_prefix`. |

## Output

Returns `path`, `size_bytes`, `sha256`, `bundle_id`, and `durability_confirmed`. The archive is fully built, tar-validated, hashed, fsynced, and then atomically published. `durability_confirmed: false` means the destination name became visible but its containing-directory fsync failed; the caller must surface that uncertainty. Dashboard downloads expose the same condition through `X-Overwatch-Durability` and verify bytes with `Content-Digest`.

## Usage Notes

- Use this when moving an engagement to another machine or preserving an audit-ready archive.
- Use [`export_graph`](export-graph.md) when you only need the graph JSON, not evidence or reports.
- The manifest records every included file, original tape path, and recovery authority so recipients can audit exactly what was packaged.
- Archive bytes are written to a sibling staging file, validated, fsynced, and atomically published. A failed replacement leaves the prior destination intact.
- Output paths that collide with the live state, WAL, config, evidence, report, snapshot, or cookie-jar stores are rejected.
