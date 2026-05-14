# Data Storage Reference

This page describes exactly what Overwatch writes to disk, where each file lives, and how to back up or move an engagement.

---

## Config file

Overwatch reads its active engagement config from the path set by the `OVERWATCH_CONFIG` environment variable. If that variable is unset, it falls back to `./engagement.json` relative to the working directory you start the server from.

```
OVERWATCH_CONFIG=/path/to/engagement.json  # override
./engagement.json                          # default (cwd-relative)
```

The config file is the root from which all other paths are derived. Everything else lives in the same directory or subdirectories beneath it.

---

## Engagement state file

The active engagement's full in-memory state is periodically flushed to the config file path itself:

```
<config-file>                     # e.g. ./engagement.json
```

This single JSON file contains:

- **Engagement metadata** — id, name, scope, phases, campaigns, objectives, opsec profile
- **Knowledge graph** — all nodes and edges with their properties
- **Activity log** — up to 5,000 most-recent entries (tiered truncation preserves milestones)
- **Agent registry** — registered agents and their status
- **Chain checkpoints** — hash-chain integrity anchors (when `hash_chain_enabled: true`)

The server writes this file on every tool call that mutates state (debounced) and on clean shutdown.

### Snapshots

Point-in-time recovery snapshots live in a hidden subdirectory next to the state file:

```
<config-dir>/
└── .snapshots/
    ├── engagement-1746000000000.json
    ├── engagement-1746003600000.json
    └── ...                           # up to 10 retained (oldest pruned)
```

If the main state file becomes corrupted on startup, the server automatically recovers from the most recent snapshot.

### WAL (mutation journal)

Engagements with `engagement_nonce` set use a write-ahead log for durability between debounced snapshots:

```
<config-dir>/
└── journal.jsonl                     # append-only; truncated after each snapshot
```

Legacy engagements (no `engagement_nonce`) skip this file.

---

## Engagements directory

When you create additional engagements (via `create_engagement`), their state files are stored alongside the active one:

```
<config-dir>/
└── engagements/
    ├── <engagement-id-A>.json
    ├── <engagement-id-B>.json
    └── ...
```

---

## Evidence store

Full-fidelity stdout/stderr from every subprocess is streamed to blobs in:

```
<config-dir>/
└── evidence/
    ├── manifest.json                 # index of all evidence records
    ├── <sha256-prefix>-stdout        # raw stdout bytes
    ├── <sha256-prefix>-stderr        # raw stderr bytes
    └── ...
```

Evidence records are referenced by ID (`stdout_evidence_id`, `stderr_evidence_id`) in the activity log and report evidence chains. Retrieve them with `get_evidence(evidence_id)`.

Evidence files are named by content SHA-256 so identical outputs deduplicate automatically.

---

## Report archive

Reports rendered via `generate_report` or the dashboard "Generate Report" button are persisted in:

```
<config-dir>/
└── reports/
    ├── manifest.json                 # index of all report records
    ├── <report-id>.md                # markdown format
    ├── <report-id>.html              # HTML format
    ├── <report-id>.pdf               # PDF format (requires puppeteer)
    └── <report-id>.json              # structured JSON format
```

List reports: `GET /api/reports`. Download: `GET /api/reports/:id`.

---

## Tape sessions

Tape recordings (full session transcripts + timing data) are stored in a configurable location:

```
$OVERWATCH_TAPE_DIR/                  # env override
config.tape.dir/                      # engagement config field
./tapes/                              # default (cwd-relative)
└── <session-id>/
    ├── metadata.json
    ├── events.jsonl
    └── ...
```

---

## Example layout

A typical engagement directory after one session:

```
./
├── engagement.json                   # active state (config + graph + activity log)
├── .snapshots/
│   └── engagement-1746005400000.json
├── engagements/
│   └── eng-abc123.json
├── evidence/
│   ├── manifest.json
│   ├── a3f7b2c1d4e5-stdout
│   └── b8e2a9f0c6d1-stderr
├── reports/
│   ├── manifest.json
│   ├── rpt-xyz789.md
│   └── rpt-xyz789-client.html
└── tapes/
    └── session-2026-05-12-1430/
        ├── metadata.json
        └── events.jsonl
```

---

## Backup and portability

**To back up an engagement:** copy the entire directory containing `engagement.json`.

The state file is self-contained — it includes the full graph, activity log, and all config. Evidence blobs are referenced by ID from the manifest; copy the `evidence/` subdirectory to retain them.

**To move to another machine:** copy the directory, set `OVERWATCH_CONFIG` to point at the new path, and start the server.

**To export a shareable bundle:** use `export_graph` which produces a single JSON file with the graph and metadata (no credentials or raw evidence).

---

## What is NOT stored on disk

- **MCP session state** — in-memory only, lost on restart. Agents re-register on reconnect.
- **Pending action queue** — reconstructed from the activity log on startup.
- **Cache** — path-graph projections and community detection caches are rebuilt on demand.
- **Credentials in plaintext** — `cred_value` stores only the redacted form or a reference. Raw secrets are never written.
