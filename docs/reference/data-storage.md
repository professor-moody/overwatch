# Data Storage Reference

This page describes exactly what Overwatch writes to disk, where each file lives, and how to back up or move an engagement.

---

## Confidentiality boundary

Overwatch state and audit artifacts are **operator-confidential by design**. The active state file, evidence blobs, JSON-RPC tapes, dashboard graph/API responses, and engagement bundles may contain live credential material, raw tool output, target paths, operator paths, and full request/response frames. This is intentional for an engagement orchestrator: operators often need full-fidelity data to reproduce a path, replay reasoning, or validate a finding.

Do not treat these files as client deliverables. Use `generate_report({ client_safe: true })` or a purpose-built sanitization pass when preparing material for a client or external system.

---

## Config file

Overwatch reads its active engagement config from the path set by the `OVERWATCH_CONFIG` environment variable. If that variable is unset, it falls back to `./engagement.json` relative to the working directory you start the server from.

```
OVERWATCH_CONFIG=/path/to/engagement.json  # override
./engagement.json                          # default (cwd-relative)
```

The config file is the operator-authored definition: scope, objectives, OPSEC, phases, and campaign defaults. Mutable graph state is stored separately beside it by default.

---

## Engagement state file

The active engagement's full in-memory state is periodically flushed to a separate state file beside the config:

```
<config-dir>/state-<engagement-id>.json
```

This single JSON file contains:

- **Engagement metadata** — id, name, scope, phases, campaigns, objectives, opsec profile
- **Knowledge graph** — all nodes and edges with their properties
- **Credential material** — `cred_value` and related fields when a parser/tool captured reusable material
- **Activity log** — up to 5,000 most-recent entries (tiered truncation preserves milestones)
- **Agent registry** — registered agents and their status
- **Chain checkpoints** — hash-chain integrity anchors (when `hash_chain_enabled: true`)

Set `OVERWATCH_STATE_FILE=/path/to/state.json` to override the default. The server writes this file on every tool call that mutates state (debounced) and on clean shutdown. The config file remains clean unless you explicitly edit engagement settings.

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

Evidence is raw by default. Client-safe report generation redacts sensitive values in the rendered output; it does not rewrite the underlying evidence store.

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
├── engagement.json                   # active config (scope, objectives, OPSEC)
├── state-example-engagement.json     # live graph, activity log, agents, campaigns
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

**To back up an engagement:** copy the entire directory containing `engagement.json` and `state-<id>.json`.

The state file contains the full graph, activity log, agents, campaigns, and checkpoints. The config file contains the operator-authored engagement definition. Evidence blobs are referenced by ID from the manifest; copy the `evidence/` subdirectory to retain them.

**To move to another machine:** copy the directory, set `OVERWATCH_CONFIG` to point at the new path, and start the server.

**To export a shareable bundle:** use `bundle_engagement`. It produces a portable `.tar.gz` containing the state file, evidence blobs, generated reports, `bundle-manifest.json`, and the mutation journal when present. Optional snapshots can be included. Registered JSON-RPC tapes are referenced in the manifest but are not copied.

**To export only the graph:** use `export_graph`. It returns a JSON graph dump for external analysis, custom reporting, or visualization; it is not a full evidence/report bundle.

Bundles and graph exports inherit the same operator-confidential boundary as the source state. If you need a client-safe artifact, generate a client-safe report rather than sharing raw bundles or graph JSON.

---

## What is NOT stored on disk

- **MCP session state** — in-memory only, lost on restart. Agents re-register on reconnect.
- **Pending action queue** — reconstructed from the activity log on startup.
- **Cache** — path-graph projections and community detection caches are rebuilt on demand.
- **Runtime-only external connectors** — for example, a live PostgreSQL connection handle is session-scoped; only the redacted display DSN survives reload.
