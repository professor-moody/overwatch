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

The config file is the operator-authored definition: scope, objectives, OPSEC,
phases, and campaign defaults. For an active engagement it is also a managed,
revisioned representation: Overwatch writes `config_revision` and `config_hash`
through to the file, live engine, and durable state. Mutable graph state remains
stored separately beside it by default.

During an active-config update, Overwatch may create a temporary durable intent:

```
<config-path>.write-intent.json
```

The intent records the source and target hashes/revision plus a checksum. It is
removed only after the file, runtime, audit event, and durable state complete.
If present after a crash, startup attempts to finish that known write. Preserve
it during backup or incident handling; deleting it can remove the information
needed to distinguish an interrupted write from unexplained divergence.

If an intent is valid but conflicts with the observed file or durable state,
Overwatch preserves its exact bytes (base64-encoded with observed-state audit
metadata) in a content-addressed conflict archive before requiring explicit
reconciliation:

```
<config-path>.write-intent.json.conflict-<sha256>.json
```

Once that archive is durable, the conflicting active intent is removed so it
cannot retain write authority. Preserve the conflict archive; it is audit and
recovery evidence, not a disposable temporary file.

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

Set `OVERWATCH_STATE_FILE=/path/to/state.json` to override the default. The
server writes this file on every tool call that mutates state (debounced) and on
clean shutdown. Active configuration changes also atomically update the config
file; an API/tool success means its revision/hash matches runtime and state.

### Snapshots

Point-in-time recovery snapshots live in a hidden subdirectory next to the state file:

```
<config-dir>/
└── .snapshots/
    ├── state-example-engagement.snap-2026-07-15T18-00-00-000Z-21409.json
    ├── state-example-engagement.snap-2026-07-15T18-30-00-000Z-21409.json
    └── ...                           # up to 5 retained (oldest pruned)
```

At startup, Overwatch selects the newest valid primary/snapshot base and replays
every newer committed WAL record. Incomplete replay remains degraded and
read-only; recovery never treats an older snapshot as permission to discard a
malformed, unknown, skipped, or failed WAL tail.

### WAL (mutation journal)

The write-ahead log lives beside its state file and uses the state basename:

```
<config-dir>/
└── state-<engagement-id>.journal.jsonl
```

Engagements with `engagement_nonce` journal primitive durable mutations.
Legacy engagements can acquire the same WAL before their first composite scope
or graph-correction mutation. On every startup, any existing non-empty WAL is
inspected and recovered regardless of whether the incoming config currently has
an `engagement_nonce`; feature flags never make durable bytes disappear.

Compaction removes only a contiguously applied prefix that is already covered
by a durable recovery base. A malformed or incomplete tail is preserved, and a
content-addressed `.quarantine-<sha256>.jsonl` copy may be written for repair.

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
├── engagement.json.write-intent.json # present only while a config write needs completion
├── state-example-engagement.json     # live graph, activity log, agents, campaigns
├── state-example-engagement.journal.jsonl # WAL when durable mutations are pending
├── .snapshots/
│   └── state-example-engagement.snap-2026-07-15T18-30-00-000Z-21409.json
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

**To back up an engagement:** copy the entire directory containing
`engagement.json` and `state-<id>.json`. Include any adjacent
`.write-intent.json`, intent conflict archives, mutation journal, and retained
snapshots; do not omit them from a crash-state capture.

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
