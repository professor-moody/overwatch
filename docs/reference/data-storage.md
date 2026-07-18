# Data Storage Reference

This page describes exactly what Overwatch writes to disk, where each file lives, and how to back up or move an engagement.

---

## Confidentiality boundary

Overwatch state and audit artifacts are **operator-confidential by design**. The active state file, evidence blobs, JSON-RPC tapes, dashboard graph/API responses, and engagement bundles may contain live credential material, raw tool output, target paths, operator paths, and full request/response frames. This is intentional for an engagement orchestrator: operators often need full-fidelity data to reproduce a path, replay reasoning, or validate a finding.

Do not treat these files as client deliverables. Use `generate_report({ client_safe: true })` or a purpose-built sanitization pass when preparing material for a client or external system.

---

## Config file

Raw Overwatch processes read their active config from `OVERWATCH_CONFIG` and
fall back to `./engagement.json`. The recommended managed daemon does not
retarget itself from each startup shell: `npm run setup` persists the exact
selected config and state paths in `.overwatch-runtime/profile.json`, and
lifecycle commands use that profile.

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

The active engagement's durable checkpoint is stored in a separate state file
beside the config:

```
<config-dir>/state-<engagement-id>.json
```

This single JSON file contains:

- **Format envelope** — `state_version` and `journal_version`
- **Engagement metadata** — id, name, scope, phases, campaigns, objectives, opsec profile
- **Knowledge graph** — all nodes and edges with their properties
- **Credential material** — `cred_value` and related fields when a parser/tool captured reusable material
- **Activity log** — up to 5,000 most-recent entries (tiered truncation preserves milestones)
- **Orchestration state** — agents, campaigns, approvals, directives, leases, frontier linkage and weights
- **Coordination state** — proposed plans, questions/answers, command previews/outcomes, versioned playbook runs/steps/attempts and ownership, process ownership, and secret-free session descriptors
- **Chain checkpoints** — hash-chain integrity anchors (when `hash_chain_enabled: true`)
- **External artifact references** — evidence/report manifests, tapes, bundles, and cookie jars by path/hash rather than embedded content

For an explicitly isolated raw process or stopped setup selection,
`OVERWATCH_STATE_FILE=/path/to/state.json` overrides the default. Do not use it
to retarget an already configured managed daemon; update the stopped profile
through setup instead. Durable
mutations enter the WAL before live apply; checkpoint snapshots are
write-triggered/debounced and are also flushed on clean shutdown. Active
configuration changes atomically update the config file as part of their
managed convergence path; an API/tool success means its revision/hash matches
runtime and state.

### State format versions and migration

A state file with no `state_version` is legacy V0. Current writers emit
`state_version: 1` and `journal_version: 2`. V0 remains readable, but startup
does not publish V1 until it has:

1. acquired the migration/write lease and selected a valid recovery base;
2. created and verified a checksummed backup of config, state, WAL, snapshots,
   rollback/config intents, and config-recovery artifacts;
3. completely replayed the backed-up legacy WAL;
4. reverified the source inventory and durably recorded the migration intent;
   and
5. written the first V1 checkpoint.

Backups live beside state:

```
<state-dir>/.migration-backups/
└── state-<id>-<timestamp>-v0-to-v1-<uuid>/
    ├── files/
    ├── manifest.json
    ├── manifest.sha256
    └── complete
```

While a migration or filesystem write boundary is active, Overwatch may create
`<state>.migration-lock/` or `<state>.writer-lock/`. They coordinate state,
WAL, snapshot, and active-config writers across processes. Do not remove a live
lock; startup validates process identity and only reclaims a stale owner.

Use `overwatch state migrate --check` before an upgrade to inspect the selected
base, WAL readiness, format versions, and config agreement without modifying
engagement files. An unsupported newer state or journal version starts
read-only and is never replaced, reseeded, compacted, or downgraded.

To run an older binary after migration, restore the **complete verified
migration backup into a clean engagement directory** first. Merely checking out
an older binary against V1 files is not a rollback.

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

Snapshot creation is triggered by durable writes once the snapshot interval is
eligible; there is no independent periodic timer that implies progress while
the engagement is idle. Up to five valid snapshots are retained.

### WAL (mutation journal)

The write-ahead log lives beside its state file and uses the state basename:

```
<config-dir>/
└── state-<engagement-id>.journal.jsonl
```

Every engagement uses the WAL, including legacy configurations without an
`engagement_nonce`. Journal V2 stores each logical `EngineTransaction` as a
checksum-protected `tx_begin`, one or more bounded operation chunks, and a
`tx_commit`. Recovery exposes only complete committed transactions and applies
their operations atomically; an incomplete physical tail is never treated as a
committed mutation. Existing primitive journal V1 records remain readable for
migration and backward compatibility.

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
    ├── archive-format.json           # descriptor-authority format marker
    ├── manifest.json                 # rebuildable aggregate index
    ├── <report-id>.record.json       # immutable UUID → payload commit descriptor
    ├── <report-id>.deleted.json      # deletion commit/tombstone
    ├── <report-id>.md                # markdown format
    ├── <report-id>.html              # HTML format
    ├── <report-id>.pdf               # PDF format (requires puppeteer)
    └── <report-id>.json              # structured JSON format
```

List reports: `GET /api/reports`. Download: `GET /api/reports/:id`.

Report publication is payload → immutable descriptor → aggregate manifest. The descriptor is the per-report commit authority; `manifest.json` is repaired from valid descriptors after a crash. The format marker prevents a descriptorless payload from being mistaken for a committed new-format report. A valid legacy manifest remains authoritative during upgrade, so orphan payloads are preserved but not silently resurrected. Deletion publishes a tombstone before unlinking the descriptor/payload. Invalid or unreadable tombstones hide the affected report and make report mutations read-only while preserving all bytes for reconciliation.

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
├── .migration-backups/                 # verified V0→V1 rollback authorities
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

**To back up a live engagement:** prefer `bundle_engagement`, which captures
through the engine's artifact/state barrier. For a raw copy, first stop the
verified daemon or use a filesystem snapshot that is consistent across the
entire selected state family. The config and state may live in different
directories; identify both with `npm run daemon:status` or `npm run doctor`.

Copy `engagement.json`, `state-<id>.json`, and all adjacent WALs, snapshots,
write/migration/rollback intents, conflict archives, migration backups,
evidence, reports, tapes, and recovery artifacts. Do not omit uncertain bytes
from a crash-state capture.

The state file contains the full graph, activity log, agents, campaigns, and checkpoints. The config file contains the operator-authored engagement definition. Evidence blobs are referenced by ID from the manifest; copy the `evidence/` subdirectory to retain them.

**To move to another machine or path:** copy the complete artifacts while the
writer is stopped, then run `npm run setup` in the moved checkout before
starting. Setup regenerates machine-local profile, token-path, MCP, and Claude
hook wiring without replacing the engagement. Do not use a transient
`OVERWATCH_CONFIG` override as the normal managed startup path.

**To export a shareable bundle:** use `bundle_engagement`. It produces a portable `.tar.gz` from one artifact-first/state capture barrier containing the state file, active config, evidence, reports, registered JSON-RPC tapes, `bundle-manifest.json`, and the mutation journal when present. Manifest v2 records format versions, checkpoint/config identity, recovery status, exact recovery-authority paths, and per-file sizes and SHA-256 digests. Active config intents, conflict archives, migration backups, rollback intents, and nonstandard recovery journals are copied under `recovery-artifacts/` when present. Optional snapshots can be included. Publication is atomic; an interrupted build cannot replace a prior good archive with a partial tarball. During degraded read-only recovery, staging and the default output move to the OS temp directory so diagnostic export does not require writes under the engagement root.

Report payloads are published before immutable per-report recovery descriptors and the aggregate report manifest. Startup quarantines a corrupt report manifest and reconstructs the index from descriptors or legacy payloads; degraded read-only startup performs the same projection in memory without changing the source bytes. Report/ATT&CK-Navigator and retrospective file sets also publish as immutable checksummed generations with one small current-generation pointer as their commit boundary; fixed filenames are post-commit compatibility mirrors. Evidence streams publish an owner-identity intent before accepting bytes, allowing restart to retain an interrupted partial capture with an explicit `capture_error`. Named curl cookie jars use a bounded per-jar staging transaction, so a failed, zero-cookie, or killed login does not truncate the previous authenticated session.

**To export only the graph:** use `export_graph`. It returns a JSON graph dump for external analysis, custom reporting, or visualization; it is not a full evidence/report bundle.

Bundles and graph exports inherit the same operator-confidential boundary as the source state. If you need a client-safe artifact, generate a client-safe report rather than sharing raw bundles or graph JSON.

---

## State taxonomy

Durable state includes graph/config truth, evidence references, orchestration,
approvals, directives, proposals, questions/answers, command idempotency
outcomes, legacy tracked-process inventory, canonical runtime-run ownership, and
secret-free session descriptors.

The following remain intentionally ephemeral:

- PTYs, sockets, child-process objects, live WebSocket clients, and terminal buffers
- database connection handles
- uncaptured environment variables, adapter/runtime passwords and private keys,
  and unsaved browser drafts (credential values deliberately ingested into the
  graph remain durable operator-confidential state)
- path-graph projections, UI projections, telemetry buffers, and other rebuildable caches

After restart, durable descriptors may say that a process or session existed,
but no runtime handle is fabricated. Runtime-run identity is checked before any
signal: a verified owned orphan is finalized as interrupted, while a reused or
unverifiable PID becomes unresolved/unknown and is never killed on guesswork.
PTY, SSH, and socket-connect session descriptors become interrupted/non-live;
rearm-listener descriptors become `resume_available` and require explicit
`resume_session`, which creates a new listener/connection generation rather
than reviving the old handle.
