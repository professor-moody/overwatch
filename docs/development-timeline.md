# Development Timeline

This page is a human-readable trail of the work as it landed in commits. Use it when you need to explain the project moving from one capability layer to the next without asking someone to reverse-engineer `git log`.

For source-of-truth details, inspect the commit:

```bash
git show --stat <commit>
git show <commit>
```

## Updating This Page

When a meaningful sprint or reliability patch lands:

1. Add the commit to the timeline table with the short hash, date, area, and the operator-visible result.
2. Keep entries newest first.
3. Link the commit to the test or validation evidence when it matters for trust.
4. Prefer one concise row per commit; add a narrative section only when several commits form a larger milestone.

Useful generation command:

```bash
git log --date=short --pretty=format:'| `%h` | %ad | AREA | %s | RESULT |' --max-count=20
```

## Recent Timeline

| Commit | Date | Area | Work Step | Operator-Visible Result |
|--------|------|------|-----------|-------------------------|
| 0.2.0 release | 2026-07-18 | Compatibility/release | Established the first explicit version boundary, generated an evidence-linked retirement ledger, retired two internal shims, and added live plus frozen state/WAL upgrade checks. | Operators can pull and upgrade the shared daemon without guessing whether a legacy reader is safe to delete; future removals now require N-1 and rollback evidence. |
| PR10 release | 2026-07-18 | Scale and soak | Added durable 50,000-task gates, linear WebSocket state patches, indexed recovery, mixed restart/snapshot soak, and complete dashboard lifecycle checks. | Large engagements keep heartbeat and dashboard updates bounded, restart without losing coordination truth, and fail CI on scale or resource regressions. |
| `7b97f68` | 2026-07-18 | Agent work shaping | Added durable handoff, split, duplicate detection, and canonical merge workflows. | Completed work can move to a specialist without losing lineage, evidence references, or exact task identity. |
| `c99062a` | 2026-07-17 | Agent architecture | Established narrow agent workspace and command boundaries. | Agent lifecycle, reads, mutations, and dashboard projection have explicit owners instead of sharing the graph-engine surface implicitly. |
| `0491bcf` | 2026-07-17 | Runtime lifecycle | Added a managed one-daemon setup/start/stop/restart/upgrade workflow. | Terminal Claude, the CLI, dashboard, and managed workers can share one engagement without competing daemon writers. |
| `247027d` | 2026-07-17 | Application commands | Routed remaining external mutation adapters through durable idempotent commands. | Retried HTTP, MCP, CLI, planner, session, and runner mutations return their original outcome rather than executing twice. |
| `115c250` | 2026-07-17 | Artifact durability | Made reports and external artifacts generation- and pointer-committed. | Interrupted publication retains the prior valid report/evidence authority and startup can repair compatibility mirrors. |
| `eb15f19` | 2026-07-17 | Test hermeticity | Removed shared-build and runtime assumptions across the supported Node matrix. | CI jobs prove their own build/runtime inputs and no longer pass because another job left artifacts behind. |
| `4872be0` | 2026-07-17 | Persistence scaling | Replaced high-amplification graph mutations with bounded transaction deltas. | Small changes no longer clone or journal the full engagement graph. |
| `acac0e0` | 2026-07-17 | Planner reliability | Made headless planning durable, timed, and ownership-safe. | Planner timeout/failure is explicit and terminal/dashboard Claude sessions do not contend for one transient plan. |
| `7ea0586` | 2026-07-17 | Operator safety | Preserved state visibility and dashboard connectivity during recovery/config divergence. | A changing config cannot crash dashboard reads or silently discard the current engagement. |
| PR15 release | 2026-07-17 | Public contracts/docs | Generated tool schemas, categories, archetype inventories, capability counts, and drift gates; made shared-daemon setup the default and reconciled public architecture/recovery claims. | New operators reach the one-daemon workflow by default, terminal Claude and dashboard workers coexist without sharing sessions, and stale public inventories fail CI. |
| `8a25fc7` | 2026-07-17 | Reliability gates | Added deterministic semantic journeys, crash/restart coverage, and mandatory browser CI. | Recovery, command, campaign, playbook, token, and reconnect behavior now fail CI when their operator journeys regress. |
| `ee5d37f` | 2026-07-17 | Architecture/performance | Decomposed stabilized hotspots and bounded dashboard projection/delta work. | Large engagements avoid unnecessary full-state work and the initial dashboard bundle is held to a budget. |
| `1881cd3` | 2026-07-16 | Playbooks | Added durable playbook definitions, runs, steps, attempts, ownership, and retry/resume operations. | Terminal and dashboard operators can coordinate credential expansion without overwriting evidence or claiming the same step. |
| `38ca6d2` | 2026-07-16 | Planner startup | Added build-freshness and runtime diagnostics around planner startup. | A stale daemon/build is reported instead of masquerading as a current planner that times out or returns old UI text. |
| `028f641` | 2026-07-16 | Planner isolation | Isolated managed Claude workers from interactive terminal Claude project settings. | Dashboard-deployed planners and agents can run beside the operator's terminal Claude without sharing process-local configuration. |
| `02ada7a` | 2026-07-16 | Dashboard contracts | Established shared compatibility contracts, endpoint/WS manifests, and authoritative projectors. | REST, full-state, and WebSocket views agree on agents, campaigns, graph state, and console events. |
| `20698fe` | 2026-07-16 | Application commands | Introduced transport-neutral, idempotent command services. | MCP, dashboard, CLI, planners, and runners use one durable mutation boundary and duplicate commands return their original outcome. |
| `a2d0c44` | 2026-07-16 | Sessions | Persisted listener intent and connection generations with explicit resume. | Restarts no longer present dead sockets as live; rearmed listeners require an operator Resume and new connections get fresh generations. |
| `284f42b` | 2026-07-16 | Process ownership | Added durable runtime-run ownership and supervisor handshakes. | Startup can distinguish verified orphans from reused/unverifiable PIDs and finalize interrupted work once. |
| `755f1ab` | 2026-07-16 | Agent coordination | Normalized task identity and persisted proposals, questions, answers, and lifecycle state. | Agent attribution survives restart without guessing ambiguous labels, and open operator decisions return to the inbox. |
| `3257e16` | 2026-07-16 | Transaction journal | Established transaction journal v2 and the canonical mutation applier. | Only checksum-valid committed transactions replay; post-commit apply failures stop writes and recover through the same applier. |
| `bbb6cd3` | 2026-07-16 | State migration | Added explicit persisted-state versions, backup-first migration, and compatibility checks. | Legacy engagements can be checked/migrated without silent reseeding, while newer unsupported formats open read-only. |
| `c7cc7d5` | 2026-07-15 | Config/scope durability | Made active config, state, scope promotion, and recovery revisioned and crash-consistent. | Config divergence is explicit and reconcilable without discarding the current engagement graph. |
| `a9da490` | 2026-07-15 | Dashboard correctness | Corrected frontier, campaign, agent, graph, settings, health, objective, token, and socket semantics. | The operator dashboard reflects backend state, supports remote-token mode, and reconnects without duplicate sockets. |
| `53c7870` | 2026-07-15 | Parser/playbooks | Unified parser context/outcomes and repaired AWS, GitHub, and Entra expansion. | A zero-yield requested parse is visible as failure, context survives every execution path, and cloud steps land what they advertise. |
| `98ee0f0` | 2026-07-15 | WAL recovery | Made base selection and WAL replay non-destructive. | Malformed or unknown records preserve their remaining tail, and a missing valid base enters degraded read-only recovery rather than creating an empty engagement. |
| `b16514f` | 2026-05-27 | Operator trust surfaces | Added `/api/trust-signals`, dashboard trust summaries, graph inspector signals, report verification notes, and route-smoke/demo coverage. | Operators can see when a no-finding, no-path, IAM decision, parser output, or CVSS score needs verification across Overview, Activity, Findings, Graph, Smoke, and reports. |
| `29c7e34` | 2026-05-27 | Dashboard trust signals | Surfaced correctness caveats from parser, ingest, path, IAM, and CVSS work in dashboard panels and deferred Bedrock integration to a separate plan. | Activity and Findings now show compact trust labels instead of burying uncertainty in raw JSON. |
| `837d4d2` | 2026-05-27 | Durability/testing | Added regression coverage for state persistence, parsers, process edge cases, and correctness fixes. | The reliability sprint has tests around crash-safe persistence, parser edge cases, and subprocess failure modes. |
| `8efe5f8` | 2026-05-27 | Correctness reliability | Made IAM simulator and CVSS estimates expose uncertainty instead of overconfident denial/severity assumptions. | Unmapped Azure roles and capped assume chains now surface as indeterminate; CVSS estimates stop treating every credential as scope-changing/public-network critical. |
| `c653f1b` | 2026-05-27 | Parser/replay correctness | Fixed LDAP, NXC, Rubeus, and Okta token replay edge cases. | Lockout policy, plaintext credentials with spaces, SPN-derived Kerberos domains, and Okta OIDC Bearer replays behave closer to real tool output. |
| `799316e` | 2026-05-27 | Ingest/path reliability | Surfaced empty parse results, BloodHound unknown types, AzureHound dropped records, path projection failures, and inference fanout caps. | Operators can distinguish "no finding/no path" from "the parser or analyzer could not safely complete." |
| `a604f1d` | 2026-05-27 | Dashboard graph UX | Added typed graph deep links for node, evidence, frontier, finding, path, and edge contexts. | Graph links now preserve operator intent and open a focused graph context instead of silently falling back to the full graph. |
| `b9f7783` | 2026-05-26 | Dashboard graph UX | Polished focused graph navigation, graph overlays, toolbar density, inspector layout, and dashboard graph docs/tests. | Frontier-to-graph links now open a focused, centered neighborhood with less overlay crowding and stronger route-smoke coverage. |
| `726cb4e` | 2026-05-26 | Dashboard reliability | Split host-tool health from MCP tool registration, added `/api/mcp-tools` and `/api/readiness`, corrected SmokePanel response checks, and added smoke/API contract tests. | Smoke now reports stale API shapes as failures, optional missing local binaries as warnings, and dashboard readiness as a compact summary. |
| `78f9b6e` | 2026-05-26 | Tape/runtime cleanup | Cleaned up tape shutdown behavior and dependency audit state after tape attribution work. | CI returned green after tape shutdown changes; runtime cleanup no longer leaves the server in a noisy state. |
| `19ab38e` | 2026-05-26 | Tape attribution + hooks | Added tape start attribution across env/config/dashboard paths, HTTP startup parity, hook smoke script, and docs updates. | Operators can tell whether tape started from env, config, or dashboard, and can smoke-test Claude hooks locally. |
| `5af8937` | 2026-05-20 | Claude hooks | Tightened prompt-context gating, transcript scanning, Bash guard messaging, and hook test coverage. | Hooks became quieter during repo work while still nudging engagement output back into Overwatch. |
| `0a13fa0` | 2026-05-20 | Claude hooks | Added local Claude Code hook scripts, example settings, MCP example config, setup docs, and tests. | New clones have a documented path for enabling anti-drift hooks and raw-Bash guardrails. |
| `4a1a76f` | 2026-05-18 | Prompt/tool alignment | Updated AGENTS/CLAUDE guidance, prompt generator behavior, and tool docs around runtime source of truth and bundle exports. | Static bootstrap docs and generated prompts point operators toward the same workflow. |
| `bdd5ae2` | 2026-05-18 | Documentation | Refreshed tool references for bundle exports, cloud playbooks, JSON/Postgres ingest, sessions, tapes, transcripts, and activity-chain verification. | Tool docs reflect newer graph, bundle, session, reporting, and credential workflows. |
| `a5418cb` | 2026-05-17 | Reliability | Hardened dashboard bundle parity, WAL replay skipped/failed accounting, session-close journaling, and Postgres DSN schema handling. | Bundle downloads, crash replay, and redacted Postgres config reload are more trustworthy. |
| `182d02b` | 2026-05-17 | Sessions/evidence UX | Deepened session and evidence narratives in the dashboard. | Operators get better context around session activity and evidence relationships. |
| `2617e19` | 2026-05-16 | Dashboard demo | Enriched the deterministic demo workspace. | Local dashboard reviews exercise more realistic graph, session, campaign, and action states. |
| `e4d7bbf` | 2026-05-16 | Actions UX | Built a terminal-first actions workspace. | Pending approvals and action execution are easier to review from the dashboard. |
| `5918218` | 2026-05-16 | Graph/frontier UX | Upgraded graph inspector behavior and frontier links. | Operators can move between frontier items and graph context with less manual searching. |
| `f01f841` | 2026-05-15 | Operator workflow | Polished core dashboard workflow panels. | Overview, frontier, sessions, and related panels became more usable for live operations. |
| `740e2ca` | 2026-05-15 | Graph UX | Hardened graph workspace controls. | Graph navigation and control behavior became less fragile. |
| `d8a470b` | 2026-05-15 | Graph UX | Fixed graph fit camera reset. | Fit-to-view behaves predictably after graph interaction. |
| `5233520` | 2026-05-15 | Graph UX | Fixed graph manual dragging. | Manual layout adjustments no longer fight the graph view. |
| `b7725c4` | 2026-05-15 | Sessions UX | Built a sessions-first operator workspace. | Persistent shells and session metadata became first-class dashboard workflow objects. |
| `0c9bb74` | 2026-05-15 | Dashboard architecture | Refactored the dashboard graph workspace. | Later graph and operator UX work had a cleaner surface to build on. |
| `5fc94d4` | 2026-05-15 | Review fixes | Addressed persistence, bundle, config, ingest, and graph-correction review findings. | Several reliability defects from the review pass were closed in one patch set. |
| `f5522e0` | 2026-05-14 | Ingest reliability | Routed JSON and Postgres ingest through `prepareFindingForIngest`. | Structured ingests use the same normalization path as other findings. |
| `3a9bcab` | 2026-05-14 | Bundle export | Added engagement bundle MCP tool and dashboard download path. | Operators can package engagement state, evidence, reports, manifest, and related artifacts. |
| `88dc892` | 2026-05-14 | Ingest expansion | Added generic JSON/JSONL ingest. | Unsupported structured output can be mapped into graph nodes and edges. |
| `5c39a89` | 2026-05-14 | Graph UX | Added edge label toggle in the Layers menu. | Dense graph views can be decluttered during inspection. |
| `aba3d14` | 2026-05-14 | Review fixes | Fixed findings from Phase 2/3/4 and session-default review work. | Earlier reliability and session-default gaps were closed before dashboard polish continued. |
| `9bbebf6` | 2026-05-14 | Roadmap phase | Added ingest expansion, report commands, graph zoom fixes, Postgres support, and docs. | The tool gained broader ingestion/reporting capability and corresponding operator documentation. |

## Milestone Narrative

### Reliability, Workflow, And Architecture Program (PR1–PR15)

Commits `98ee0f0` through `8a25fc7` form the July reliability train. The work
first closed destructive recovery, parser, dashboard, and config correctness
gaps; then versioned durable state and established one committed transaction
boundary. It subsequently made coordination, process ownership, sessions,
commands, dashboard contracts, and playbooks restart-truthful before adding
performance bounds and semantic crash/browser gates. The PR15 release closes
the train with generated public inventories, shared-daemon startup defaults,
and documentation aligned to the resulting runtime.

### Ingest, Reporting, And Bundle Foundations

Commits `9bbebf6` through `3a9bcab` expanded how data enters and leaves Overwatch: JSON/JSONL ingest, Postgres-backed inspection, graph display fixes, report commands, and portable engagement bundles. The main operator story was moving from ad hoc graph growth to repeatable import/export workflows.

### Dashboard Becomes The Operator Workspace

Commits `0c9bb74` through `182d02b` reshaped the dashboard from graph viewer into operational cockpit: sessions, actions, graph inspection, frontier links, demo data, evidence narratives, and workflow panels. These commits are best shown together because each one made a different panel more useful during a live engagement.

### Reliability And Replay

Commit `a5418cb` hardened the state and export layer: bundle parity, WAL replay accounting, session edge journaling, and redacted Postgres config reload. This is the key commit to cite when discussing crash recovery and output trust.

### Prompt, Docs, And Anti-Drift Controls

Commits `bdd5ae2` through `5af8937` aligned docs, generated prompts, AGENTS/CLAUDE bootstrap files, and Claude Code hooks. The workflow goal was to keep model behavior anchored to Overwatch: retrieve state, route actions through instrumented tools, and put discoveries back into the graph.

### Tape Attribution And Dashboard Readiness

Commits `19ab38e`, `78f9b6e`, and `726cb4e` tightened runtime confidence. Tape now records why it started, hooks can be smoke-tested, and the dashboard separates API health, MCP registration, and host binary availability instead of mixing them into one noisy health signal.

### Correctness Signals Become Operator Surfaces

Commits `799316e` through `b16514f` converted several silent-failure classes into visible operator signals. Parsers, ingests, path analysis, IAM simulation, CVSS scoring, Activity, Findings, Overview, Graph inspector, Smoke, and reports now share the same "needs verification" vocabulary.

## Evidence Checklist

For a commit-level walkthrough, collect these items:

| Evidence | Command |
|----------|---------|
| Commit order | `git log --oneline --date=short --decorate` |
| Files changed by a commit | `git show --stat <commit>` |
| Exact patch | `git show <commit>` |
| CI status | `gh run list --branch main --limit 10` |
| CI details | `gh run view <run-id> --json status,conclusion,jobs` |
| Docs build | `npm run build:pages` |
