# Compatibility and releases

Overwatch `0.2.0` is the first explicit source-release and compatibility
baseline. Earlier `main` revisions were pullable development snapshots, but the
repository did not carry a tag, package-version transition, or dated retirement
ledger. A comment saying “one release” therefore does not prove that a public
wire field or persisted reader is safe to delete.

The generated ledger below is the release contract. `npm run check:docs` rejects
drift between this page, the machine-readable
[`compatibility-manifest.json`](reference/compatibility-manifest.json), and the
source registry.

<!-- BEGIN:compatibility-ledger -->
| Compatibility surface | Status | Canonical replacement | Release boundary |
|---|---|---|---|
| <a id="agent-identity-aliases"></a>`id`/`agent_id` task fields and legacy label input | Retained | `task_id` and `agent_label` | 0.3.0 |
| <a id="agent-identity-v1-fields"></a>legacy agent identity fields stored in PersistedStateV1 relationships | Migration path retained | a future versioned state migration to canonical task identity | Evidence-gated |
| <a id="agent-work-v1-fallback"></a>PersistedStateV1 agent tasks without explicit `work` metadata | Migration path retained | versioned `AgentWorkMetadataV1` attached to every task | Evidence-gated |
| <a id="coordination-owner-aliases"></a>legacy owner/source fields in approvals, questions, and proposed plans | Retained | `owner_task_id` and `owner_agent_label` | Evidence-gated |
| <a id="parser-response-aliases"></a>`parse_status: "no_parser"` and `parser_exception` | Retained | `parse_outcome` and `error` | 0.3.0 |
| <a id="playbook-projection-aliases"></a>credential expansion stamps and AWS `principal` response field | Retained | durable playbook runs and `bindings.principal_name` | 0.3.0 |
| <a id="dashboard-http-v1"></a>dashboard HTTP compatibility contract v1 | Retained | the current stable endpoint and envelope registry | Evidence-gated |
| <a id="dashboard-websocket-v1"></a>full-state main WebSocket envelopes when no contract is selected | Retained | main WebSocket contract v2 keyed patches | 0.3.0 |
| <a id="state-v0-journal-v1-readers"></a>absent-version state V0 and primitive journal V1 readers | Migration path retained | PersistedStateV1 and transaction journal V2 | Evidence-gated |
| <a id="legacy-playbook-placeholders"></a>schema-less playbook run placeholders recovered from legacy state | Migration path retained | versioned durable PlaybookRun records and explicit new-run replacement | Evidence-gated |
| <a id="session-v1-rollback-lifecycle"></a>conservative V1 `closed`/`error` lifecycle plus additive recovery metadata | Retained | `resume_available` and `interrupted` runtime lifecycle | Evidence-gated |
| <a id="subagent-control-prompt"></a>`OVERWATCH_PROMPT_VARIANT=control` rollback selection | Retained | the context-first `lean` sub-agent prompt | 0.3.0 |
| <a id="subagent-isolation-config"></a>`subagent_isolation` from the Node IPC worker scaffold | Retained | managed-daemon worker runtime settings | Evidence-gated |
| <a id="dashboard-hash-deep-links"></a>`#panel=...` dashboard navigation | Retained | route and query-string deep links | 0.3.0 |
| <a id="dashboard-v1-state-consumer"></a>bundled-dashboard consumption of WebSocket v1 full-state updates | Retired in 0.2.0 | WebSocket v2 full base plus revisioned keyed patches | 0.2.0 |
| <a id="pending-action-label-wrapper"></a>internal `PendingActionQueue.abortByAgent()` label-only wrapper | Retired in 0.2.0 | `abortByTask(task_id, legacy_label)` | 0.2.0 |
<!-- END:compatibility-ledger -->

## Removal policy

A compatibility entry can be removed only when all of these are true:

1. Its earliest removal version has arrived, when one is specified.
2. Every item in its retirement-evidence list has a deterministic test or a
   recorded release artifact.
3. Persisted data has an explicit reader and migration path; changing a current
   TypeScript type is not a migration.
4. When a persisted format changes, the preceding released binary can restore
   a checksummed migration backup, and the current binary can re-upgrade that
   restored copy.
5. HTTP, MCP, CLI, dashboard, and WebSocket clients either interoperate across
   the supported release window or fail with an explicit version diagnostic.

State V0 and primitive journal V1 readers are migration machinery, not ordinary
deprecated API aliases. They remain until copied-engagement inventory and
backup/restore drills prove that retirement cannot strand an engagement. A
future PersistedStateV2 must add a V1 reader and must continue verifying
historical V0→V1 backup manifests by their immutable transition tuple.

## Upgrade and rollback contract

After pulling a release, use:

```bash
git pull --ff-only origin main
npm run upgrade
npm run daemon:status
```

Upgrade checks the source/dependency inputs and runs an early offline state/WAL
migration check while the current daemon remains available. After the
identity-verified stop, it repeats the state/WAL check against the frozen file
family before running `npm ci` or a build. An early failure leaves the daemon
running; a frozen-check failure releases the reservation and attempts to
restart the unchanged compiled daemon. A competing physical owner can win that
legacy-runtime handoff window, in which case restart fails closed without
mutating engagement data. Only a successful frozen check permits dependency or
build mutation. A cross-process state-family reservation is held from that
frozen check through install/build.
The replacement runtime publishes its durable owner while presenting the same
reservation token, then waits for the lifecycle supervisor to release the
reservation before recovery. Thus there is no unowned writer gap, and a second
checkout or direct runtime fails closed. The lifecycle does not delete or
rewrite configuration, state, WAL, snapshots, evidence, reports, tapes, cookie
jars, or migration backups.

Version 0.2.0 is the first supported source-release baseline, so there is no
supported 0.1 binary rollback claim. For a future same-format rollback, stop
Overwatch and restore a complete pre-upgrade copy or bundle of the engagement
file family into a separate directory; never mix individual files from two
points in time. If an upgrade changes the persisted state or journal format,
restore the complete checksummed migration backup instead. Confirm the config,
state, WAL, snapshots, artifacts, and available manifest checksums before
starting the older binary. N-1 rollback becomes a release gate beginning with
the release after 0.2.0; the current same-checkout lifecycle smoke is not
presented as N-1 evidence.

## Version 0.2.0 boundary

This release removes two internal paths: WebSocket V1 state consumption inside
the bundled V2 dashboard and the unused label-only pending-action abort
wrapper. It deliberately retains hash-link redirects, HTTP and WebSocket V1,
public identity, parser, playbook, session, and persisted-format compatibility.
Their first eligible breaking boundary is documented in the ledger rather than
inferred from merge count.

## Release validation

Every pull request and `main` build runs `npm run check:release`, which verifies
the package/lockfile version, source release constant, changelog, generated
compatibility manifest, built runtime metadata, and manifest hash as one
release identity. A release tag must be named `v<package-version>` and point at
the exact merged commit; tag CI reruns the same checks with
`--require-head-tag`; tag CI also requires an annotated tag and equality with
the freshly fetched `origin/main` commit. After both merged-`main` CI and tag CI
pass, the maintainer manually publishes the package artifact and its SHA-256
checksum with the GitHub release.
