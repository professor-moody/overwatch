# Changelog

All notable source releases are documented here. Overwatch follows semantic
versioning for public wire/configuration contracts and uses explicit persisted
state and journal versions for durable engagement data.

## 0.2.0 — 2026-07-18

This is the first explicit compatibility baseline after the reliability,
workflow, architecture, and post-refactor hardening programs.

### Added

- Non-destructive WAL recovery, versioned state migration, and transaction
  journal V2.
- Durable agents, campaigns, approvals, planner work, credential playbooks,
  process ownership, session descriptors, and application-command outcomes.
- One shared-daemon lifecycle for terminal Claude, the CLI, dashboard, and
  managed agents, including state-preserving setup, doctor, upgrade, and status.
- Dashboard contract registry, authenticated HTTP/WebSocket transport, keyed
  WebSocket V2 patches, deterministic browser journeys, and scale/soak gates.
- A generated compatibility ledger with explicit retirement criteria and
  claim-mapped CI evidence for every retired legacy surface.

### Changed

- `npm run upgrade` performs an early live migration-readiness check and a
  second authoritative frozen check after verified shutdown. A frozen-check
  failure attempts to restart the unchanged compiled daemon before any install
  or build; if another physical owner wins that compatibility handoff, startup
  fails closed without mutating engagement data.
  A cross-process reservation then protects the frozen state family through
  install/build and transfers ownership to the replacement runtime without an
  unowned writer gap.
- The bundled dashboard is a WebSocket V2 client. Server WebSocket V1 remains
  available for the documented compatibility window.

### Removed

- Bundled-dashboard consumption of WebSocket V1 state updates. The server
  continues to provide WebSocket V1 to older clients and reports an explicit
  upgrade diagnostic if the bundled V2 client reaches a V1 daemon.
- The unused internal `PendingActionQueue.abortByAgent()` wrapper; queue owners
  use canonical task identity through `abortByTask()`.

### Compatibility

- Existing V0/V1 state families remain readable and migrate only after a
  checksummed backup and complete replay.
- Agent identity, parser response, playbook projection, session rollback,
  hash-link redirects, dashboard HTTP V1, and WebSocket V1 compatibility remain supported. See
  [the compatibility policy](docs/compatibility.md).
