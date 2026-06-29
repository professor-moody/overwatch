# Roadmap

This page is the canonical development roadmap for Overwatch. The
[Development Timeline](development-timeline.md) explains what already landed;
this page explains what the project is building toward next.

The current product priority is **credentials, identity, and operations depth**:
every panel that shows agents, sessions, actions, credentials, or identities
should give operators distinct, actionable state language and clear lifecycle
visibility.

## Now: Credentials, Identity, And Operations Depth

These tracks should follow after the graph-context pass is stable.

### Credentials And Identity Workflow

- Keep **Credentials** as the canonical credential-material inventory:
  status, reachability, expiry, reveal/copy, graph links, and evidence links.
- Keep **Identity** as the trust-model view: IdPs, apps, principals,
  federation, MFA, and token relationships.
- Add derived views for credentials that are expired, unverified, reachable, or
  ready for cloud/SaaS expansion without duplicating secret-bearing cards in
  Identity.

### Agents, Sessions, And Actions Operations

- Make agent state, heartbeat freshness, task ownership, session liveness, and
  pending approvals easier to scan.
- Show blocked, stale, failed, interrupted, and completed work with distinct
  language and status treatment.
- Tie action lifecycle views back to evidence, graph context, and trust
  signals.

### Smoke, Demo, And Review Confidence

- Keep the deterministic demo dashboard rich enough to exercise every major
  operator state.
- Expand route smoke around operator workflows, not only page load.
- Keep the dashboard review checklist current for desktop layout, narrow-width
  layout, graph focus, trust signals, and duplicate-title regressions.

## Completed: Prompt Architecture Rethink + Behavior-Eval

The agent operating prompt is now changed against evidence, not taste. Step (a)
trimmed the persona opener to a one-line role tag; step (b) added a context-first
[`lean` sub-agent variant](prompt-stepb-design.md) (behind a variant seam —
`control` is still the default). Both are gated by a two-tier
[behavior-eval harness](prompt-eval.md): a deterministic rubric grader + structural
guard in CI, and an on-demand, cost-bounded real-model A/B (`npm run prompt-eval`).
Next: promote `lean` to default only on a clean real A/B, then the archetype-aware
registry refactor it unblocks.

## Completed: Graph And Evidence Context

Every operator click in the graph and evidence surfaces now lands on actionable
context: NodeDetailDrawer rows deep-link to specific findings and sessions;
clicking an edge opens a compact EdgeDetailPanel with source → target navigation;
the graph overlay and PathInfoBar handle narrow widths cleanly; OverviewPanel
frontier items, objectives, and recent finding events are all interactive.
Route smoke tests cover the `?item=` deep-link routes.

## Completed: Dashboard Command Center

The dashboard primitive-migration pass is done. All daily workflow panels
(Overview, Credentials, Identity, Activity, Agents, Sessions, Actions,
Findings, Graph, Smoke, Settings) use the shared `PageHeader`, `PanelSection`,
`ActionButton`, `FilterBar`, `StatusPill`, and `MetricTile` primitives.
Overview surfaces the operator queue (attention items, verification gaps, active
access, recent changes). CredentialsPanel surfaces unverified and
expansion-candidate counts. No duplicate titles, no decorative surfaces.

## Later: Backend And Runtime Tracks

These remain important but are not the active dashboard-polish sprint.

- **Playbook checkpointing:** track cloud/SaaS expansion steps as planned,
  running, parsed, failed, or skipped.
- **Source-trust labels:** distinguish tool-observed findings, target-asserted
  data, inferred edges, manual analyst input, and external imports.
- **Anti-canary detection:** flag honey credentials or canary-like target output
  before it drives the frontier.
- **Transport drivers / no-MCP internal mode:** Overwatch's engine is
  transport-agnostic and MCP is one driver, not the brain. Add a no-MCP internal
  driver (headless Claude + an `overwatch` CLI / local HTTP) for environments where
  MCP is unavailable, plus operator target-execution endpoints — same executor,
  same lifecycle and audit. The MCP driver stays first-class for external lab work.
  See [Deployment Architecture](deployment-architecture.md).
- **Process-isolated subagents:** move beyond the current scaffold toward
  role-by-role parity with schema-validated IPC.
- **Parser sandboxing:** constrain file-backed parser input and parser runtime
  privileges.
- **Bedrock integration:** keep the compact system-contract and middleware work
  in [Bedrock Integration Plan](bedrock-integration-plan.md) until an
  enterprise wrapper owns the API payload.

## Acceptance Gates

Dashboard roadmap work should run the normal source and docs gates:

```bash
git diff --check
npx tsc --noEmit
npm run test:source
npm run build:dashboard-next
mkdocs build --strict
```

For visible dashboard work, also run live route smoke against the demo dashboard
as described in [Development](development.md#dashboard-review-checklist).
