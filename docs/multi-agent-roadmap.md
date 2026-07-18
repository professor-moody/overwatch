# Multi-Agent Operator Roadmap

This is the focused roadmap for operating Overwatch as one coordinated team.
The general delivery state lives in [Roadmap](roadmap.md); the current interface
is documented in [Operator Cockpit](operator-cockpit.md).

## Thesis

The operator has three jobs:

- **Monitor** what agents, campaigns, processes, sessions, and playbooks are
  doing.
- **Decide** approvals, questions, recovery choices, and whether evidence is
  sufficient.
- **Command** intent through visible, validated, idempotent operations.

Natural language does not create a separate mutation path. Planner output is a
durable proposal; confirmation executes the same application commands used by
MCP, HTTP, the terminal CLI, and scripted agents.

## Shipped foundation

The reliability program through PR15 is represented in the current release.
The multi-agent operating model now includes:

- typed archetypes with bounded tool exposure, methodology skills, and
  capability tests;
- one Console attention queue for approvals, questions, stuck work, and agent
  state, plus targeted steering directives;
- durable task identity, proposals, questions/answers, campaigns, approvals,
  leases, transcripts, and frontier attribution;
- transport-neutral, idempotent application commands with retained command
  outcomes;
- truthful detached-process ownership and cleanup across restart;
- resumable listener intent and connection-generation-aware session state;
- durable playbook runs, steps, attempts, dependencies, bindings, retries, and
  ownership;
- shared dashboard contracts/projectors and browser journeys for planner,
  campaign, token, reconnect, recovery, and playbook workflows.

The public tool/archetype inventories and schema hashes are generated from that
runtime, and CI rejects documentation or dashboard-category drift.

## One daemon, multiple operator surfaces

Run one Overwatch daemon for the active engagement. Terminal Claude, the
`overwatch` CLI, the dashboard, and dashboard-deployed managed Claude workers
can operate at the same time because they share the daemon's durable task
leases, idempotency keys, playbook attempt ownership, and application commands.

Managed workers are isolated from the operator's interactive Claude project
settings. The daemon rejects a second writer, and startup freshness checks stop
a stale build from presenting an older planner UI or runtime contract as
current. This is not an MCP-versus-no-MCP split: MCP, HTTP, WebSocket, and CLI
are adapters over the same engine boundary.

## Prompt and role status

The context-first `lean` sub-agent prompt is the default. The older `control`
variant remains available throughout the 0.2.x compatibility release through
`OVERWATCH_PROMPT_VARIANT=control`; its retirement gate is tracked in the
[compatibility ledger](compatibility.md#subagent-control-prompt). Archetype missions and skills refine the
job and method; the generated system prompt remains the live source of
engagement state and tool availability.

## Remaining team-workflow candidates

These are post-program candidates rather than commitments:

### Better command previews

- Estimate likely graph changes, objective-distance effects, noise, and approval
  pressure before confirming a broad plan.
- Ask a concise clarifying question when target or blast radius is ambiguous.
- Offer quiet, faster, and credential-focused variants when the estimator has
  enough evidence to distinguish them.

### Agent handoff and work shaping

- Hand a discovery to the most appropriate specialist without losing frontier,
  evidence, or campaign attribution.
- Split a broad task into explicit child tasks and merge duplicate work into one
  durable handoff summary.
- Add richer productivity signals without treating heartbeat activity alone as
  progress.

### Campaign and policy depth

- Add campaign-scoped dispatch limits and fuller campaign noise projections.
- Compile technique preferences into visible frontier policy while preserving
  deterministic scope and approval gates.
- Keep board drag/drop, if added, as an adapter over existing directives rather
  than a new lifecycle path.

### Deterministic capability loops

- Extend scripted execution beyond simple credential tests where a repeatable
  runner is safer and more observable than free-form model orchestration.
- Continue archetype evaluation against graph-grade artifacts, not prose-only
  completion.
- Keep manual/paid real-model evaluation separate from deterministic CI.

### Provenance and deliverables

- Continue converging node-centric Evidence and run-centric Analysis into one
  cross-linked provenance story.
- Add natural-language retrospective/report drafting over confirmed graph and
  evidence records without bypassing client-safe redaction.

## Acceptance gates

Multi-agent changes must preserve command idempotency, exact task attribution,
terminal lifecycle monotonicity, durable ownership, and restart truthfulness.
They run the standing source, stdio/HTTP, restart/crash, browser, generated-doc,
and strict-documentation gates appropriate to the change.
