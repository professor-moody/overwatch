# Multi-Agent Operator Roadmap

This is the forward roadmap for the **multi-agent + natural-language** operating model. It builds on the console-first cockpit shipped in the Phase 4 work (see [Operator Cockpit](operator-cockpit.md) and [Dashboard](dashboard.md)). The general project roadmap lives in [Roadmap](roadmap.md); this page is the focused plan for turning Overwatch from "many agents running" into **one operator commanding a coordinated team**.

## Thesis

The operator has three jobs. Every feature here serves one of them:

- **Monitor** — what is the fleet doing, and which agents are productive vs. stuck vs. blocked?
- **Decide** — what needs me right now (approvals, agent questions, stuck agents, failures), and do I have enough proof?
- **Command** — assign intent, steer agents, and add scope — always through a visible, confirmable plan.

A guiding constraint runs through all of it (the cockpit [safety invariant](operator-cockpit.md#operatorop)): **natural language never invents a new mutation path.** Every command resolves to a visible plan that runs through the existing validated engine methods (`executeOps`). NL makes the engine easier to command; it doesn't bypass it.

## What we already have

Much of "command a team" is **surfacing primitives that already exist**, not building new ones:

| Capability | Already in the engine |
|---|---|
| "Why is this agent running?" | `explain_action` + `get_decision_log` reconstruct objective → frontier → thought → action → outcome |
| Agent state for mission cards | status, skill, findings, `current_action`, owned sessions, campaign, frontier item already flow to the dashboard |
| Campaign state | `Campaign` status + progress + abort conditions; frontier-linkage tracks open/pursued/rejected/dropped per item |
| Per-finding proof | the report generator already assembles evidence chains, proof cards, and CWE/OWASP/ATT&CK mappings |
| Directives | a 7-kind directive substrate (`pause`/`resume`/`stop`/`narrow_scope`/`skip_types`/`prioritize`/`instruct`) delivered on heartbeat |
| Retrospective | inference-gap, skill-gap, and context-gap analysis plus training traces |
| Scope preview | `previewScopeChange` is a read-only dry-run returning nodes entering/leaving scope (the Add-Targets precedent) |

The net-new engine work has been landing phase by phase. **Shipped:** the **data-driven role system** (agent archetypes), **question clustering**, the **operator-memory → compiled-policy** substrate (MVP — approval rules + per-subnet/target dispatch caps + a Settings editor), and **NL graph queries** (read-only changes_since / timeline / list_nodes / finding_readiness / retrospective / find_paths, plus a structured Attack-Paths node-picker), and **stuck-agent detection**. **Still ahead:** a **graph-delta plan estimator**. Those are tracked in the phases below.

## Runtime: MCP-optional drivers

How these agents reach tools is a **driver**, not a fixed dependency. The headless
runtime described in [Operator Cockpit](operator-cockpit.md#roles) speaks MCP today,
which is correct for the external lab. For internal environments where MCP is
unavailable, the same agents run unchanged through a **no-MCP driver** (headless
Claude + an `overwatch` CLI / local HTTP), routing into the same executor and
lifecycle. The phases below are driver-agnostic. See
[Deployment Architecture](deployment-architecture.md) for the decision and the
implementation sequence.

## Phases

### Phase 1 — Mission Control console *(✅ shipped)*

Reorganize the console body around Monitor / Decide / Command — mostly surfacing existing data, no new engine state.

- **Mission Cards** — each agent's card shows role, campaign, assigned frontier item, current action, heartbeat freshness, owned sessions, pending approval, and blocker — so stale, blocked, and productive agents are obvious at a glance.
- **One Attention Queue** — a single prioritized "what needs me" surface merging pending approvals, agent questions, and failures (stuck agents join in Phase 2), with one item expanded at a time. This consolidates today's separate approvals lane and questions inbox.
- **One contextual command box** — a single command input with a **Fleet / Campaign / Agent** scope pill, replacing the separate global command bar and per-agent "Tell" box.
- **Threaded, compact activity** — group a directive → acknowledged → action → completed lifecycle into one collapsible thread; raw details hidden until expanded; a segmented filter (All / Agent / Actions / Findings / Errors); loud color reserved for findings, approvals, questions, and failures.
- **Single-scroll density — ✅ shipped** — the cockpit was getting cramped: clipped Fleet-overview metric cards, a tight "Needs you" queue, nested fixed-height scroll regions fighting each other. The panel is now one page scroll: a sticky act-surface band (command bar + "Needs you" queue) over a flowing master-detail, the Activity stream keeping its own bounded live-tail (the one justified inner scroll). Metric grid widened to a 4-up row so Running/Queued/Completed/Failed never wrap-clip. Reusable `dense` `PanelSection`/`MetricTile` variants.

### Phase 2 — Smarter Decide

Make the cards and queue intelligent.

- **Stuck / blocked detection — ✅ shipped** — the watchdog only knows heartbeat-TTL, so a heartbeating-but-idle agent would otherwise run forever. **Blocked** (waiting on an approval/answer) was already derived (mission-card tone + the approval/question items in "Needs you"). **Stuck** is the net-new: a pure dashboard-side projection (`isStuck` in `agent-mission.ts`) flags a still-`running` agent that's idle past `STUCK_IDLE_MS` (8 min, above the heartbeat TTL / visual-quiet thresholds) and **not** blocked, using the `current_action_at` / `assigned_at` already on the agent DTO — no new engine state. It surfaces as a `stuck` "Needs you" item (priority below approvals/questions, above stale failures), a `stuck` mission-card tone, and the board's Blocked lane. *(Richer per-task productivity counters remain a later enrichment; the last-action timestamp is sufficient to flag stuck.)*
- **Proof Packets** — a per-finding readiness rollup over the existing evidence chains, classifier, and trust signals: summary, supporting action IDs, evidence, affected nodes, validation status, attack-path impact, and a readiness label (draft / needs-validation / client-ready).
- **Directive Templates** — reusable one-click operator directives ("go quiet", "credential focus only", "no target-facing", "wrap up with proof packet", "avoid this subnet", "prioritize identity edges", "stop after one confirmed finding") compiling to the existing directive ops.

### Phase 3 — Command by intent

Deepen the natural-language layer.

- **Expected-graph-delta plan preview** — generalize the scope-preview dry-run into a plan preview: before confirming, show the *state transition* (likely new/removed nodes and edges, objective-distance change, OPSEC/noise estimate, approval risk) — and offer variants (quiet / faster / credential-only) instead of a single confirm button.
- **Ambiguity handling** — when a command is ambiguous or affects more than a threshold, the interpreter returns a tight clarifying question ("48 hosts — campaign or sample?").
- **Natural-language graph queries (read-only) — ✅ shipped** — "what changed in the last 15 minutes?", "which findings lack evidence?", "timeline of 10.0.0.5", "run a retrospective" — a read-only NL→query grammar in `query-interpreter.ts` (sibling to the mutation `command-interpreter.ts`), running ahead of the mutation grammar behind a `MUTATION_LEAD` guard so it's purely additive, resolving to the existing `get_state({since})` / `get_timeline` / `query_graph` / `get_finding_readiness` / `run_retrospective` reads. `find_paths` is included but deliberately **narrow** (objective fan-out, explicit obj-id, symbolic DC, single concrete IP/id/FQDN endpoints) — free-form two-endpoint NL parsing proved a wrong-node minefield. The robust UX for arbitrary endpoints is the **structured Attack-Paths "Custom path" picker** (`GET /api/find-paths` → engine-ranked, `NodePicker` from/to + optimize), with a graph context-menu "paths from/to here" deep-link.

### Phase 4 — Coordinated team

The heaviest backend, and the biggest "team" leap.

- **Specialized roles + smart/manual deploy — ✅ shipped** (pulled forward). Roles are now data-driven **agent archetypes** (`agent-archetypes.ts`): recon_scanner, web_tester, credential_operator, post_exploit, cve_researcher, pathfinder, report_scribe + the legacy default/research/planner — each a real tool-surface boundary, backend, default skill/objective, and scope strategy. Dispatch honors the type; `recommendArchetype` auto-picks one for a target and the operator can override. **Ad-hoc real-time deploy** (`POST /api/agents/quick-deploy` + the console **Deploy** button): paste an IP/CIDR/domain → auto-scope + dispatch in one step. See [Agent types & deploy](operator-cockpit.md#agent-types). The full archetype set — including `evidence_auditor`/`opsec_sentinel`/`session_shepherd`/`cloud_cartographer` — now ships and is sharpened (see [Agent capability](#agent-capability-usefulness) below); the remaining Phase-4 item below is **agent handoff / split / merge**.
- **Campaign swimlanes — ✅ shipped (read-only)** — a read-only **board view** in the Campaigns panel (Campaigns ⇄ Board toggle): each campaign is a swimlane, its agents bucketed into status lanes (Planned / Running / Needs You / Blocked / Produced Finding / Completed / Failed). Pure projection of the mission cards (`campaign-board.ts`), no new engine state. **Lane-drag transitions are explicitly deferred** (nice-to-have): dragging an agent card between lanes to issue the matching directive is a convenience over the existing command bar, not a capability gap, so it waits behind the heavier threads.
- **Question clustering — ✅ shipped** — identical open questions (same normalized text + option set) cluster into one card in the "Needs you" queue; answering it **fans out** to every asking agent in one call (`AgentQueryStore.answerMany` + the `/api/agent-queries/answer-batch` route).
- **Agent handoff / split / merge** — hand work to a specialist (recon → credential_operator on a token find), split a broad item into child tasks, or merge duplicate agents into a summary.
- **Per-campaign OPSEC meter — ✅ shipped** — each campaign's detail view shows a **Campaign Noise** gauge: that campaign's noise contribution vs. the global budget, threaded through the action lifecycle (`opsec-tracker.ts` per-campaign aggregation, reusing the shared `OpsecGauge`). *(The fuller noise-budget dashboard — actions-by-noise-level, denied/approved, quiet-mode enforcement — is still ahead.)*

### Phase 5 — Continuity & deliverables

- **Operator memory → compiled policies — ✅ shipped (MVP)** — operator preferences ("approval-all on production", "at most one target-facing agent per subnet") are now an *explicit* `OperatorPolicy` on the engagement config that the approval gate and dispatcher actually consult — durable, auditable, and editable in Settings, not hidden prompt text that evaporates on compaction. The MVP:
  - **Approval rules** match on `host_class` / `network` (CIDR) / `technique` and fold into the effective approval mode by **max-strictness** — a rule can only *tighten* the gate (`auto-approve < approve-critical < approve-all`), never weaken the engagement/phase mode, preserving the existing safety invariant. Wired through `getEffectiveApprovalConfig` → `needsApproval` with an optional action context (legacy callers unchanged).
  - **Per-subnet / per-target dispatch caps** limit concurrent *target-facing* agents per `/24` or host, enforced at the single `registerAgent()` chokepoint all dispatch paths funnel through. On a cap hit the dispatch **defers** (surfaced as HTTP 429 / skip reasons), never silently dropping; read-only and no-IP archetypes are exempt; refusal events use `withClock` for replay determinism.
  - **Settings editor** to view/edit rules + caps, persisted through the existing `PATCH /api/config` behind a strict Zod guard.

  *Deferred to a later phase:* technique-preference frontier boosting, planner-proposed policy edits, and per-campaign (vs engagement-global) cap scoping.
- **NL retrospective + report drafting** — a natural-language narrative over the existing structured retrospective ("what worked, what wasted time, what the next operator should do"), and a drafting surface over the report generator ("draft this finding", "make this client-safe", "turn these into an executive narrative").

## Agent capability & usefulness

The archetypes are real tool-surface boundaries, but a useful agent needs more
than the right `--allowedTools`: it needs a capability loop that actually
produces graph-grade findings, end to end. This track makes each agent type
genuinely *capable*, not just *scoped*:

- **End-to-end capability loops** — for each archetype, a validated
  objective → tool selection → output → `parse_output`/`report_finding` loop
  that lands real nodes/edges/findings (not prose). Today only `credential_test`
  has a deterministic scripted runner; the reasoning archetypes lean entirely on
  the headless model.
- **Skill + prompt quality — ✅ shipped** — the six thin/mis-bound archetypes
  (`pathfinder`, `report_scribe`, `cloud_cartographer`, `opsec_sentinel`,
  `session_shepherd`, `evidence_auditor`) each got a real default skill
  (`skills/*.md`: methodology + decision tree + escalation thresholds), a
  correctly bound `defaultSkill` (replacing mis-bound `pivoting` /
  `aws-exploitation`), and a prescriptive mission (tool sequence → doneness tied
  to graph artifacts → when to `ask_operator`). A test asserts every archetype's
  `defaultSkill` resolves to a real skill file.
- **Remaining archetypes — ✅ present & sharpened** — `evidence_auditor`,
  `opsec_sentinel`, `session_shepherd`, and `cloud_cartographer` (the Phase-4
  starter set) exist with real tool surfaces, eval coverage, and (as of the
  sharpening pass above) bound skills and prescriptive missions. The remaining
  capability work is **deterministic scripted runners** for the reasoning
  archetypes (only `credential_test` has one today).
- **Agent eval harness — ✅ shipped** — capability is now regression-tested, not
  assumed: `fake-claude.mjs` modes + the `runArchetype` fixture +
  `archetype-capability.integration.test.ts` assert each archetype produces the
  right graph output (recon/web/opsec/audit/cloud/shepherd/cve_researcher/
  pathfinder/credential_operator/post_exploit/report_scribe). Sharpening each
  archetype's mission/skill (above) is the remaining capability work.

## Provenance surfaces — consolidate Evidence and Analysis

The [**Analysis workspace**](operator-cockpit.md#analysis) — ✅ **shipped**:
assess a tool run's raw stdout/stderr (live while running, durable after),
re-parse it into the graph, and deploy a follow-up at what it found. It added a
**run-centric** lens (the raw output a tool produced). The **Evidence** tab is
**node-centric** (a node's
provenance chain). They are complementary but currently overlap awkwardly — the
Evidence tab also carries a redundant Attack Paths finder (already its own nav
item). The consolidation:

- **✅ Drop the redundant Attack Paths block from Evidence** (it's already its own nav item).
- **✅ Cross-link the two lenses**: an evidence chain's action ids now deep-link into the
  Analysis run that produced them (`navigateToAction`), and Analysis auto-selects a run from a `?item=` deep-link.
- Node-provenance is most useful *contextually* (NodeDetailDrawer, finding
  detail). End state (still ahead): one provenance story across contextual surfaces + Analysis,
  with Evidence merged in or demoted rather than a standalone search-only tab.

## Acceptance gates

Each phase ships as its own reviewed PR, merged in sequence, and passes the standing gates:

```bash
git diff --check
npx tsc --noEmit
npm run test:source
npm run build:dashboard-next
mkdocs build --strict
```

Backend-bearing phases also run the relevant integration config (`npm run test:integration:http` / `:stdio`); visible dashboard work runs a live `npm run demo:daemon` walkthrough.
