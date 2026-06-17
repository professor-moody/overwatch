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

The net-new engine work is concentrated in a few places: **productivity-based stuck detection**, a **data-driven role system**, a **graph-delta plan estimator**, **question clustering**, **NL graph queries**, and an **operator-memory → compiled-policy** substrate. Those land in the later phases below.

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

### Phase 1 — Mission Control console *(in progress)*

Reorganize the console body around Monitor / Decide / Command — mostly surfacing existing data, no new engine state.

- **Mission Cards** — each agent's card shows role, campaign, assigned frontier item, current action, heartbeat freshness, owned sessions, pending approval, and blocker — so stale, blocked, and productive agents are obvious at a glance.
- **One Attention Queue** — a single prioritized "what needs me" surface merging pending approvals, agent questions, and failures (stuck agents join in Phase 2), with one item expanded at a time. This consolidates today's separate approvals lane and questions inbox.
- **One contextual command box** — a single command input with a **Fleet / Campaign / Agent** scope pill, replacing the separate global command bar and per-agent "Tell" box.
- **Threaded, compact activity** — group a directive → acknowledged → action → completed lifecycle into one collapsible thread; raw details hidden until expanded; a segmented filter (All / Agent / Actions / Findings / Errors); loud color reserved for findings, approvals, questions, and failures.

### Phase 2 — Smarter Decide

Make the cards and queue intelligent.

- **Stuck / blocked detection** — the watchdog today only knows heartbeat-TTL, so a heartbeating-but-idle agent runs forever. Add per-task productivity counters (actions / findings / mutations since last, last-action time) and flag `stuck` (heartbeating, no progress) and `blocked` (waiting on an approval/answer).
- **Proof Packets** — a per-finding readiness rollup over the existing evidence chains, classifier, and trust signals: summary, supporting action IDs, evidence, affected nodes, validation status, attack-path impact, and a readiness label (draft / needs-validation / client-ready).
- **Directive Templates** — reusable one-click operator directives ("go quiet", "credential focus only", "no target-facing", "wrap up with proof packet", "avoid this subnet", "prioritize identity edges", "stop after one confirmed finding") compiling to the existing directive ops.

### Phase 3 — Command by intent

Deepen the natural-language layer.

- **Expected-graph-delta plan preview** — generalize the scope-preview dry-run into a plan preview: before confirming, show the *state transition* (likely new/removed nodes and edges, objective-distance change, OPSEC/noise estimate, approval risk) — and offer variants (quiet / faster / credential-only) instead of a single confirm button.
- **Ambiguity handling** — when a command is ambiguous or affects more than a threshold, the interpreter returns a tight clarifying question ("48 hosts — campaign or sample?").
- **Natural-language graph queries (read-only)** — "what changed in the last 15 minutes?", "which findings lack evidence?", "what's the riskiest unapproved action?" — translated to the existing structured query/path/timeline tools, never mutating.

### Phase 4 — Coordinated team

The heaviest backend, and the biggest "team" leap.

- **Specialized roles + smart/manual deploy — ✅ shipped** (pulled forward). Roles are now data-driven **agent archetypes** (`agent-archetypes.ts`): recon_scanner, web_tester, credential_operator, post_exploit, cve_researcher, pathfinder, report_scribe + the legacy default/research/planner — each a real tool-surface boundary, backend, default skill/objective, and scope strategy. Dispatch honors the type; `recommendArchetype` auto-picks one for a target and the operator can override. **Ad-hoc real-time deploy** (`POST /api/agents/quick-deploy` + the console **Deploy** button): paste an IP/CIDR/domain → auto-scope + dispatch in one step. See [Agent types & deploy](operator-cockpit.md#agent-types). *(Remaining Phase-4 items below are still ahead: evidence_auditor/opsec_sentinel/session_shepherd/cloud_cartographer archetypes, plus —)*
- **Campaign swimlanes** — a board view (Planned / Running / Needs-Approval / Blocked / Produced-Finding / Completed / Failed) derived from campaign status, frontier-linkage, agent status, and pending approvals.
- **Question clustering** — group related agent questions (by campaign / role / similarity) so the operator answers once and the decision fans out.
- **Agent handoff / split / merge** — hand work to a specialist (recon → credential_operator on a token find), split a broad item into child tasks, or merge duplicate agents into a summary.
- **Noise budgets** — a per-campaign live OPSEC meter (actions by noise level, target-facing count, denied/approved, quiet-mode enforcement) over the existing OPSEC tracker.

### Phase 5 — Continuity & deliverables

- **Operator memory → compiled policies** — operator preferences ("low-noise first", "approval-all on production", "expand GitHub before cloud", "at most one target-facing agent per subnet") compiled into *explicit* approval/scope/dispatch rules — not hidden prompt text.
- **NL retrospective + report drafting** — a natural-language narrative over the existing structured retrospective ("what worked, what wasted time, what the next operator should do"), and a drafting surface over the report generator ("draft this finding", "make this client-safe", "turn these into an executive narrative").

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
