# Overwatch — Message Spine (canonical source for the decks)

> **Purpose of this file.** This is the single source of truth the four presentation
> outlines draw from. Facts here are verified against the codebase (counts, defaults,
> behaviors). If a deck and this file disagree, this file wins. Keep capability claims
> honest: shipped is shipped, roadmap is roadmap (see the maturity table at the end).

Audience-tailored decks built on this spine:
- `01-leadership.md` — strategic, outcomes, soft adopt/pilot ask (no funding ask).
- `02-awareness.md` — org-wide, plain-language "what is this thing".
- `03-showcase.md` — live/recorded demo script.
- `04-technical.md` — engineer/operator deep-dive.

---

## One-liner

**Overwatch is an offensive-security engagement orchestrator: a persistent server that holds the entire engagement in a knowledge graph and drives a fleet of AI agents from one operator cockpit — with every action scoped, OPSEC-checked, approval-gated, and audited.**

## Elevator pitch (30 seconds)

Today an AI-assisted pentest lives inside a chat window: the model's context *is* the
engagement state. That doesn't survive compaction, can't be watched, and can't be
proven after the fact. Overwatch inverts that — it moves state **out of the prompt** into
a durable graph engine. The model becomes a driver that reads the graph, scores what to
do next, and dispatches parallel sub-agents; the human watches and steers from a live
dashboard; and every target-facing action routes through one validated lifecycle
(scope → OPSEC → approval → execute → capture evidence → log). One graph, two surfaces, a
fleet of agents, audited end-to-end.

## The problem (what's painful without it)

- **State lives in the context window.** Compaction, a restart, or a sub-agent handoff
  loses the engagement. The operator re-briefs the model constantly.
- **No shared picture.** Parallel work re-tests the same hosts; nobody has a unified view
  of progress, conflicts, or what's been tried.
- **OPSEC & scope are vigilance, not enforcement.** Drift out of scope or a noisy choice
  depends on the operator remembering — not the system refusing.
- **"Why did we do that?" is guesswork.** A transcript isn't a causal record; retros are
  archaeology.
- **Credentials float free.** A captured hash loses its provenance and coverage; people
  re-test what's already tested.

## The five pillars

1. **One graph, not a prompt.** All engagement state — hosts, services, credentials,
   sessions, findings, agent tasks — lives in a persistent property graph that survives
   compaction and restarts. The model reconstructs everything with one `get_state()`.
2. **Deterministic guardrails + LLM reasoning.** A deterministic layer enforces the hard
   constraints (scope, dedup, OPSEC ceiling, dead hosts) and *filters* the impossible;
   the model does the offensive thinking (attack chains, sequencing, risk/reward). The
   guardrail is a guardrail, not a brain.
3. **A fleet, not a chatbot.** Typed sub-agents (archetypes) run in parallel — recon,
   web, credential, post-exploit, CVE research, pathfinder, cloud — each with a real
   tool-surface boundary, a frontier **lease** (no two agents claim the same work), a
   heartbeat **watchdog**, and **dispatch caps**.
4. **Operator in control.** One cockpit: a natural-language command bar, a single
   "Needs you" queue (approvals + agent questions + stuck agents), a fleet roster, a live
   activity stream, a campaign board, and an interactive graph. Approve/deny, answer,
   steer, deploy — from one screen.
5. **Audited end-to-end.** Deterministic action IDs + a write-ahead mutation journal make
   engagements **replayable**; a tamper-evident **hash chain** and **content-addressed
   evidence** (sha256) make them **provable**; `explain_action` and the timeline answer
   "why did we do X?" and "what was true at time T?".

## Proof points (verified counts & defaults)

- **74** MCP tools · **63** built-in inference rules · **50** output parsers · **34**
  RAG-searchable offensive skills · **23** node types · **73** edge types · **13** agent
  archetypes · **6** frontier item types.
- **One** `GraphEngine` process; **two** surfaces (terminal/MCP + dashboard HTTP/WS);
  headless sub-agents are real `claude -p` processes connecting **back** to the daemon's
  `/mcp`.
- Frontier **leases** default 600s TTL; heartbeat **watchdog** TTL 120s (300s cold-start
  grace for headless spawn); **dispatch cap** default 3 concurrent headless agents;
  per-task wall-clock timeout 30 min.
- **Approval gate** auto-fires on timeout (default `approval_timeout_ms` = 300s), tagged
  `unattended_execute` — loud, never silent; a reaped agent's pending approval is
  **aborted**, never executed.
- Reports default to evidence-rich (operator-internal); `client_safe: true` strips
  secrets, raw output, command-arg secrets, inline creds, and operator paths for client
  deliverables.

## The differentiators (vs ad-hoc scripts or a human + notebook)

- **Graph-grounded next-step**, not "what have we tried?" recall — `next_task()` returns a
  deterministically filtered, LLM-scored menu.
- **Inference auto-surfaces attack chains** — a new `smb_signing:false` host
  automatically spawns `RELAY_TARGET` edges to every compromised host; 63 rules across
  AD, ADCS (ESC1–13), Linux, web, MSSQL, and cloud.
- **OPSEC is enforced at validation time**, not hoped for — noise budget, blacklist,
  time windows, phase-aware tightening.
- **Replayable + provable** by construction — deterministic IDs, WAL journal, hash chain,
  content-addressed evidence; reproducible client/regulator-grade audit trail.
- **Parallel without conflicts** — leases + a campaign planner coordinate a fleet on one
  graph.

## Demo catalog (the moments that land)

| # | Moment | The "wow" |
|---|--------|-----------|
| 1 | Fleet board, live | Deploy several agents; swimlanes move Running → Needs You → Completed as the graph pulses with new findings. |
| 2 | NL command bar | "what changed in the last 15 minutes?" / "scan 10.50.0.0/16" / "pause the apache agent" — recognized fast-path, or a planner sub-agent proposes a confirmable plan. |
| 3 | Stuck-agent detection | A heartbeating-but-idle agent (idle > 8 min, not blocked) surfaces in "Needs you" with View → Pause/Stop; re-dispatch a fresh agent at the freed lease. |
| 4 | Graph focus + shortest path | Double-click a host for its 2-hop neighborhood; shift-click two nodes to highlight the path compromised-host → DC → objective. |
| 5 | Credential expansion | `expand_aws_credential` returns a numbered recon plan; watch S3/Lambda/IAM surface on the graph through the approval gate. |
| 6 | Evidence chain | Click a credential node: dumped-from → cracked-from → tested-against, each link jumping to the evidence/action that produced it. |
| 7 | Re-parse | Re-parse a stored nmap blob with a different parser; preview the new nodes/edges, then promote (merges, never duplicates). |
| 8 | OPSEC budget reject | In a quiet phase, a loud spray is rejected at validation: "exceeds phase noise ceiling"; override is explicit and logged. |
| 9 | Explain a decision | `explain_action` walks frontier item → reasoning → alternatives → validation → approval → outcome for any action_id. |

## Who's in the picture

- **Operator (human):** runs the engagement, makes risk calls, answers escalations,
  steers the fleet from the cockpit.
- **Primary model (Claude):** the main loop — scores the frontier, executes, dispatches
  sub-agents, synthesizes; holds no state (reconstructs via `get_state`).
- **Sub-agents (typed):** parallel scoped workers landing findings on the shared graph.
- **Analyst / watcher:** monitors the dashboard, re-parses evidence, deploys follow-ups.

## Honest maturity table (use this verbatim for maturity slides)

**Shipped & working today**
- Graph engine, frontier (6 item types), 63 inference rules, scope/OPSEC/approval
  validation, deterministic action IDs, WAL mutation journal, hash chain + signed
  checkpoints, content-addressed evidence.
- Multi-agent headless runtime: `claude -p` sub-agents over `/mcp`, role-scoped
  `--allowedTools`, leases, heartbeat watchdog, dispatch caps.
- Operator cockpit: NL command bar, "Needs you" attention queue (approvals + questions +
  **stuck detection**, question **clustering**), fleet roster, activity stream, campaign
  **board**, sigma.js graph explorer, attack paths, sessions (xterm), credentials,
  identity, **analysis/re-parse**, evidence, report generation (+ `client_safe`).
- 13 agent archetypes; credential lifecycle + coverage matrix + cloud playbooks
  (AWS/GitHub/Entra/OIDC/refresh-token); operator-memory → compiled policies (approval
  rules + dispatch caps, editable in Settings).

**In progress / next**
- Graph-delta "plan estimator" (preview a plan's expected graph impact before running).
- Agent handoff / split / merge; campaign lane-drag transitions; a fuller noise-budget
  dashboard.

**Roadmap (clearly not yet)**
- Process-isolated sub-agents (beyond the current in-process recon-scoping role).
- Parser sandboxing (parsers currently run in-process).
- Source-trust labels on findings (tool-observed vs target-asserted vs inferred).
- Ed25519 checkpoint **signing** (the chain exists; key mgmt/rotation/verify do not).
- Full phase-aware policy enforcement; a non-MCP internal CLI driver for offline use.

## Quote-worthy lines (lifted from the docs)

- "There is one engine, and everything else is a driver routing into it."
- "The deterministic layer is a guardrail, not a brain. It filters the obviously
  impossible. The LLM does the offensive thinking."
- "Overwatch survives compaction because the graph lives outside the context window."
- "Same inputs → same IDs … a byte-identical state hash on replay."
- "The cockpit never invents a new mutation path — every operator action routes through an
  existing validated engine method."
