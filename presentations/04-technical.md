---
deck: Overwatch — Technical Deep-Dive
audience: Security engineers / operators who will run, extend, or evaluate it
goal: How it actually works, how to operate it, how to extend it, and where the edges are.
length: ~18 slides, ~30 min + Q&A
tone: Precise, honest, code-anchored. Name the modules. Don't oversell maturity.
source_of_truth: ./00-message-spine.md
---

# Overwatch — Technical Deep-Dive

> Presenter: this room wants mechanism and honesty. Cite the real modules. The maturity
> slide near the end is load-bearing — say what isn't built yet.

---

## Slide 1 — Title + thesis

- **Overwatch:** invert "LLM-as-orchestrator" — the orchestrator is a persistent MCP
  server; the LLM is a driver that calls into it.
- **Speaker notes:** State the thesis up front; everything else follows from "state lives
  in the engine, not the prompt."
- **Suggested visual:** Engine-in-the-center diagram.

## Slide 2 — One engine, three drivers

- A single persistent `GraphEngine` process owns *all* state. Three drivers route into it:
  (1) operator + primary Claude over **MCP** (stdio or HTTP `/mcp`); (2) **headless
  sub-agents** (`claude -p`) over `/mcp`; (3) the **dashboard** over HTTP + WebSocket.
- One `EngineContext`, one state file, one activity log. Both surfaces are views of the
  same live state.
- **Speaker notes:** This is the runtime-model slide. The dashboard isn't a copy kept in
  sync — it's a second front door to the same engine.
- **Suggested visual:** The two-surfaces/one-engine + dispatch-backends diagram.

## Slide 3 — The knowledge graph

- Directed property graph (graphology): **23 node types** (host, service, credential,
  user, domain, cloud identity/resource/policy, certificate/CA/template, webapp, …),
  **73 edge types** (ADMIN_TO, HAS_SESSION, VALID_ON, RELAY_TARGET, ESC*, …).
- Confidence (0.0–1.0) on every node/edge. Persisted on every change. Survives compaction.
- **Speaker notes:** Confidence drives prioritization (low-confidence edges are the most
  valuable to test). Note community detection (Louvain) for graph structure.
- **Suggested visual:** Node/edge schema excerpt + a confidence scale.

## Slide 4 — The frontier (what-to-do-next)

- 6 deterministic item types: incomplete nodes, untested edges, inferred edges, network
  discovery, network pivots, credential tests.
- The deterministic layer **filters** out-of-scope / duplicate / over-noise / dead-host
  items; the **LLM scores** what's left. The frontier is a menu, not a decree.
- Items carry graph metrics (hops-to-objective, fan-out, degree) and are **leased**.
- **Speaker notes:** `next_task()` is the loop's heartbeat. Emphasize: deterministic
  filter + LLM ranking — "guardrail, not a brain."
- **Suggested visual:** Frontier pipeline: generate → filter → score.

## Slide 5 — Inference rules

- **63 built-in declarative rules** across AD, ADCS (ESC1–ESC13), Linux privesc, web,
  MSSQL, cloud. Fire on node ingest; **edge-triggered** rules re-evaluate endpoints when
  edges arrive. Produce hypothesis edges (0.3–0.7 confidence) → new frontier items.
- Example: `smb_signing:false` host → `RELAY_TARGET` edges to all compromised hosts.
- Custom rules at runtime via `suggest_inference_rule`. Source of truth:
  `src/services/builtin-inference-rules.ts`.
- **Speaker notes:** This is the "auto-surface attack chains" engine. New findings
  reactively re-plan. Mention rules are data, not hardcoded branches.
- **Suggested visual:** Rule firing → new edge → new frontier item.

## Slide 6 — The action lifecycle

- Every target-facing action: `validate_action` → log `action_started` → execute
  (`runInstrumentedProcess`) → `parse_output` / `report_finding` → log
  `action_completed`/`failed`. Uniform regardless of which surface triggered it.
- Scope, OPSEC, approval, evidence capture, audit apply **once**, in the engine.
- **Speaker notes:** The single-executor invariant — the dashboard never invents a new
  mutation path. Everything goes through validated engine methods.
- **Suggested visual:** Lifecycle pipeline with the gates as checkpoints.

## Slide 7 — Agent archetypes

- **13 data-driven archetypes** (`agent-archetypes.ts`): recon_scanner, web_tester,
  credential_operator, post_exploit, cve_researcher, pathfinder, report_scribe,
  cloud_cartographer, opsec_sentinel, session_shepherd, evidence_auditor + default/
  research/planner.
- Each = a tool-surface boundary (real `--allowedTools` allowlist) + backend + default
  skill + scope strategy + suitability. `recommendArchetype` auto-picks; operator can
  override.
- **Speaker notes:** The allowlist is a hard boundary, not a suggestion — recon can't pop
  shells; cve_researcher has web tools but no target execution.
- **Suggested visual:** Archetype table (type → backend → tool surface).

## Slide 8 — Dispatch, backends, and how a sub-agent loops back

- Backends by **frontier-item type**: `scripted` (in-process, deterministic — e.g.
  credential tests), `headless_mcp` (real `claude -p` over `/mcp`), `manual`.
- Headless sub-agents connect **back** to the daemon's own `/mcp` and drive themselves
  through the real tools; findings land on the shared graph.
- **Speaker notes:** Walk the loop: register_agent → resolve backend → spawn `claude -p`
  → it's an MCP client of the same daemon. `dispatch_subnet_agents` / `dispatch_campaign_agents`
  parallelize.
- **Suggested visual:** The dispatch-backends diagram.

## Slide 9 — Coordination: leases, heartbeats, caps

- **Frontier leases** (default 600s TTL): a second agent gets `lease_conflict`, not a race.
- **Heartbeat watchdog**: reaps silent tasks past TTL (120s; 300s cold-start grace for
  headless spawn+bootstrap); per-task wall-clock timeout 30 min.
- **Dispatch caps**: default 3 concurrent headless agents; per-subnet/per-target operator
  policy caps.
- **Speaker notes:** This is what makes "a fleet" safe and bounded. Note the lease release
  on terminal/reap so work becomes retryable.
- **Suggested visual:** Lease/heartbeat/cap timeline.

## Slide 10 — Safety: scope + OPSEC + approval

- **Scope:** validated on every action; implicit target extraction for known
  target-facing binaries (e.g. `nmap`, `nxc`); out-of-scope **fails closed**.
- **OPSEC:** noise budget ceiling, technique blacklist, time windows; phase-aware overrides
  can *tighten* (never weaken) mid-engagement; the whole pipeline can be disabled
  (`opsec.enabled:false`).
- **Approval:** blocks in-engine; auto-fires on timeout (default 300s) tagged
  `unattended_execute`; a reaped agent's pending approval is **aborted**, never run.
- **Speaker notes:** Enforcement at validation time, not vigilance. The unattended-execute
  tag is the "loud, never silent" guarantee.
- **Suggested visual:** Three gates with their failure modes.

## Slide 11 — Audit & reproducibility

- **Deterministic IDs:** with an `engagement_nonce`, action IDs are
  `act_<16hex> = sha256(nonce|agent|timestamp|command|sequence)` → byte-identical replay.
- **Mutation journal (WAL):** crash-safe recovery, replayed on load.
- **Hash chain** over agent/system events + signed checkpoints (every 500 events / 30 min)
  so verifiers don't re-walk genesis.
- **Content-addressed evidence:** `content_hash = sha256(content)`; identical outputs
  dedupe; streaming sinks finalize the hash on close; manifests record capture errors
  (never silent truncation).
- **Speaker notes:** Replayable (determinism + WAL) vs provable (hash chain + evidence) —
  two different guarantees. Checkpoint *signing* (Ed25519) is roadmap; the chain is real.
- **Suggested visual:** Hash-chain + replay motif.

## Slide 12 — Introspection: why / when

- `explain_action(action_id)` — frontier item → `log_thought` reasoning → alternatives →
  validation → approval → outcome.
- `get_decision_log` — per-decision timeline. `get_timeline` — "what was true at time T?"
  reconstructed from the activity log + graph.
- **Speaker notes:** These power retros and human-facing audit. They're derivations over
  the same activity log, not extra bookkeeping.
- **Suggested visual:** A single decision expanded into its chain.

## Slide 13 — The operator cockpit

- React/Vite SPA (Zustand, sigma.js) over HTTP + WS (DeltaAccumulator broadcasts).
- Console: NL command bar; **"Needs you"** queue (approvals + questions + **stuck**, with
  question **clustering**); fleet roster; activity stream (newest-first). Plus Frontier,
  Approvals, Campaign **Board**, Graph Explorer, Attack Paths, Sessions (xterm),
  Credentials, Identity, **Analysis** (re-parse), Evidence, Findings/Reports.
- **Speaker notes:** The cockpit calls only existing validated engine methods — no
  bypass. Re-parse previews then promotes (merge, not duplicate).
- **Suggested visual:** Annotated cockpit screenshot.

## Slide 14 — Sessions & credentials

- **Sessions:** persistent SSH / local PTY / TCP socket (reverse-shell catch, listeners);
  `send_to_session` is instrumented (scope + evidence + action lifecycle); 128KB ring
  buffers, ownership + TTY-quality tracking; survive compaction as `HAS_SESSION` edges.
- **Credentials:** lifecycle (active/stale/expired/rotated) with auto-degrade; coverage
  matrix → `credential_test` items; cloud playbooks (`expand_aws/github/entra/oidc`,
  `exchange_refresh_token`) emit sequenced plans with per-step parsers.
- **Speaker notes:** Credentials are first-class objects, not strings — provenance,
  reachability, coverage. Playbooks turn a capture into a queued recon plan.
- **Suggested visual:** Credential node inspector + a playbook plan.

## Slide 15 — How to run it

- `npm run setup`; pick an engagement template (CTF, internal-pentest, …). Stdio mode for
  a single terminal; **daemon mode** (HTTP `/mcp` + dashboard on :8384) to enable headless
  agents + the cockpit.
- `.mcp.json` wires the MCP client; `.claude/settings.json` wires the hooks (block raw
  target-facing Bash, re-anchor to Overwatch, nudge discovery into the graph).
- **Speaker notes:** The hooks are how the workflow is enforced at the Claude Code layer,
  complementing the engine's gates. Daemon mode is what unlocks the fleet + dashboard.
- **Suggested visual:** Two run-modes (stdio vs daemon) side by side.

## Slide 16 — Extending it

- **Inference rules** — `suggest_inference_rule` at runtime; built-ins in
  `builtin-inference-rules.ts`.
- **Skills** — 34-skill RAG methodology library (`get_skill`).
- **Archetypes** — data-driven; add a type = tool surface + backend + skill + scope.
- **Parsers** — 50 output parsers (`parse_output`); re-parse + promote workflow.
- **Drivers** — engine is transport-agnostic; MCP is one driver (a non-MCP CLI driver is
  on the roadmap).
- **Speaker notes:** Most extension points are data/config, not core surgery — that's
  deliberate (the altitude is in the engine).
- **Suggested visual:** The five extension points as plug-in slots.

## Slide 17 — Honest limitations / roadmap

- **In progress:** graph-delta plan estimator; agent handoff/split/merge; fuller
  noise-budget dashboard.
- **Roadmap (not yet):** process-isolated sub-agents (most roles run in-process today);
  parser **sandboxing** (parsers run in-process, can read fs); finding **source-trust
  labels** (tool-observed vs target-asserted vs inferred); **Ed25519 checkpoint signing**
  (chain exists, key mgmt doesn't); full phase-aware policy enforcement; non-MCP driver.
- **Speaker notes:** Say these plainly. The credibility of slides 10–11 depends on not
  pretending these are done. (Mirrors the spine's maturity table.)
- **Suggested visual:** Shipped / In-progress / Roadmap three-column table.

## Slide 18 — Close

- *One engine, two surfaces, a typed fleet, every action gated, every step provable.*
- Repo / docs (mkdocs site) / where it's running. Q&A.
- **Speaker notes:** Point engineers at `docs/` (runtime-model, architecture, tools
  reference) and offer a pairing session to deploy it.
- **Suggested visual:** One-liner + doc map.

---

### Deep-dive Q&A primer

- *"What stops a sub-agent going rogue?"* — archetype `--allowedTools` allowlist + the
  same scope/OPSEC/approval gates as the primary; it's an MCP client of the same engine,
  not a free shell.
- *"How is replay byte-identical?"* — deterministic IDs from the nonce + caller-provided
  timestamps + the WAL journal; no `Date.now()`/random in the state path.
- *"What if the daemon dies mid-engagement?"* — state file + WAL replay on load; running
  agents reconciled to interrupted; pending approvals reconciled to aborted; leases
  released.
- *"Parsers reading arbitrary files — risk?"* — yes, acknowledged; in-process today,
  sandboxing is on the roadmap. Don't oversell.
