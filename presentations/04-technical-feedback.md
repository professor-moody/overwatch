# Feedback — "Technical Deep-Dive" deck (`04-technical.md`)

Review for a **technical (engineer) audience**. Every quantitative claim below was
re-verified against current `main` (counted from `src/types.ts`, `agent-archetypes.ts`,
`skills/`, the parser registry, and `src/tools/*.ts`).

> **Through-line: the deck *undersells* the tool.** Almost every number is *lower* than
> reality, and several whole capability areas shipped recently are absent. For an audience
> that will `grep` the repo, low-but-true numbers read as "they don't track their own
> system" — the single biggest credibility risk in an otherwise strong deck. Nothing is
> overstated except two "future work" items that are actually mostly built.

---

## 1. TL;DR

- **Fix the numbers first (20 min).** 23→**30** node types, 73→**90** edges, 34→**43** skills,
  50→**114** parsers, 6→**11** frontier types, 13→**15** archetypes, inference 0.3–0.7→**0.3–1.0**.
  Add the **78-tool** MCP count the deck never gives.
- **Add 3–4 capability slides** for things already in the repo: the **prompt/orchestration
  behavior-eval harness** (the standout omission), OSINT/external-recon, campaigns, the
  operator CLI, retrospective analysis, enterprise-identity depth.
- **Re-label two roadmap items** that are mostly built (phase-aware policy, process
  isolation) so the *present* looks as strong as it is.
- The content already exists — the deck just hasn't caught up to ~6 months of shipping.

---

## 2. Factual corrections (do these first)

Ordered by how wrong + how visible (a greppable count on an early slide is worst).

| # | Slide (title) | Deck says | Actual | Evidence |
|---|---|---|---|---|
| 1 | Knowledge graph | **23** node types | **30** | `src/types.ts` `NODE_TYPES` length = 30 |
| 2 | Knowledge graph | **73** edge types | **90** | `src/types.ts` `EDGE_TYPES` length = 90 (unique) |
| 3 | Extensibility | **50** output parsers | **114 aliases (56 fns)** | `src/services/parsers/` PARSERS registry |
| 4 | Extensibility | **34**-skill RAG | **43** | `ls skills/*.md` = 43 (boot logs "Loaded 43 skills") |
| 5 | Frontier | **6** item types | **11 declared / 9 generated** | FrontierItem union = 11; `idp_enumeration` + `cross_tier_pivot` declared-not-generated |
| 6 | Agent archetypes | **13** (lists 14) | **15** | `agent-archetypes.ts` `AgentArchetypeId` = 15 — adds `osint_recon`; the "13" also disagrees with the 14 it enumerates |
| 7 | Inference rules | hypothesis edges **0.3–0.7** | **0.3–1.0** (weighted 0.6–0.8) | built-in rule confidence distribution incl. 0.75–1.0 |
| 8 | Extensibility | *(no tool count)* | **78 MCP tools** | `grep -roh "server.registerTool" src/tools/*.ts` = 78 |

**Confirmed correct — keep as-is (don't over-edit):** 63 inference rules · 0–1.0 confidence ·
graphology directed multigraph · Louvain · survives-compaction · 600s lease TTL · 120s
heartbeat / 300s cold-start / 30-min task timeout · 3 concurrent headless · `act_<16hex>` ID
formula · 500-event / 30-min checkpoint cadence · 128KB session ring buffers.

> **Durability:** the build/boot already logs the skill count. Emit node/edge/parser/tool
> counts the same way and quote "30+/90+/110+/78" so the deck can't drift stale again.

---

## 3. Undersold & missing capabilities (slides to add / expand)

All real, in the repo, and relevant to engineers.

**3a. Prompt + orchestration behavior-eval harness — LEAD WITH THIS (new slide).**
`src/cli/prompt-eval.ts` + `src/cli/orch-eval.ts`: real-model A/B with a deterministic
rubric, per-`(scenario × model)` control-baseline caching, regression detection, and layered
cost guards (pre-run estimate → per-run turn cap → global token budget → hard stop). It was
used to *promote* the `lean` sub_agent prompt on evidence (`SUBAGENT_PROMPT_VARIANTS` in
`prompt-generator.ts`), and to A/B the primary `contextfirst` prompt and *reject* it (control
won) — i.e. it catches regressions, not just wins. Almost no agent project shows a prompt
measurement loop. Make it a named slide: *"We A/B our prompts against real models with a
deterministic rubric and ship on evidence."*

**3b. OSINT / external-recon (new slide or fold into the graph slide).** `osint_recon`
archetype (WebSearch/WebFetch, no shells/creds), OSINT node types (`subdomain/asn/
organization/email`), OSINT edges (`SUBDOMAIN_OF/RESOLVES_TO/IN_NETBLOCK/OWNS_ASSET/
AFFILIATED_WITH`), `domain_enumeration` frontier. "Passive attack-surface mapping from public
sources, into the same graph, without active scanning."

**3c. Campaigns / Campaign Board (expand the cockpit slide).** `manage_campaign`
(`src/tools/scoring.ts`) — create/activate/pause/resume/abort/status/clone/split/… with abort
conditions (consecutive failures, failure %, noise ceiling, time limit) and parent-progress
aggregation; `dispatch_campaign_agents` fans out a swarm. Multi-step sequenced ops with
guardrails — reduced to a one-word "Campaign Board" mention today.

**3d. Operator CLI — drive without Claude (new slide / fold into cockpit).**
`src/cli/operator-cli.ts`: read + write commands over `/api` (status/frontier/findings/
agents/approvals/opsec/sessions/queries; approve/deny/answer/deploy/dispatch). "Steer a live
engagement from a terminal, no LLM" — compelling and entirely missing.

**3e. Retrospective + KB feedback loop (fold into inference).** `run_retrospective`
(`src/tools/retrospective.ts`) emits inference-rule suggestions, skill-gap analysis,
context-improvement recs, a client-ready attack-path report, and RLVR training traces. Pairs
with 3a as "we close the loop on our own tooling."

**3f. Enterprise identity / cloud-pivot depth (expand graph or new "enterprise" slide).**
3 IdP node types (`idp/idp_application/idp_principal`), federation modes, OIDC/SAML
token-bound creds with MFA pass-through flags, full ADCS ESC1–ESC13 (+ESC15), and 4
credential-expansion playbooks (AWS/Entra/GitHub/OIDC). The deepest, most differentiated
surface — the deck barely gestures at it.

**3g. 78-tool MCP surface (one line on extensibility).** Quantifies the API surface the rest
of the deck implies.

**3h. Frontier internals (fold into the frontier slide).** Not just a ranked list: ~7
deterministic filter stages (scope, superseded-skip, staleness, credential-TTL multipliers,
CIDR-truncation, dedup, KB/chain confidence boosts), a 5-state linkage lifecycle
(`open→validated/pursued/rejected/dropped`, drop after 5 silent `next_task` calls), and 600s
leases preventing duplicate dispatch. Also state plainly that `confidence` here is a
**composite multiplier** that can exceed 1.0, not a calibrated probability — an engineer will
ask.

---

## 4. Per-slide notes (only slides needing a change)

- **Knowledge graph:** 23→**30** nodes, 73→**90** edges; add OSINT + IdP families to the
  example list.
- **Frontier:** 6→**11** item types (flag `idp_enumeration` + `cross_tier_pivot` as
  declared-not-generated); add the filter stages + linkage lifecycle + lease note; clarify
  composite-confidence semantics.
- **Inference rules:** confidence 0.3–0.7 → **0.3–1.0 (weighted 0.6–0.8)**. One clarifying
  line: cloud *rules* are AWS-focused (Entra/Okta/OIDC *modeling* exists, inference rules
  deferred); rules synthesize attack chains, external recon is the parser/archetype layer.
- **Agent archetypes:** 13→**15**; add `osint_recon` to the enumeration.
- **Audit & reproducibility:** the deck implies signed checkpoints ship today — the Ed25519
  signing slot is reserved/wired but sign+verify is the remaining work. Say "signing slots
  reserved" or move "signed" to roadmap (see §5/§6).
- **Operator cockpit:** name the real panels; mention the 4 not listed (Engagements,
  Overview, Settings, Smoke). Note Campaign Board is a view mode.
- **Extensibility:** 34→**43** skills, 50→**114** parsers, add the **78**-tool count.
- **Honest limitations / Q&A:** two "future" items are mostly built — re-label as
  "hardening," not "not started" (see §6), or you undersell again.

---

## 5. Narrative / structure for a technical audience

Engineers reward *depth on hard problems* over breadth.

1. **Open on determinism + replay, not the graph.** Single-executor invariant, WAL mutation
   journal, snapshot+journal replay across compaction, deterministic `act_<16hex>` IDs,
   tamper-evident hash chain. Lead with "state survives compaction and is replayable +
   tamper-evident," then show the graph as the data model under it. This is the credibility
   anchor.
2. **Make inference a "rules are data" set-piece.** 63 declarative rules + runtime
   `suggest_inference_rule` + the retrospective→rule-suggestion loop. Show one rule firing →
   hypothesis edge → frontier item end-to-end, not a bullet that says "data-driven."
3. **Identity/credential modeling deserves its own slide** (§3f) — deepest, most
   differentiated, currently compressed into a list.
4. **Close on the eval harness** (§3a) as the engineering-maturity proof: "and here's how we
   keep the agents' prompts from regressing." Reframes the project from "cool agent demo" to
   "measured system."
5. **Be crisp about boundaries — it increases trust here.** Confidence is a composite
   multiplier, not a probability; cloud inference is AWS-only; parsers run in-process
   (sandboxing is roadmap); the Bash-deny hook is a speed bump and the *real* egress boundary
   is the MCP/engine layer (sole creds + scope validation). Naming the limits is what makes
   the strengths believable. Don't pad: one rule-firing trace + one replay diagram beats ten
   feature bullets.

---

## 6. Unaddressed / roadmap items — prioritized

Verdicts from reading current state. Separates genuine credibility wins from treadmill work;
two deck "future" items are mostly-built and two are low-ROI drops. (Full plan with files +
sequencing lives in the implementation plan.)

| Priority | Item | Effort | Why / current state |
|---|---|---|---|
| **do-now** | Stop-hook turn-scoping | M | Highest-ROI hook gap. Today a single early `get_state()` (or the literal `report_finding` in prose) suppresses the drift block all session. Key on structured `tool_use` for the current turn. |
| **do-now** | Fuller noise-budget dashboard | S | `opsec-tracker.ts serialize()` already tracks per-host/domain/campaign noise; needs only an `/api` accessor + a view. Makes the OPSEC-enforcement slide legible. |
| **next** | Ed25519 checkpoint signing | M | Turns "tamper-evident" into "non-repudiable" — closes the audit-slide gap the deck calls out. Slots reserved (`activity-chain.ts`); crypto is small. Real surface is key mgmt. |
| **next** | Graph-delta plan-impact preview | M | Show a plan's graph delta before it runs. Reuse the ingest **dry-run** path, not a parallel estimator. |
| **next** | Finding source-trust labels (observed/asserted/inferred) | M | Epistemic honesty an offsec report needs; signals already scattered, needs a backfill default. |
| **next** | PreToolUse matchers: Task / Write / WebFetch | M | Closes the hook surface rated highest — **Task** lets a delegated subagent escape every gate. Deny Task; remind on Write/WebFetch. Reuse the engagement-active gate. |
| **next** | SessionStart / PreCompact bootstrap hook | S | Cheap; re-injects the `get_system_prompt` mandate after compaction. |
| **next** | Parser sandboxing — cheap slice first | S→L | `parse-output.ts` passes no `baseDir` to `validateFilePath` → constrain reads to the evidence dir now; defer execution isolation. |
| **next** | OSINT 2D-2: asn→scope-suggestion fork | L | whois netblocks become operator-reviewable scope expansions; org/email enrichment is the lower-value half — defer it. |
| **later** | gitleaks/trufflehog secret parser | M | Typed, **redacted** credential nodes vs today's raw `cred_value` dump. |
| **later** | Full phase-aware policy enforcement | M | **Deck overstates the gap** — phase overrides already merge (tighten-only). Remaining work is edge-case hardening; re-word the slide. |
| **later** | Process-isolated sub-agents | XL | **Deck understates current state** — the highest-risk LLM agents already run out-of-process as headless MCP clients with allowlists. |
| **later** | Agent handoff / split / merge | L | Fleet ergonomics; existing directive + dispatch primitives cover most steering. |
| **drop** | Bash-deny regex hardening | L | Low ROI by design — the deny is a speed bump; the real boundary is MCP/engine egress. Say so on the slide. |
| **drop** | Non-MCP CLI driver (offline loop) | L | The operator CLI already covers "drive without Claude." |

**Sequence:** the two **do-now** items first (both back deck claims). Then **next** in two
infra-sharing tranches — (1) credibility: Ed25519 + plan-preview + source-trust; (2) hooks:
Task/Write/WebFetch + SessionStart/PreCompact + parser baseDir — then OSINT asn-slice. Defer
*later*; cut the two *drop* items from the roadmap slide and replace with "MCP/engine egress
is the real boundary."
