# Prompt rethink — step (b): context-first sub-agent prompt

Step (b) of the [prompt-architecture rethink](prompt-architecture-review.md). Step
(a) trimmed the persona opener; step (b) restructures the **sub-agent** operating
prompt into a context-first shape and measures the change through the
[behavior-eval harness](prompt-eval.md) instead of shipping on taste.

## The two axes (and why we split them)

Research surfaced that the design space has two largely-orthogonal axes the early
candidates conflated:

- **Axis A — prompt *shape*:** restructure prose into context-first form. Pure
  copy/ordering; no signature change.
- **Axis B — *architecture*:** today `generateSubAgentPrompt` is **archetype-blind**
  — the agent's mission/done-test live only in the runner bootstrap (`MISSIONS`),
  not in the prompt it fetches via `get_system_prompt`. Making the system prompt
  archetype-aware (fold `MISSIONS → ARCHETYPES`, generate AGENTS.md from one
  source) is a registry refactor.

**Decision: ship Axis A first (the `lean` variant), as its own change, so a
Tier-2 regression is cleanly attributable to *shape*, not plumbing.** Axis B (the
registry refactor) lands as a separate follow-up; an explicit decision-policy
layer (named exit-states + ask-gate) is added only if the eval shows the lean
shape under-constrains long-running/ambiguous tasks.

## Enabling `lean`

`control` is the **default** — `lean` is opt-in:

- **Eval A/B:** `npm run prompt-eval -- --real --variant lean --yes` (the supported way to evaluate it; see [Prompt Behavior-Eval](prompt-eval.md)).
- **Whole server:** `export OVERWATCH_PROMPT_VARIANT=lean` before starting, and every sub-agent's `get_system_prompt(role="sub_agent")` renders `lean`.
- **In code:** `generateSystemPrompt(engine, tools, { role: 'sub_agent', variant: 'lean' })`.

Nothing changes at runtime until you opt in; promotion to default happens only on a clean real A/B (see Results below).

## What `lean` is

A second sub-agent prompt variant selected via `generateSystemPrompt({ variant })`
(resolved from the option, then `OVERWATCH_PROMPT_VARIANT`, then `control`).
`control` is the shipped prompt and **stays the default**. The `lean` shape:

1. **Identity** — one orienting line, no persona paragraph.
2. **Brief** (promoted to the top) — objective, **done-when**, scope (hard stop),
   archetype, expected noise, skill (by reference), and concrete target-node
   properties. Closes by noting `get_agent_context` is the authoritative live view.
3. **Tools** — the scoped tool table, kept behind `include_tools` for the first
   A/B (so the ~tool-table cut can be measured before hard-removing).
4. **Loop** — 5 named phases (ORIENT / VALIDATE / EXECUTE / LAND / WRAP), each a
   tool call with a checkable postcondition, replacing the 0–12 step list.
5. **Guardrails** — exactly four motivated invariants (stay in scope; validate
   before every execute with a matching `action_id`; land results don't narrate;
   heartbeat while long-running).
6. **Steering & escalation** — operator directives + named terminal states
   (NO_PATH / BLOCKED / AMBIGUOUS) + the `ask_operator` gate.
7. **Example** — one worked trace showing IDs flowing through the loop.
8. **Tactics** — trimmed durable heuristics; the credential-playbook block renders
   only for credential-class archetypes.

It preserves the five structural-guard literals (`get_agent_context`,
`validate_action`, `parse_output`, `report_finding`, `submit_agent_transcript`)
and runs **~43–46% leaner** than control (tool table kept).

## How it goes through the harness

1. **Variant seam** — `control` and `lean` render from the same entry; the eval
   selects the arm via `OVERWATCH_PROMPT_VARIANT`.
2. **Tier-1 structural guard** ($0 CI) — `checkPromptAffordances` asserts the five
   literals survive in `lean` for every scenario archetype *and* a read-only
   archetype (`cve_researcher`); a size guard asserts it fits the token budget and
   is leaner than control.
3. **Tier-2 real A/B** (on-demand, cost-bounded) — `npm run prompt-eval -- --real
   --variant lean` runs `lean` vs the cached `control` baseline per scenario and
   flags any per-criterion regression via `compareGrades`. The two 2×-weighted
   criteria (validate-before-execute, lands-results) are the hard gates.
4. **Self-validation** — before trusting the result, A/B `lean` vs a deliberately
   degraded run to confirm the rubric still flags a regression.
5. **Promotion** — on a clean A/B, make `lean` the default and update AGENTS.md +
   `docs/tools/index.md` in lockstep (control stays behind the flag for one
   release as rollback). Until then **control remains the default**, so the
   offline fallbacks are unchanged.

## Results

First real-model A/B — `haiku`, 3 scenarios, **1 trial/cell** (6 runs), **~$0.63**
total (2.45M tokens, mostly cheap cache-reads). Overall scores (lean vs control):

| Scenario | control | lean | Δ | flag |
|----------|---------|------|------|------|
| recon | 0.378 | 0.556 | **+0.18** | — |
| web | 0.167 | 0.333 | **+0.17** | ⚠ `starts_with_context` 1.00→0.00 |
| cloud | 0.333 | 0.667 | **+0.33** | — |

**Lean improved overall on all three scenarios.** The gains concentrate where the
restructure aimed: the 2×-weighted **`validate_before_execute`** criterion jumped
(recon 0.20→1.00, web 0.25→1.00, cloud 0.00→1.00 — the explicit "validate before
every execute, with the matching action_id" guardrail working) and
**`threads_frontier_item_id`** improved (web/cloud 0→1.00 — the worked-trace example).
No regression on the two 2×-weighted hard-gate criteria.

Caveats, stated plainly:

- **`objective_progress` and `completed` were 0 for every run, both arms.** The
  synthetic targets are unreachable, so no services are found and the agent hits
  `--max-turns` before WRAP (`status: interrupted`). Those criteria carry no signal
  here; the result rests on the loop-compliance criteria.
- **The harness flagged a real regression** on web (`starts_with_context` 1.00→0.00:
  lean's agent didn't orient with `get_agent_context` first). This is exactly the
  signal the A/B exists to surface — but at **n=1 it may be noise**.
- **n=1 per cell is noisy.** This is a promising first pass, not a verdict.

**Recommendation:** lean is a real, consistent improvement and worth promoting —
but confirm first with **2–3 trials** (especially the web orientation regression)
before flipping the default. Promotion remains a separate, deliberate step.

## Known weak spots (carried, not hidden)

- **Synthesized done-when** — derived from the frontier item, so it's only as
  good as that description; the Axis-B registry-sourced `doneTest` later upgrades it.
- **Context-first at ~3–5k tokens is a hypothesis** — the salience evidence is for
  20k+ inputs; a flat/negative A/B delta is a real possibility. That's why it's
  measured, not assumed.
- **Dropped redundancy may matter in long sessions** — the leanest variant can
  pass structural + fake-claude checks yet regress on long real runs; the A/B must
  include a long-running scenario before `lean` is promoted.
- **De-emphasis is model-sensitive** — correct for the Opus-4.x runtime backing
  sub-agents; revisit if sub-agents ever run on a weaker/peer model.
