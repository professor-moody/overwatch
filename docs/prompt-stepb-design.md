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

Real-model A/B on `haiku`, **5 trials/cell**, 3 scenarios (~35 runs total, ~$1.8).
A first **n=1** pass looked like a clean sweep for lean (+0.18/+0.17/+0.33) — but
**n=5 shows that was mostly noise.** Per-scenario overall (lean vs control):

| Scenario | control | lean | Δ |
|----------|---------|------|------|
| recon | 0.501 | 0.444 | −0.06 |
| web | 0.120 | 0.183 | +0.06 |
| cloud | 0.378 | 0.511 | +0.13 |

Per-criterion (the criteria that actually carry signal here):

| Criterion (weight) | recon c→l | web c→l | cloud c→l |
|--------------------|-----------|---------|-----------|
| `validate_before_execute` (2×) | 0.16→**0.50** | 0.04→**0.20** | 0.60→**1.00** |
| `threads_frontier_item_id` (1×) | 0→0 | 0→**0.45** | 0.40→**0.60** |
| `starts_with_context` (1×) | 1.00→1.00 | **1.00→0.40** | **1.00→0.80** |

What the data actually says:

- **Lean reliably improves the load-bearing safety criterion.**
  `validate_before_execute` (2×-weighted) is up in all three scenarios — the explicit
  "validate before every execute, with the matching action_id" guardrail works. It
  also improves `threads_frontier_item_id` on web/cloud (the worked-trace example).
- **One real regression: orient-first.** `starts_with_context` drops on web
  (1.00→0.40) and cloud (1.00→0.80) — confirmed across n=5, not the n=1 fluke it
  could have been. **Likely cause:** lean's context-rich **Brief** front-loads
  objective + scope + target-node properties, so the agent feels it already has its
  context and skips the `get_agent_context` call the LOOP tells it to make first. A
  context-first brief can *suppress* the orient-first tool call it's meant to support.
- **recon's −0.06 is an artifact of a noisy criterion.** It's entirely
  `objective_progress` (control 0.60 vs lean 0.00) — but on an unreachable host
  "finding a service" is the agent reporting a node from partial output, i.e. luck,
  not skill. Discounting `objective_progress`, recon lean is *better* (the validate
  gain). `objective_progress` + `completed` are ~0/noisy for both arms on synthetic
  targets and carry little signal — a fuller eval needs targets agents can actually
  act on.

**Verdict — do NOT promote lean as-is.** It's directionally positive (wins the
safety criterion everywhere; net-positive on 2 of 3 scenarios) but carries one
confirmed, concrete regression. **Next step:** iterate the lean prompt to fix
orient-first — strengthen ORIENT / require `get_agent_context` before acting, or
trim the Brief's inline target-node detail so the agent still needs the tool — then
re-eval. The fix is local; lean already wins on validate/threading, so removing the
orientation regression would likely make it a clear win.

> Run notes: one web trial ran away to ~2.6M tokens (vs ~450k typical), which spiked
> the budget guard's **max-based** adaptive estimate and truncated the first n=5 batch
> early (cloud was completed in a follow-up run). A percentile-based estimate would
> be more robust to a single outlier.

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
