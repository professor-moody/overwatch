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

## Status: `lean` is now the default

After the real-model A/B + the orient-first fix (see Results), **`lean` was promoted
to the default** sub-agent prompt. `control` is kept as a **one-release rollback**:

- **Default (lean):** `get_system_prompt(role="sub_agent")` renders `lean` for every
  dispatched sub-agent — no flag needed.
- **Rollback to control:** `export OVERWATCH_PROMPT_VARIANT=control` (or
  `generateSystemPrompt(…, { variant: 'control' })`).
- **Eval either arm:** `npm run prompt-eval -- --real --variant lean --yes` A/Bs a
  variant vs the cached control baseline (see [Prompt Behavior-Eval](prompt-eval.md)).

## What `lean` is

The sub-agent prompt variant selected via `generateSystemPrompt({ variant })`
(resolved from the option, then `OVERWATCH_PROMPT_VARIANT`, then the default `lean`).
The `lean` shape:

1. **Identity** — one orienting line, no persona paragraph.
2. **Brief** (promoted to the top) — objective, **done-when**, scope-by-id (hard
   stop), archetype, expected noise, skill (by reference). It deliberately does
   *not* inline the nodes' properties (the orient-first fix removed that — it made
   the agent feel pre-oriented and skip `get_agent_context`); the Brief is framed as
   a stale snapshot whose first instruction is to call `get_agent_context`.
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
5. **Promotion** — **done.** On the clean A/B + orient-first fix, `lean` became the
   default (`resolveSubAgentVariant`) and AGENTS.md's sub-agent workflow was updated
   in lockstep; `control` stays behind `OVERWATCH_PROMPT_VARIANT=control` for one
   release as rollback.

## Results

### Guarded qualification follow-up (2026-07-19)

The hermetic web control qualification completed at **1.00**, landed the expected
fixture through the production parser, and produced a complete artifact. The first
lean qualification failed safely before target execution: it reached the eight-turn
limit after repeatedly calling `ToolSearch` for `get_agent_context`, even though the
search had already returned the tool reference. No shim or network-capable command
ran, and the incomplete run was not promoted to a baseline.

That preserved artifact demonstrated a prompt-level deferred-tool handoff gap, so
the lean ORIENT instruction now makes the boundary explicit: `ToolSearch` discovers
a tool; after it returns a reference, the agent invokes that MCP tool next and does
not search for it again. This is intentionally narrower than disabling ToolSearch,
which remains necessary when the deferred MCP surface starts empty. The failed lean
cell must be rerun under the same independent dollar cap before qualification
continues.

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

> Run notes: one web trial ran away to ~2.6M tokens (vs ~450k typical), which spiked
> the budget guard's **max-based** adaptive estimate and truncated the first n=5 batch
> early (cloud was completed in a follow-up run). A percentile-based estimate would
> be more robust to a single outlier.

### Orient-first fix + re-eval

The diagnosis above drove a targeted lean change: **remove the inline target-node
property dump from the Brief** (the redundant bit — those details come from
`get_agent_context`) and make **ORIENT explicitly "always your first action."** The
Brief keeps its context-first framing (objective / done-when / scope-ids on top) but
no longer substitutes for the orientation call. Re-ran lean at n=5 vs the same cached
control (~$1.67):

| Scenario | control | lean (pre-fix) | lean (**fixed**) | Δ vs control | `starts_with_context` |
|----------|---------|----------------|------------------|--------------|----------------------|
| recon | 0.501 | 0.444 | **0.497** | −0.004 (tied) | 1.00 |
| web | 0.120 | 0.183 | **0.214** | **+0.094** | 0.40 → **0.60** |
| cloud | 0.378 | 0.511 | **0.533** | **+0.156** | 0.80 → **1.00** ✓ |

- **The cloud regression is eliminated** (`starts_with_context` 0.80→1.00; cloud now
  has *no* per-criterion regressions) and **web more than halved** it (0.40→0.60).
- **All overalls improved**, and the validate/threading gains held.
- **recon is now tied** (−0.004) — and on the real criteria it's *better* (validate
  0.16→0.47, threading 0→0.14); the gap is the noisy `objective_progress` again.

**Verdict — lean (with the orient-first fix) is net-positive on all three scenarios**
(web +0.09, cloud +0.16, recon tied/better-on-real-criteria), wins the 2×-weighted
safety criterion everywhere, and no longer carries the big regression. **It was
promoted to the default.**

A further web-specific tweak was tried (an explicit "orient before you act" guardrail
+ an "even when the objective names a target" ORIENT clause) and **reverted** — at
n=5 it nudged web `starts_with_context` up (0.60→0.80) but knocked cloud *down*
(1.00→0.80), a net wash within noise that didn't justify diluting the four-invariant
guardrail block. The residual web `starts_with_context` ≈ 0.60 is left as-is: a
1×-weight criterion, partly inherent (for a single-URL web target the agent rationally
jumps straight to it), and not worth chasing further on these synthetic scenarios.

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

## Move 4 — context-first PRIMARY prompt (TESTED NEGATIVE RESULT)

After `lean` was promoted, the same context-first restructure was applied to the
**primary/orchestrator** prompt (`contextfirst`: lead with live engagement state, a tight
ORIENT→SCORE→DISPATCH→SYNTHESIZE loop, motivated guardrails) and A/B'd through the
**orchestration eval** built for it — a real `claude` primary that dispatches *fake*
children (`npm run orch-eval`), graded by `eval-orchestration-rubric.ts` (9 criteria: a
binary floor + the continuous discriminators dispatch_precision / orient_efficiency /
adaptive_synthesis, added after the floor saturated at 1.0 on the first calibration).

**Result: `control` won — `contextfirst` was not promoted.** Two real-model A/Bs on haiku
(~$4.6):

- A/B v1 (5 control / 4 contextfirst, budget-limited): mean Δ +0.10, but a *tie by median*
  (0.939 vs 0.929) — the gap was one catastrophic control trial (oriented, then dispatched
  zero). contextfirst slipped orient-first in 1/4 trials (opened with `Bash`, not `get_state`).
- Orient-first fix (mirroring lean's): made ORIENT "always your first action," get_state
  before any execute.
- A/B v2 (equal 5v5, orient-fixed): **control 0.944 vs contextfirst 0.900, Δ −0.044.** The
  fix did *not* close the slip — contextfirst still opened with `Bash` in 2/5 trials.

**Finding: context-first does not transfer from sub-agent to orchestrator.** The
orchestrator's "context" is the *live frontier*, which it must re-fetch with `get_state`
(for freshness, and the rubric rewards it). Leading with the state snapshot makes the model
feel pre-oriented, so it skips the orient call — a *structural* effect a text-only emphasis
can't fix (the lean analogue was fixed by *removing* inlined detail, which would gut the
"lead with state" thesis here). contextfirst also over-dispatched (lower dispatch_precision).
`control` never slips orient because the live frontier isn't in its prompt.

The `contextfirst` variant is kept behind `OVERWATCH_PRIMARY_VARIANT` as a reproducible
negative-result reference; the orchestration eval harness (Move 3) is the durable asset —
it stopped a plausible-by-analogy change from regressing the most load-bearing prompt.
