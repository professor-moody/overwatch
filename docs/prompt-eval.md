# Prompt behavior-eval harness

A two-tier harness for checking that a change to the agent operating prompt
doesn't **degrade agent behavior** — without burning an insane amount of money to
find out.

It exists to gate prompt rethink **step (b)** (the context-first sub_agent
restructure): you can't trust a restructured prompt until you can measure whether
agents still follow the loop. The catch is that `fake-claude` (the deterministic
test double) runs a *scripted* tool sequence regardless of prompt wording, so it
can't test prompt-reading — only a real model can. So the harness has two tiers.

## Tier 1 — deterministic, in CI, $0

Runs on every PR. No model.

- **Rubric grader** ([`src/services/eval-rubric.ts`](https://github.com/professor-moody/overwatch/blob/main/src/services/eval-rubric.ts))
  — `gradeRun(run, scenario)` scores a run for loop-compliance across six
  criteria: starts-with-context, validate-before-execute, frontier_item_id
  threading, lands-results-not-prose, objective-progress, completed. Pure +
  deterministic given a run, so it grades a non-deterministic real-model run
  reproducibly and is unit-tested on canned inputs.
- **Structural affordance guard** — `checkPromptAffordances(prompt)` asserts a
  generated sub_agent prompt still *mentions* the load-bearing tools
  (`get_agent_context`, `validate_action`, `parse_output`, `report_finding`,
  `submit_agent_transcript`) and fits `DEFAULT_MAX_PROMPT_TOKENS`. A restructure
  that drops one fails here, in CI, before any spend.
- **Plumbing smoke** — `prompt-eval-smoke.integration.test.ts` seeds each
  scenario, runs a fake-claude sub-agent, maps the run into a `RunRecord`, and
  grades it — proving the run→record→grade pipeline end-to-end (not prompt
  behavior).

## Tier 2 — real model, on-demand, cost-bounded

`npm run prompt-eval` runs real `claude` sub-agents on the tiny scenario set,
grades each with the rubric, and caches a **control baseline** per
(scenario × model). When step (b) adds a candidate prompt variant, the same
machinery A/Bs candidate-vs-control and flags regressions (`compareGrades`).

**It never runs in CI and spends nothing until invoked with `--real`.**

```bash
npm run prompt-eval                                   # usage (no spend)
npm run prompt-eval -- --real --yes                   # establish/refresh baselines
npm run prompt-eval -- --real --scenarios recon --trials 1 --budget 20000 --yes
```

### Cost controls

These are the point of the design — Tier 2 is hard to run expensively by
accident:

1. **Cheap model by default** — `haiku`; override with `--model`.
2. **Per-run turn cap** — `--max-turns` (default 10) bounds a runaway agent (this
   is the only *per-run* bound — there is no mid-run token cap).
3. **Global token budget** — `--budget` (default 50k), enforced two ways: a
   pre-run gate whose per-run estimate adapts up to the heaviest run seen (so
   after one heavy run it stops optimistically launching more), and a **hard
   post-run stop** the moment *actual* cumulative spend reaches the budget. A run
   already in flight is bounded only by `--max-turns`, so total spend can exceed
   `--budget` by at most one run's cost — it is a tight bound, not a per-token
   hard ceiling.
4. **Tiny defaults** — 3 scenarios, `--trials 2`.
5. **Pre-run estimate + confirm** — prints the run count + token estimate and
   requires interactive `y` or `--yes`.
6. **Baseline cache** — control results are cached to `eval-baselines/`
   (gitignored); subsequent runs reuse them (`--refresh-baseline` to re-run), so
   iterating on a candidate never repays for control.

### Scenarios

The library ([`src/test-support/eval-scenarios.ts`](https://github.com/professor-moody/overwatch/blob/main/src/test-support/eval-scenarios.ts))
is intentionally tiny (recon / web / cloud), each a seeded engagement state +
archetype + objective + rubric, kept small so a real run stays cheap.

## What it does *not* do

- It does not judge offensive **quality** (an LLM judge — parked; rubric-only
  first).
- The `--variant` candidate A/B is wired but inert until prompt step (b) adds the
  variant seam.
