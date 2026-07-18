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
npm run prompt-eval -- --real --scenarios recon --trials 1 --max-budget-usd 0.50 --max-total-usd 0.50 --yes
```

### Cost controls

These are the point of the design — Tier 2 is hard to run expensively by
accident:

1. **Cheap model by default** — `haiku`; override with `--model`.
2. **Hard in-flight dollar cap** — every real Claude invocation receives
   `--max-budget-usd` (default `$0.50`). The evaluator refuses to run if the
   installed Claude CLI does not advertise that flag.
3. **Command-wide dollar ceiling** — `--max-total-usd` (default `$2.00`) limits
   the sum charged across the command. When Claude does not report a cost, the
   complete assigned run cap is reserved, so missing accounting never reopens
   budget.
4. **Turn and time caps** — `--max-turns` (default 10) and `--timeout-ms`
   (default 600000 = 10 min) bound agent work and wall-clock waiting.
5. **Token-accounting batch gate** — `--budget` (default 50k) uses input,
   output, cache-read, and cache-creation accounting to decide whether another
   run should start and to stop a batch after a large result. It is not an
   in-flight spend ceiling; the dollar flags are.
6. **Tiny defaults + confirmation** — 3 scenarios, `--trials 2`; the command
   prints the maximum possible dollar spend and requires `y` or `--yes`.
7. **Baseline cache** — control results are cached to `eval-baselines/`
   (gitignored); subsequent runs reuse them (`--refresh-baseline` to re-run), so
   iterating on a candidate never repays for control.

### Preserved real-run evidence

Every `--real` invocation writes a private, gitignored directory beneath
`eval-artifacts/`. Each run retains a schema-versioned manifest, redacted Claude
stream, record, grade, sanitized command/tool metadata, usage and cost accounting,
graph delta, timestamps, and member checksums. Directories use mode `0700` and
files use mode `0600`.

The directory contains only the isolated synthetic evaluation runtime. It does
not copy the active operator engagement, credentials, evidence, or reports.

Terminal outcomes are recorded as `completed`, `failed`, `interrupted`,
`timed_out`, `budget_exhausted`, or `harness_error`. A timeout cancels the model
worker and waits for terminal process state before the isolated runtime is
removed. Only `completed` runs are eligible for cached baselines; every other
outcome remains diagnostic evidence. Deterministic fake-model and CI runs remain
temporary unless an artifact test explicitly requests preservation.

### Scenarios

The library ([`src/test-support/eval-scenarios.ts`](https://github.com/professor-moody/overwatch/blob/main/src/test-support/eval-scenarios.ts))
is intentionally tiny (recon / web / cloud), each a seeded engagement state +
archetype + objective + rubric, kept small so a real run stays cheap.

## What it does *not* do

- It does not judge offensive **quality** (an LLM judge — parked; rubric-only
  first).

The `--variant` candidate A/B is live as of [step (b)](prompt-stepb-design.md):
`npm run prompt-eval -- --real --variant lean` runs the `lean` arm vs the cached
`control` baseline per scenario and flags per-criterion regressions.
