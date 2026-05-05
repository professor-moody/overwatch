# Retrospectives

**Goal:** Get a client-deliverable report and learn what went well / what went wrong, automatically.

## Do this

When the engagement is done (or just paused for the day):

> **"Run the retrospective and write it to disk."**

The AI calls `run_retrospective with write_to_disk: true`. Output lands in `./retrospective/<engagement-id>/`.

Or via shell:

```bash
npm run retrospective
```

That's it. Open `retrospective/<engagement-id>/report.md` and you have a client-ready Markdown report.

## What you get

| File | What it is |
|------|-----------|
| **`report.md`** | Client-deliverable attack-path report — narrative timeline, findings, evidence, recommendations |
| `inference-suggestions.json` | New inference rules the engine spotted from graph patterns |
| `skill-gaps.json` | Skills that were never used + techniques that were missing |
| `context-improvements.json` | Frontier scoring observations, OPSEC noise patterns, logging gaps |
| `training-traces.json` | RLVR training triplets (state → action → outcome → reward) |
| `trace-quality.json` | Quality assessment of the training data |
| `summary.txt` | High-level "what happened" |

## What to do with the outputs

- **`report.md`** → review, customize, deliver to the client.
- **`inference-suggestions.json`** → apply the high-confidence ones with [`suggest_inference_rule`](../tools/suggest-inference-rule.md). Patterns with **5+ occurrences are auto-applied** to the active rule set; the rest are flagged for review.
- **`skill-gaps.json`** → tells you which skills to write or update before the next engagement.
- **`training-traces.json`** → feed into your RLVR pipeline if you have one.

## When to run it

- **End of every engagement**, even partial ones.
- **End of each working day** during long engagements — you'll catch logging gaps while you can still fix them.
- **Before starting the next engagement of the same type** — apply the inference suggestions first.

## How auto-improvement works

Two things happen automatically when you run a retrospective:

### Inference rule auto-apply

```
Occurrences ≥ 5  →  Auto-applied (added to active rule set)
Occurrences < 5  →  Suggestion only (logged for review)
```

The threshold prevents one-off coincidences from poisoning the rule set. `applyInferenceSuggestions()` returns counts of what was applied vs. skipped.

### Technique priors + skill annotations

Per-technique success rates are computed from training traces and feed into frontier scoring on the next engagement — techniques with historically higher success get a scoring boost. Skills get usage counts and success rates so you know which ones are pulling weight.

| Annotation | What it measures |
|------------|------------------|
| `use_count` | Total times the skill was referenced |
| `success_count` | Times a skill-associated action succeeded |
| `failure_count` | Times it failed |
| `success_rate` | `success_count / use_count` |

## See also

- [End-to-End Walkthrough](walkthrough.md) — Phase 8 shows what a real retrospective looks like
- [`generate_report`](../tools/generate-report.md) — standalone client report (without the full retrospective)
- [Concepts — Action Lifecycle](../concepts.md#action-lifecycle) — why structured logging matters for trace quality
