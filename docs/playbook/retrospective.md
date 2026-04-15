# Retrospectives

Post-engagement analysis for continuous improvement.

## Overview

The retrospective analyzes the full engagement history and graph state to produce five structured outputs:

1. **Inference rule suggestions** — edge patterns the graph shows that existing rules missed
2. **Skill gap analysis** — unused skills, missing methodology, failed techniques
3. **Context-improvement recommendations** — frontier observations, context gaps, OPSEC feedback, logging quality
4. **Attack path report** — client-deliverable markdown with timeline, findings, and recommendations
5. **RLVR training traces** — state→action→outcome triplets for model improvement

## Running a Retrospective

### Via MCP Tool

```
→ Call run_retrospective with write_to_disk: true
```

This generates all five outputs and writes them to `./retrospective/<engagement-id>/`.

### Via CLI

```bash
npm run retrospective
```

The CLI reads the persisted state file and writes output to `./retrospective/<engagement-id>/`.

## Output Files

| File | Description |
|------|-------------|
| `report.md` | Client-deliverable attack path report |
| `inference-suggestions.json` | Suggested new inference rules with evidence |
| `skill-gaps.json` | Unused skills, missing skills, failed techniques |
| `context-improvements.json` | Frontier observations, context gaps, OPSEC observations |
| `training-traces.json` | RLVR training traces |
| `trace-quality.json` | Quality assessment of training data |
| `summary.txt` | High-level summary |

## Interpreting Results

### Inference Rule Suggestions

Each suggestion includes:

- **Rule definition** — trigger conditions and produced edges
- **Evidence** — what graph patterns suggested this rule
- **Occurrences** — how many times this pattern appeared

Apply promising suggestions to future engagements via [`suggest_inference_rule`](../tools/suggest-inference-rule.md).

### Skill Gap Analysis

| Field | Meaning |
|-------|---------|
| `unused_skills` | Skills in the library that were never searched or applied |
| `missing_skills` | Techniques attempted that don't have corresponding skills |
| `failed_techniques` | Techniques that were tried but failed |
| `skill_usage_counts` | How often each skill was referenced |

Use this to prioritize new skill development and update existing skills.

### Context Improvements

| Area | What It Covers |
|------|----------------|
| Frontier observations | Patterns in how frontier items were scored and acted on |
| Context gaps | Where the graph lacked information that would have helped |
| OPSEC observations | Noise patterns, techniques that drew attention |
| Logging quality | How complete the action event logging was |

### Training Traces

Each trace captures:

- **State** — graph snapshot (node/edge counts, access level, objectives achieved)
- **Action** — what was done (type, target, technique, tool)
- **Outcome** — what changed (new nodes, edges, objective achievement)
- **Reward** — numerical reward based on outcome value
- **Confidence** — `low`, `medium`, or `high` based on data quality
- **Derived from** — `structured` (from action events), `text_heuristic` (from activity log text), or `mixed`

The trace quality report flags issues like missing action IDs, incomplete logging, or ambiguous outcomes.

## Best Practices

- Run retrospectives at the **end of every engagement** — even partial ones
- **Write to disk** for archival — the files are useful for comparing engagements
- Review inference suggestions **before starting the next engagement** — apply the best ones
- Use skill gaps to **prioritize skill development** — fill the most impactful gaps first
- Feed training traces into **RLVR pipelines** for model improvement
- The attack path report is designed for **client delivery** — review and customize as needed

## Automatic Inference Rule Application

When a retrospective produces inference rule suggestions, the engine can **automatically apply** high-confidence suggestions without manual review:

### Threshold-Based Auto-Apply

Suggestions with **5 or more occurrences** are applied automatically — the pattern has been observed frequently enough to be reliable. Suggestions below this threshold are flagged for manual review.

```
Occurrences ≥ 5  →  Auto-applied (added to active rule set)
Occurrences < 5  →  Suggestion only (logged for review)
```

The `applyInferenceSuggestions()` function processes the full suggestion list and returns counts of applied vs. skipped rules.

### Technique Priors

Overwatch computes **per-technique success rates** from RLVR training traces across engagements. These priors feed into frontier scoring — techniques with historically higher success rates get a scoring boost.

| Metric | Description |
|--------|-------------|
| `total_uses` | How many times this technique was attempted |
| `successes` | How many times it produced positive outcomes |
| `failures` | How many times it failed |
| `success_rate` | `successes / total_uses` |

Technique priors are extracted from the `action.technique` field in RLVR traces. Use `computeTechniquePriors()` to generate priors from a set of traces, and `getTechniquePrior()` to query the prior for a specific technique.

### Skill Annotations

The retrospective hooks automatically annotate skills with usage and outcome metrics:

| Annotation | Description |
|------------|-------------|
| `use_count` | Total times the skill was referenced during the engagement |
| `success_count` | Times a skill-associated action succeeded |
| `failure_count` | Times a skill-associated action failed |
| `success_rate` | `success_count / use_count` |

These annotations help identify which skills are most effective and which need updating. The `updateSkillAnnotations()` function processes the activity log and traces to compute these metrics.
