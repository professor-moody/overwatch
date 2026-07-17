# run_retrospective

Perform a structured post-engagement retrospective analysis.

**Read-only:** Yes (optionally writes to disk)

## Description

Produces five structured outputs:

1. **Inference rule suggestions** — patterns the graph shows that existing rules missed
2. **Skill gap analysis** — skills unused vs. techniques attempted without skills
3. **Context-improvement recommendations** — where context, logging, validation, and coverage should improve
4. **Attack path report** — client-deliverable markdown (timeline, findings, recommendations)
5. **Heuristic RLVR traces** — state→action→outcome triplets with explicit confidence and trace quality

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `write_to_disk` | `boolean` | `false` | Save all outputs to files |
| `output_dir` | `string` | `"./retrospective/"` | Directory for output files |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `summary` | `string` | High-level summary |
| `inference_suggestions` | `array` | Suggested new inference rules with evidence |
| `skill_gaps` | `SkillGapReport` | Unused skills, missing skills, failed techniques |
| `context_improvements` | `ContextImprovementReport` | Frontier observations, context gaps, OPSEC observations, logging quality |
| `training_traces_count` | `number` | Number of RLVR training traces |
| `trace_quality` | `TraceQualityReport` | Quality assessment of training traces |
| `report_preview` | `string` | First 500 chars of the markdown report |
| `output_dir` | `string` | Output directory (if `write_to_disk: true`) |
| `generation_id` / `generation_path` | `string` | Immutable authoritative output generation (if written) |
| `generation_manifest` / `pointer_path` | `string` | Checksummed manifest and atomic current-generation pointer |
| `generation_committed` / `generation_commit_durability` | `boolean` / `string` | Whether the pointer is durably committed versus only visible with uncertain directory durability |
| `legacy_mirror_complete` | `boolean` | Whether all fixed-name compatibility files match the generation |

### Output Files (when `write_to_disk: true`)

The immutable directory returned as `generation_path` is authoritative. These fixed names under `<output_dir>/<engagement_id>/` are compatibility mirrors refreshed only after the pointer commits:

| File | Content |
|------|---------|
| `report.md` | Client-deliverable attack path report |
| `inference-suggestions.json` | Suggested inference rules |
| `skill-gaps.json` | Skill gap analysis |
| `context-improvements.json` | Context improvement recommendations |
| `training-traces.json` | RLVR training traces |
| `trace-quality.json` | Trace quality assessment |
| `summary.txt` | Summary text |

## Usage Notes

- Run at the end of an engagement or after significant progress
- The attack path report (`report.md`) is designed for client delivery
- Inference suggestions can be applied to future engagements via `suggest_inference_rule`
- Training traces can be used for model fine-tuning (RLVR)
- Also available as a CLI: `npm run retrospective`
