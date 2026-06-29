# Prompt Architecture Review

A review of how Overwatch instructs the model — the generated system prompt and
the layers around it — and options for evolving it. **This is an analysis to
inform a decision; it proposes no code changes.** The source of truth at runtime
is [`src/services/prompt-generator.ts`](https://github.com/professor-moody/overwatch/blob/main/src/services/prompt-generator.ts).

## TL;DR

The instinct that we're "still doing persona prompting" is half right. The
generated prompt is **already ~70–80% concrete and regenerated live on every
call** — real graph counts, the actual frontier, the live OPSEC budget, expiring
credentials, KB-derived anti-patterns. The persona prose ("You are an offensive
security operator…") is **concentrated in two places**: the opening of the
*identity* section and the framing lines of the *core loop*. The bigger structural
issue isn't persona vs specifics — it's **redundancy across instruction layers**
(the Core Loop and Key Principles are byte-identical in the generated prompt and
`AGENTS.md`) and the fact that the universal prose was written for *human
readability*, which is what carries the persona tone.

So the realistic moves are: (1) trim the persona framing and lead with specifics;
(2) collapse the cross-layer duplication to a single source of truth; and,
optionally, (3) go *context-first* — replace prose with a structured,
machine-readable context block plus an explicit decision policy.

## 1. Anatomy of the generated prompt

`generateSystemPrompt(role)` assembles prioritized sections under a token budget
(`DEFAULT_MAX_PROMPT_TOKENS = 8000`, `prompt-generator.ts:78`), sorted
CRITICAL → HIGH → MEDIUM → LOW, with summarize-or-drop when over budget
(`:115-147`). It is **regenerated from live engine state on every call** (not
cached), so dynamic sections always reflect the current engagement.

| Section | Priority | ~Tokens | Nature |
|---|---|---|---|
| `identity` (`:222`) | CRITICAL | ~400–600 | **Mixed** — persona opener, then concrete briefing (name, id, scope, OPSEC, objectives) |
| `core_loop` (`:257`) | CRITICAL | ~2000–2500 | **Mostly concrete** — 12 numbered steps threading real tool calls + frontier/action ids; framing lines carry persona |
| `tactical` (`:595`) | HIGH | ~1200–1500 | **Mostly concrete** — before-action checks, playbook tool signatures |
| `key_principles` (`:359`) | HIGH | ~1500–2000 | **Mixed** — "the graph is your memory" framing + concrete guardrails / API specifics |
| `tool_table` (`:414`) | MEDIUM (summarizable) | ~800–1200 | **100% concrete** — live tool list |
| `state_snapshot` (`:433`) | MEDIUM | ~300–500 | **100% concrete, live** — node/edge counts, access, objective progress |
| `situational` (`:643`) | LOW (summarizable) | ~600–1500 | **100% concrete, live** — OPSEC budget, expiring creds, spray coverage, unprocessed results, scope suggestions |
| `anti_patterns` (`:856`) | HIGH | ~400–800 | **Mixed** — static "don't crack hashes when CVEs exist" + live KB low-success-technique stats + engagement `failure_patterns` |

The persona prose is the opener of `identity` (`:226`):

> "You are an offensive security operator running an authorized engagement. Your
> state, memory, and reasoning substrate is the Overwatch MCP orchestrator
> server. You do NOT need to hold engagement state in your context — the graph
> holds everything."

…and the framing lines of `core_loop` / `key_principles`. Everything below those
openers is procedure and live data. **By volume, specifics dominate.** The
`sub_agent` role variant (`:175-216`) is leaner still — scoped tool subset +
agent context (subgraph, task, inlined skill snippet), no tool table / state
snapshot.

## 2. The instruction stack + redundancy map

The model receives instruction from **four** composing layers:

1. **Generated prompt** — `prompt-generator.ts` (live, the source of truth).
2. **Archetype mission** — `bootstrapMission(archetype)` in
   `agent-archetypes.ts`, a 1–2 sentence "your job is X" injected into the
   headless sub-agent bootstrap (`headless-mcp-runner.ts:275`).
3. **Skill** — `skills/*.md`, inlined as a ~500-char snippet in the sub-agent
   prompt and available in full via `get_skill()`.
4. **`AGENTS.md`** — the static offline fallback, explicitly *not* regenerated.

Redundancy:

| Guidance | Generated prompt | AGENTS.md | Mission | Skills |
|---|---|---|---|---|
| Core Loop | ✅ | ✅ **byte-identical** | — | — |
| Key Principles | ✅ | ✅ **byte-identical** | — | — |
| Tool table | ✅ (live) | ✅ (static, may lag) | — | — |
| State snapshot / situational / anti-patterns | ✅ (live) | — | — | — |
| Sub-agent workflow | — | ✅ | ✅ (as mission) | — |
| Methodology | partial | partial | — | ✅ (deep) |

The Core Loop + Key Principles duplication is **intentional** (AGENTS.md is the
offline fallback when MCP is unavailable), but it means every edit must touch two
places, and the static copy silently drifts. Missions and skills are *not*
redundant — they're orthogonal (the job vs how to execute) and correctly layered.

## 3. Options

### (a) Trim + de-dup (incremental, low risk)
- Cut the persona opener; lead `identity` with the **concrete briefing** + a
  one-line role tag. Move the framing into a single short "operating model" line.
- Make the generated prompt the **single source of truth**: reduce `AGENTS.md` to
  a thin "MCP unavailable? here's the minimum" stub that points at
  `get_system_prompt`, instead of a byte-identical copy of Core Loop / Key
  Principles.
- Promote the live sections (state snapshot, situational) earlier so the model
  hits specifics first.
- **Token impact:** small net reduction. **Risk:** low — same structure, same
  semantics. **Effort:** small. **Sub-agent effect:** minimal.

### (b) Context-first restructure (deliberate "post-persona" redesign)
- Replace prose with a structured, machine-readable context block — `<objective>`,
  `<scope>`, `<state>`, `<affordances>` (tools), `<policy>` (an explicit decision
  procedure) — and keep only a minimal role tag.
- The decision procedure replaces the prose "Core Loop" with a tight,
  unambiguous policy the model executes.
- **Token impact:** potentially larger reduction + higher signal density.
  **Risk:** higher — changes how every agent reads instructions; needs careful
  eval against current behavior. **Effort:** larger, touches sub-agent prompts +
  AGENTS.md + the snapshot/retrospective format. **Sub-agent effect:** significant
  (the bootstrap + mission framing would need to match).

### (c) Hybrid (recommended starting point)
- Do (a) now — it's cheap, removes the real drift risk (duplication), and trims
  the persona tone the maintainer flagged — while **measuring** prompt token cost
  and model behavior on real transcripts.
- Pilot (b) on the **sub_agent** variant first (smaller surface, archetype-scoped,
  easier to eval) before touching the primary prompt.

## 4. Recommendation

Start with **(c)**: ship the trim + de-dup (option a) as the first concrete step —
biggest ratio of value (less persona, one source of truth, no drift) to risk — and
treat the context-first restructure as a piloted follow-up on the sub-agent prompt,
gated on a behavior eval. Concrete first step for a follow-up plan:

1. Reduce `AGENTS.md` Core Loop / Key Principles to a stub that defers to
   `get_system_prompt`, eliminating the byte-identical duplication.
2. Rewrite the `identity` opener to lead with the briefing + a one-line role tag.
3. Add a prompt-size assertion / snapshot test so token cost is tracked.

None of this is implemented here — this document exists to choose the direction.
