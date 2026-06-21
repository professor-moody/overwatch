# Overwatch — Internal Presentation Outlines

Outlines to hand to a slide-building AI (or a human) to produce internal
presentations explaining and evangelizing Overwatch. **Not** a funding pitch.

## Files

| File | Audience | Use |
|------|----------|-----|
| [`00-message-spine.md`](00-message-spine.md) | — | **Canonical source of truth.** Verified facts, the five pillars, proof points, demo catalog, and an honest maturity table. The four decks draw from it; if a deck disagrees with the spine, the spine wins. |
| [`01-leadership.md`](01-leadership.md) | Team leadership / decision-makers | Strategic, outcomes-first, ends with a soft adopt/**pilot** ask (no funding). ~11 slides. |
| [`02-awareness.md`](02-awareness.md) | Broad internal / non-practitioners | Plain-language "what is this thing." ~9 slides. |
| [`03-showcase.md`](03-showcase.md) | Mixed, engaged room | A live/recorded **demo script** (scene = Goal · Do · Wow · Fallback). ~12 scenes. |
| [`04-technical.md`](04-technical.md) | Security engineers / operators | Architecture, mechanism, how to run/extend, honest limitations. ~18 slides. |

## How to use these with a slide-building AI

1. Give it `00-message-spine.md` **first** as the factual ground truth.
2. Give it the one deck you want built (e.g. `01-leadership.md`).
3. Ask it to expand each `## Slide N` into a slide using the bullets as content, the
   speaker notes as the talk track, and the "Suggested visual" as the art direction.
4. Keep the **maturity table honest** — shipped is shipped, roadmap is roadmap.

## Notes

- Facts (counts, defaults, behaviors) were verified against the codebase at authoring
  time. Re-verify counts before a high-stakes external talk (the live tool count comes
  from `get_system_prompt`; the rule list from `src/services/builtin-inference-rules.ts`).
- `awareness` and `showcase` share source material but differ in delivery: a narrative
  deck vs a live-demo script.
