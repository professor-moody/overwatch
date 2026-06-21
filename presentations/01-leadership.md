---
deck: Overwatch — Leadership Briefing
audience: Team leadership / decision-makers (security org)
goal: Understand what Overwatch is, why it matters, where it fits, and its trajectory — and say yes to a pilot. NOT a funding ask.
length: ~11 slides, ~15 min + Q&A
tone: Outcomes over internals. Minimal jargon. Confident but honest about maturity.
source_of_truth: ./00-message-spine.md
---

# Overwatch — Leadership Briefing

> For the presenter: lead with the problem and the outcomes; keep architecture to one
> slide. Every claim is grounded in `00-message-spine.md`. Be candid on the maturity slide
> — credibility is the point.

---

## Slide 1 — Title

- **Overwatch** — an orchestrator for AI-assisted offensive-security engagements.
- One line: *the persistent state layer and control room for LLM-driven pentesting.*
- **Speaker notes:** Set expectation: 15 minutes, ending with a small ask (a pilot, not a budget). This is about how our team runs engagements as we add AI.
- **Suggested visual:** Product name + a single screenshot of the operator cockpit (graph + "Needs you" + fleet).

## Slide 2 — The shift that's already happening

- AI is already in our engagements. The question isn't *whether* — it's *how we keep it in scope, on budget, and accountable.*
- Ad-hoc "AI in a chat window" doesn't survive a restart, can't be watched, and can't be proven afterward.
- **Speaker notes:** Frame Overwatch as the responsible-adoption path, not a science project. Name the three things leadership cares about: scope, OPSEC, auditability.
- **Suggested visual:** Before/after split — "AI in a chat window" vs "AI on a governed platform."

## Slide 3 — The problem, in business terms

- **Lost work** — engagement state lives in the model's memory; compaction/restart loses it; operators re-brief constantly.
- **Unmanaged risk** — scope and noise depend on a human remembering, not the system refusing.
- **Unprovable** — "why did the agent do that?" is guesswork; retros are archaeology; client/regulator evidence is thin.
- **Wasted effort** — parallel work re-tests the same targets; credentials lose provenance.
- **Speaker notes:** These map to cost, risk, and trust — the three things that decide adoption. Keep it concrete, no internals yet.
- **Suggested visual:** Four-icon row: lost work · unmanaged risk · unprovable · wasted effort.

## Slide 4 — What Overwatch is (one breath)

- A persistent engine that holds the **whole engagement in a knowledge graph**, drives a **fleet of AI agents** from **one operator cockpit**, and routes **every action** through scope → OPSEC → approval → evidence → audit.
- *One graph · two surfaces · a fleet of agents · audited end-to-end.*
- **Speaker notes:** This is the only "what it is" slide. Don't go deeper than this sentence; the next slides are outcomes.
- **Suggested visual:** Simple diagram — graph in the center, operator + model + dashboard around it, a lock on the action path.

## Slide 5 — Pillar payoffs (the five, as outcomes)

- **One graph, not a prompt** → engagements survive restarts and multi-day work; nothing re-briefed.
- **Guardrails + reasoning** → the system *refuses* out-of-scope/over-noise actions; the model does the creative offense.
- **A fleet, not a chatbot** → parallel coverage without two agents colliding on the same work.
- **Operator in control** → one screen: approve, answer, steer, deploy.
- **Audited end-to-end** → replayable + tamper-evident; "show me exactly what happened" is one click.
- **Speaker notes:** Pillars are in the spine; here they're outcomes, not mechanisms. Pause on "the system refuses" — that's the governance story.
- **Suggested visual:** Five pillars as a single row with a one-word outcome under each (Durable · Safe · Parallel · Controlled · Provable).

## Slide 6 — Where it fits in how we already work

- Sits under the operator, not replacing them — augments the senior pentester running the engagement.
- Works with the tools we use (nmap, nxc, BloodHound/AzureHound, certipy, secretsdump, …); ingests their output; doesn't ask us to rip-and-replace.
- Output is a real deliverable: findings, attack narratives, evidence chains, and a **client-safe** report variant.
- **Speaker notes:** Reduce perceived switching cost. It's an orchestration layer over the existing toolkit, plus governance and a report. Mention `client_safe` as the client-trust angle.
- **Suggested visual:** "Fits in" diagram — existing tools feeding the graph, deliverables coming out.

## Slide 7 — Why this beats "just use AI carefully"

- Careful-by-vigilance doesn't scale and isn't provable. Overwatch makes the safe path the *only* path: actions can't skip scope/OPSEC/approval.
- The audit trail is **reproducible** (same inputs → same result) and **tamper-evident** — the difference between "we think the agent stayed in scope" and "here's the proof."
- **Speaker notes:** This is the governance/assurance slide — likely the one leadership remembers. Tie to client trust and our own risk posture.
- **Suggested visual:** A "receipt" / audit-trail motif — hash-chained log + replay.

## Slide 8 — Honest status: what's real today

- **Real and in use:** the graph engine, the agent fleet, the cockpit, the safety gates, the audit trail, reporting. (See the spine's maturity table.)
- **In progress:** plan-impact preview, richer fleet coordination, a fuller noise dashboard.
- **Roadmap (clearly not yet):** stronger process isolation, parser sandboxing, finding-provenance labels, signed audit checkpoints.
- **Speaker notes:** Say the not-yet items out loud — it buys credibility for the real ones. Do not overclaim; the maturity table in the spine is the script.
- **Suggested visual:** Three-column maturity table: Shipped · In progress · Roadmap.

## Slide 9 — What a pilot looks like

- Pick one upcoming internal engagement (a lab or a low-risk scope). Run it on Overwatch alongside our normal process.
- Success = (a) operators find the cockpit reduces busywork, (b) the audit trail holds up, (c) the deliverable is client-grade.
- Low commitment, reversible, bounded.
- **Speaker notes:** This is the ask — a pilot, not money. Make it small and safe. Name a candidate engagement if you have one.
- **Suggested visual:** A simple 3-step pilot timeline (Pick → Run alongside → Review).

## Slide 10 — The ask

- **Bless a one-engagement pilot** and name an operator champion.
- We bring it back with real findings, the audit trail, and operator feedback.
- **Speaker notes:** Make the yes easy and specific. Offer to run the showcase demo for the wider team next.
- **Suggested visual:** Single bold ask + "next: live demo for the team."

## Slide 11 — Close / one-liner

- *One graph. Two surfaces. A fleet of agents. Audited end-to-end.*
- Contact / where to see it running.
- **Speaker notes:** End on the one-liner; invite them to the showcase.
- **Suggested visual:** The one-liner over the cockpit screenshot.

---

### Q&A primer (anticipated leadership questions)

- *"Is it safe to point AI at live targets?"* — Every action is scope-checked and
  OPSEC-budgeted at validation time and can require approval; out-of-scope fails closed; a
  dead agent's pending action is aborted, never run.
- *"Can we prove what it did?"* — Yes: deterministic replay + tamper-evident hash chain +
  content-addressed evidence; `explain_action` reconstructs any decision.
- *"Does it replace our people?"* — No. It augments the operator; the human approves,
  answers, and steers.
- *"What's the lock-in?"* — It orchestrates the tools we already use and exports portable
  bundles/reports.
