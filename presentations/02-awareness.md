---
deck: Overwatch — What Is This Thing?
audience: Broad internal audience (adjacent teams, non-practitioners, new hires)
goal: Plain-language understanding of what Overwatch is and what it can do — awareness, not adoption.
length: ~9 slides, ~10 min
tone: Accessible, story-first, minimal acronyms. Explain every security term in one clause.
source_of_truth: ./00-message-spine.md
---

# Overwatch — What Is This Thing?

> For the presenter: assume the room knows we do security testing but not the internals.
> Use metaphors (mission control, a graph of the network). Never assume jargon.

---

## Slide 1 — Title

- **Overwatch** — mission control for AI-assisted security testing.
- **Speaker notes:** One sentence of context: our team simulates attackers to find weaknesses before real ones do ("penetration testing"). This is the tool that runs that work when AI does some of the legwork.
- **Suggested visual:** The cockpit screenshot; title overlaid.

## Slide 2 — Picture the job

- A security engagement = map a network, find weak spots, chain them into a path to something valuable, and write it all up — carefully, in scope, without being noisy.
- It's a lot of moving parts, often over days.
- **Speaker notes:** Ground the audience in what the work actually is before introducing the tool. Keep it relatable.
- **Suggested visual:** Simple illustration: laptops/hosts → a path → a "crown jewel."

## Slide 3 — Now add AI… and the catch

- AI can do a lot of that legwork. But if the AI just "remembers" everything in a chat, that memory gets wiped on a restart, nobody else can see it, and you can't prove afterward what it did.
- **Speaker notes:** This is the "why a tool exists" beat. Use the chat-window-amnesia metaphor — everyone gets it.
- **Suggested visual:** A chat bubble with a "memory wiped" symbol.

## Slide 4 — The big idea: a living map

- Overwatch keeps everything the AI learns on a **living map** (a graph) — every machine, account, password, and the connections between them — that lives *outside* the chat and never forgets.
- The AI reads the map to decide what to do next; new discoveries land back on the map instantly.
- **Speaker notes:** "Graph" = dots (things) connected by lines (relationships). This is the single most important concept; spend a moment here.
- **Suggested visual:** A small animated-feel node-and-edge graph (hosts, a credential, an arrow to a "domain admin").

## Slide 5 — A team of helpers, not one chatbot

- Instead of one AI doing everything in sequence, Overwatch runs **a small team of specialized AI agents** at once — one scanning, one probing a website, one researching known vulnerabilities — all updating the same map.
- They can't trip over each other (the system hands out "claims" so two agents never do the same job).
- **Speaker notes:** Emphasize parallel + coordinated. The "claim/lease" idea prevents duplicate work — a relatable office metaphor (you don't both take the same ticket).
- **Suggested visual:** 3–4 little agent avatars feeding one shared map.

## Slide 6 — A human is always at the controls

- A person — the operator — watches it all from one screen and is asked to weigh in when it matters: *"Approve this risky step?"* *"Which way should I go?"*
- One queue shows everything that needs a human: approvals, questions, and agents that got stuck.
- **Speaker notes:** This is the trust/safety beat for a general audience: a human is in the loop, the tool surfaces decisions rather than acting unilaterally.
- **Suggested visual:** The "Needs you" queue with an Approve/Deny and an agent question.

## Slide 7 — It stays in bounds — by design

- Every action is checked before it runs: *is this target in scope? is it too "loud"? does it need sign-off?* If it breaks the rules, the system refuses — it doesn't rely on someone remembering.
- And everything is recorded in a way that can't be quietly edited later, so we can always show exactly what happened.
- **Speaker notes:** "Loud" = likely to trip alarms; staying quiet matters in real assessments. The tamper-evident record is the accountability story.
- **Suggested visual:** A gate/checkpoint icon + a "receipt" icon.

## Slide 8 — What it produces

- Live picture while it runs (the map, the activity feed, progress per task).
- At the end: a real report — what was found, how an attacker could chain it, the evidence — including a **client-safe** version with the sensitive bits stripped out.
- **Speaker notes:** Close the loop: it's not just a live toy, it produces the deliverable the client/stakeholder actually gets.
- **Suggested visual:** Report cover + a findings list.

## Slide 9 — In one line + where to learn more

- *Overwatch keeps the whole engagement on one living map, runs a coordinated team of AI agents on it, keeps a human in control, and proves exactly what happened.*
- See the live demo / read the docs / talk to the team.
- **Speaker notes:** Invite them to the showcase. Offer the docs link for the curious.
- **Suggested visual:** One-liner over the cockpit; pointers to demo + docs.

---

### Glossary (presenter cheat-sheet — define on the fly if asked)

- **Engagement** — an authorized security test of a defined target.
- **Graph** — dots (things) and lines (relationships); here: the network's attack surface.
- **Agent** — an AI worker doing one scoped job.
- **In scope** — the targets we're allowed to touch.
- **OPSEC / "loud"** — how likely an action is to be noticed by defenders.
- **Approval gate** — a step that pauses for a human yes/no before running.
