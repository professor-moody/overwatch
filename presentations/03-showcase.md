---
deck: Overwatch — Live Showcase
audience: Mixed but engaged internal room (brown-bag / show-and-tell)
goal: Show it working. Demo-forward, theory-light. Each scene is a thing you DO on screen.
length: ~12 scenes, ~20–25 min live
tone: Narrated demo. Confidence + a little flair. Honest if something is seeded/recorded.
source_of_truth: ./00-message-spine.md
format_note: >
  This is a demo SCRIPT, not slides. Each scene = Goal · Do (what to click/say) · Wow
  (the payoff to call out) · Fallback (if live fails). Run against the seeded demo
  dashboard (npm run demo:dashboard, :8384) so the data is rich and deterministic.
---

# Overwatch — Live Showcase (demo script)

> Presenter: open on the cockpit already loaded with the seeded engagement. Keep narration
> tied to what's on screen. If the network is risky, screen-record the whole run beforehand
> and narrate over it — say so; it's still honest.

---

## Scene 0 — Cold open (15 sec)

- **Goal:** Orient the room before any clicking.
- **Do:** "This is one screen running a whole offensive engagement. A map of the target, a
  team of AI agents working it, and me in control. Watch."
- **Wow:** The full cockpit — graph + fleet + "Needs you" — in one view.
- **Fallback:** Static screenshot.

## Scene 1 — The living map

- **Goal:** Establish the graph as the source of truth.
- **Do:** Pan/zoom the graph explorer. Point at hosts, a credential node, a domain, an
  objective. Hover an edge to show the relationship.
- **Wow:** "Everything the agents learn lands here — and it survives restarts; the AI's
  memory isn't trapped in a chat window."
- **Fallback:** Static graph image with callouts.

## Scene 2 — Deploy the fleet

- **Goal:** Show parallel, typed agents.
- **Do:** From the command bar (or Deploy), launch a couple of agents — e.g. a recon
  scanner on a CIDR and a web tester on a found webapp.
- **Wow:** Multiple agents spin up at once; each is a *type* with its own tool surface
  (recon can't pop shells; CVE research can't touch the target).
- **Fallback:** Show the fleet roster pre-populated.

## Scene 3 — The fleet board, live

- **Goal:** "Where is the work, per campaign?" at a glance.
- **Do:** Open the Campaigns → Board toggle. Narrate the swimlanes: Planned → Running →
  Needs You → Produced Finding → Completed.
- **Wow:** As an agent finds something, a card jumps lanes and the graph pulses.
- **Fallback:** Board screenshot with lanes labeled.

## Scene 4 — Ask it in plain English

- **Goal:** The natural-language command bar.
- **Do:** Type `what changed in the last 15 minutes?` then `pause the apache agent`.
- **Wow:** Recognized commands resolve instantly; anything open-ended becomes a *planner*
  sub-agent that proposes a confirmable plan — you approve before anything runs.
- **Fallback:** Pre-typed command + its result.

## Scene 5 — "Needs you": approve a risky step

- **Goal:** Human-in-the-loop, enforced.
- **Do:** An agent's risky action is waiting in "Needs you". Read it, Approve (or Deny with
  a reason) inline.
- **Wow:** The blocked agent **resumes the instant you approve** — dashboard and agent are
  one engine. Mention: ignore it too long and it auto-fires *loudly* (tagged
  `unattended_execute`), never silently.
- **Fallback:** Show the approval card + explain the round-trip.

## Scene 6 — Stuck-agent detection

- **Goal:** The system notices "alive but idle."
- **Do:** Point at a `stuck` item in "Needs you" — heartbeating but no progress for >8 min.
  Click View → Pause/Stop, then re-deploy a fresh agent at the same work.
- **Wow:** "A normal watchdog only catches *dead* agents. Overwatch catches the *idle* ones
  too — burning a slot doing nothing." The freed claim lets a new agent take over cleanly.
- **Fallback:** Screenshot of the stuck item.

## Scene 7 — Answer once, fan out

- **Goal:** Question clustering.
- **Do:** Show a clustered question ("3 agents asking the same thing"); answer it once.
- **Wow:** One answer fans out to every asking agent — no repeating yourself.
- **Fallback:** Screenshot of the clustered card.

## Scene 8 — Follow the attack path

- **Goal:** The graph as an analysis tool.
- **Do:** Double-click a compromised host to focus its 2-hop neighborhood. Shift-click it
  and the objective to highlight the shortest path (host → DC → objective).
- **Wow:** The path lights up with hop count; color-coded edges show *how* (lateral move,
  credential, ADCS, etc.).
- **Fallback:** Pre-rendered path screenshot.

## Scene 9 — Turn one credential into a recon plan

- **Goal:** Credential playbooks.
- **Do:** On a captured cloud credential, run `expand_aws_credential` (or the GitHub/Entra
  variant).
- **Wow:** It returns a numbered, step-by-step recon plan; run it through the approval gate
  and watch S3 buckets / IAM roles / Lambdas surface on the graph.
- **Fallback:** Show the returned plan + a before/after graph.

## Scene 10 — Prove it: the evidence chain

- **Goal:** Provenance + audit.
- **Do:** Click a credential node's derivation chain: dumped-from → cracked-from →
  tested-against. Then click an action and hit `explain_action`.
- **Wow:** Every link jumps to the evidence/action that produced it; `explain_action` walks
  the full decision — frontier item → reasoning → alternatives → validation → approval →
  outcome. "Why did we do X?" answered, not guessed.
- **Fallback:** Screenshot of the chain + an explain panel.

## Scene 11 — OPSEC budget says no

- **Goal:** Enforcement, not vigilance.
- **Do:** In a "quiet" phase, attempt a loud action (mass spray). Validation rejects it:
  "exceeds the phase noise ceiling."
- **Wow:** The system *refuses* — the safe path is the only path. Override is possible but
  explicit and logged.
- **Fallback:** Show the rejection message.

## Scene 12 — Re-parse + the deliverable

- **Goal:** Analyst control + output.
- **Do:** In Analysis, re-parse a stored nmap blob with a different parser; preview the new
  nodes/edges; Promote. Then Generate Report → toggle `client_safe`.
- **Wow:** Re-parsing merges (never duplicates); the report comes in operator-internal and
  **client-safe** variants from the same findings — secrets stripped automatically.
- **Fallback:** Show a generated report + the client-safe diff.

## Closing (20 sec)

- **Say:** "One graph. A coordinated fleet. A human in control. And a tamper-evident record
  of every step. That's Overwatch."
- **Wow:** Return to the full-cockpit view.
- **Fallback:** The one-liner slide.

---

### Demo logistics checklist

- Run the seeded demo dashboard fresh (verify it's not stale — restart if the data looks
  degenerate, e.g. every agent "idle 1000m").
- Have a recorded backup of the full run.
- Pre-stage the two or three commands you'll type (avoid live typos).
- Know which moments are seeded vs live and say so — honesty reads as confidence.
- Keep a host/credential/objective you know the path between, for Scene 8.
