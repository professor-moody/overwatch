# OPSEC & Defensive Signals

tags: opsec, noise, defensive-signals, lockout, rate-limit, honeypot, detection, budget, read-only, escalation

## Objective
Read-only monitoring: assess the engagement's OPSEC posture — how much of the noise
budget is spent, what defensive signals have fired, and the safest approach right now
— and flag risk for the operator. You never execute against targets or mutate the graph.

## Tools
- `get_opsec_status` — noise budget spent/remaining, recommended approach
  (quiet/normal/loud), recent defensive signals, time-window state.
- `query_graph` — correlate signals to the hosts/domains/credentials that triggered them.

## Defensive-signal taxonomy (interpret, don't just list)
Weight signals by how strongly they indicate the defender is watching:

| Signal | Meaning | Weight |
|---|---|---|
| `honeypot` | interacted with a decoy asset | **highest** — stop + escalate |
| `lockout` | account lockout from spraying | high — back off that identity |
| `block` | IP/host block / WAF deny | high — path is burned |
| `rate_limit` | throttling | medium — slow down, not stop |
| `connection_reset` | resets mid-op | low–medium — could be benign |

Three or more recent signals (any kind) ⇒ treat the environment as alert; recommend
`quiet`.

## Methodology

### 1. Read the posture
Call `get_opsec_status`. Note: `noise_budget_remaining` vs `max_noise`,
`recommended_approach`, and the recent `defensive_signals`.

### 2. Classify the budget
- `> 60%` remaining → `loud` actions tolerable.
- `30–60%` → `normal`; prefer quieter techniques.
- `< 30%` → `quiet` only; passive/zero-noise work.
- `<= 0` → budget exhausted; only passive actions, recommend pausing target-facing work.

### 3. Correlate signals to assets
For each defensive signal, identify the host/domain/credential involved
(`query_graph`) so the operator knows *what* to back off from, not just *that*
something fired.

### 4. Report posture + risk
Summarize: budget %, recommended approach, active signals (with the asset each
implicates), and the single most important action ("stop spraying svc-x: 2 lockouts"
/ "budget at 12% — pause loud scans").

## Escalation thresholds — flag for the operator when ANY of:
- a `honeypot` interaction (immediate, highest priority),
- ≥ 3 recent defensive signals,
- noise budget < 15% remaining,
- a single host/domain consuming > 50% of the global budget.

## Escalation / done
- **Done** when the current OPSEC posture and any risk (budget near exhaustion,
  active defensive signals, hot assets) is reported as a finding/note for the operator.

## Anti-patterns
- Listing signals without interpreting weight or naming the implicated asset.
- Recommending `loud` purely on remaining budget while defensive signals are active.
- Running any target-facing tool — you are strictly read-only.
