# Session Lifecycle Monitoring

tags: sessions, oversight, stale, orphaned, live, idle, shepherd, list_sessions, read_session, read-only

## Objective
Read-only oversight of the open interactive sessions: classify each by lifecycle
state and ownership, and flag stale/orphaned ones for the operator. You do NOT run new
target commands or open/close sessions — you observe and report.

## Tools
- `list_sessions` — all sessions with owner agent, target node, last-activity, live flag.
- `read_session` — the recent buffer of a session (what it's doing / last output).
- `query_graph` — resolve a session's owning agent/target to confirm context.

## Lifecycle states (classify each session)
- **live** — owner agent is running and the session has recent activity. Healthy.
- **idle** — owner running but no recent activity. Usually fine; note if long-idle.
- **stale** — no activity past a reasonable window (e.g. > ~15 min) while still open.
  Candidate to close (frees resources, reduces footprint).
- **orphaned** — the owning agent is gone (completed/interrupted/failed) but the
  session is still open. The riskiest: an unowned shell on a target. Flag for the
  operator to close or re-attach.
- **closed** — already closed; report only if recently closed and relevant.

## Methodology

### 1. Enumerate
`list_sessions`. For each, record: id, owner `agent_id`, target node, live flag,
last-activity timestamp.

### 2. Resolve ownership
Cross-check the owner against running agents (`query_graph` / the fleet). An owner not
in the running set ⇒ the session is **orphaned**.

### 3. Peek at activity
For non-live sessions, `read_session` to see the last buffer — is it mid-command, at
a prompt, or hung? This tells the operator whether it's safe to close or worth
re-attaching.

### 4. Report, don't act
Produce a per-session rollup: state + owner + target + a one-line "what it's doing /
recommendation" (close stale, escalate orphaned, leave live). Surface orphaned/stale
ones prominently.

## Escalation / done
- **Flag for the operator**: every orphaned session (unowned shell on a target), and
  any stale session on a sensitive target.
- **Done** when each open session's state and ownership is reported, with stale/orphaned
  ones flagged. You never close/signal sessions yourself — recommend it.

## Anti-patterns
- Running new commands in a session "to check" — read-only means `read_session` only.
- Closing or signaling sessions (that's an operator decision you surface).
- Reporting raw buffers without the state/ownership classification.
