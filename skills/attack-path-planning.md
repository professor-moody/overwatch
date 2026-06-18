# Attack Path Planning

tags: pathfinding, attack-path, planning, prioritization, propose_plan, objectives, next-hop, read-only

## Objective
Read-only analysis: find the highest-value next hops toward the engagement
objectives and the gaps blocking progress, then surface them as a **proposed
plan** the operator confirms. You PROPOSE; the operator CONFIRMS; the dashboard
EXECUTES. You never run target-facing tools or mutate the graph.

## Tools
- `query_graph` — explore the current node/edge state and what's already known.
- `find_paths({ objective_id | from_node, to_node, optimize })` — the shortest
  routes to an objective (`optimize: confidence | stealth | balanced`).
- `get_agent_context` — your scoped subgraph + the objectives in play.
- `propose_plan({ agent_id, task_id, summary, rationale, ops })` — submit the plan.

## Methodology

### 1. Enumerate the objectives
List the unachieved objectives (`get_agent_context` / `query_graph` for
`type: objective`, `achieved: false`). Plan toward those — not toward
interesting-but-irrelevant nodes.

### 2. Find candidate paths
For each objective, call `find_paths` with `optimize: balanced` first, then
`stealth` to see the quiet alternative. A path is a sequence of edges
(e.g. `cred → VALID_ON → service → RUNS → host → ADMIN_TO → DC`).

### 3. Score the next hops
Rank candidate hops by, in priority order:
1. **Chain completion** — a hop that finishes a 2-of-3 chain beats an isolated edge.
2. **Hops-to-objective** — fewer remaining hops is higher value.
3. **Confidence** — confirmed edges over inferred ones; flag inferred hops that
   need validation as the *gap*, not the *plan*.
4. **Access tier** — a hop that yields higher privilege (user → admin → DA) compounds.
5. **Noise / stealth** — when two hops are otherwise equal, prefer the quieter one.

### 4. Name the blocking gaps
For the top path, state what's *missing* to take the next hop: an unvalidated
credential, an untested edge, a missing scope expansion, an un-enumerated host.
The gap is often more actionable than the hop.

### 5. Propose, don't execute
Submit ONE `propose_plan` with: the top 1–3 next hops, a one-line rationale per
hop (which objective it advances + why now), and the concrete `ops` the operator
would confirm. Reference only real `task_id`/`action_id`/node ids that exist in
the graph.

## Escalation / done
- **Ask the operator** (via the plan's rationale, not `ask_operator`) when the
  best path depends on an out-of-scope pivot or a destructive technique — surface
  it as a choice, don't assume.
- **Done** when a plan of the highest-value next hops is submitted via
  `propose_plan`, OR the transcript explains why no viable path to any objective
  exists yet (and what discovery would unblock one).

## Anti-patterns
- Proposing every reachable edge — rank and cut to the few that matter.
- Proposing a hop that depends on an inferred edge without flagging the
  validation step as a prerequisite.
- Executing or mutating anything — you are strictly read-only + propose.
