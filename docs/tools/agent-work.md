# Agent work shaping

These four tools make future agent work explicit without rewriting historical
ownership. They share the same durable application-command service as the HTTP
and dashboard adapters.

## `find_duplicate_agent_work`

Operator/orchestrator-only and read-only. Returns groups whose server-derived work signatures match exactly,
including node scope, frontier/campaign linkage, archetype, role, skill, and
normalized objective. The response identifies a recommended canonical task but
does not mutate any task.

## `handoff_agent_work`

Creates one successor for a terminal task. The source must first be cancelled or
otherwise finished, and its processes, sessions, playbook attempts, approvals,
open plans, questions (including answered but unacknowledged answers), and directives must have settled. The successor receives a durable
lineage relation plus the operator's summary and optional key finding, evidence,
and event references.

If the source frontier item is still actionable, the successor safely reacquires
it. Otherwise the successor becomes node-scoped and the response includes
`frontier_not_reacquired`; a source with neither an actionable frontier nor node
scope is rejected.

Campaign attribution is retained only when the same item is still pending and
actionable in an active leaf campaign. A stale or terminal item falls back to
node scope with `campaign_not_reacquired`; inactive or parent campaigns require
explicit operator lifecycle handling before handoff.

Required parameters are `source_task_id`, `archetype`, `objective`, and
`summary`. Optional parameters are `agent_label`, `skill`, `model`,
`key_finding_ids`, `key_evidence_ids`, and `key_event_ids`.

## `split_agent_work`

Splits one terminal, ad-hoc node task into 2–20 child tasks. Every child specifies
an archetype, objective, and non-empty `target_node_ids`. Child scopes must be
pairwise disjoint and their union must equal the source scope exactly. The
source remains in the roster as a non-retryable lineage record.

Frontier- and campaign-linked sources are rejected in this release. Use a single
handoff for those tasks so a split cannot duplicate a frontier lease or campaign
assignment.

## `merge_duplicate_agent_work`

Marks 1–32 terminal exact duplicates as merged into one canonical task. Every
duplicate must have the canonical task's exact work signature and no live-owned
resources. The task records and all historical findings, evidence, transcripts,
sessions, approvals, and process attribution remain intact.

Required parameters are `canonical_task_id`, `duplicate_task_ids`, and
`summary`.

## Retry metadata

All three mutation tools accept optional `command_id`, `idempotency_key`, and
`retry_token`. Successful responses return all three durable identities plus
`replayed`. Reusing an idempotency key with the identical command returns the
original result; using it for different input fails closed.

Work inspection and shaping are operator-owned. The primary MCP session,
dashboard, and CLI may use these commands concurrently through shared
idempotent receipts; a scoped worker token cannot inspect duplicates, create
successors, split work, or merge other agents' work. An Overwatch orchestrator
task is the only agent-task exception.

Every lineage participant is retained in the roster: sources, successors,
merged sources, canonical tasks, and roots cannot be dismissed while their
lineage references exist.

## Safe operator sequence

1. Cancel or complete the source/duplicate task.
2. Wait until its runtime ownership is settled.
3. Inspect exact duplicates when merging.
4. Call handoff, split, or merge with a stable idempotency key.
5. The returned tasks are already registered and pending; use their IDs to
   monitor or steer them.
