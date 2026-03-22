# Key Concepts

Overwatch uses several domain-specific terms throughout its tools and documentation. This page defines each one.

## Engagement Graph

The core data structure. A **directed property graph** where nodes represent discovered entities (hosts, services, credentials, users) and edges represent relationships between them (`RUNS`, `VALID_ON`, `ADMIN_TO`, etc.). Every tool reads from or writes to this graph.

The graph is powered by [graphology](https://graphology.github.io/) and persisted to disk after every change. See [Graph Model](graph-model.md) for the full schema.

## Frontier Item

A **candidate next action** generated from the graph. The deterministic layer produces frontier items by scanning the graph for:

| Type | Meaning | Example |
|------|---------|---------|
| `incomplete_node` | A node missing expected properties or relationships | Host with no service enumeration |
| `untested_edge` | An edge that exists but hasn't been validated | `POTENTIAL_AUTH` credential → service |
| `inferred_edge` | A hypothesis edge created by an inference rule | `RELAY_TARGET` from SMB signing disabled |

Frontier items include **graph metrics** (hops to objective, fan-out estimate, node degree) but are **not scored** — scoring is the LLM's job. The deterministic layer only filters out items that are out-of-scope, duplicated, or exceed the OPSEC noise ceiling.

Access frontier items via [`next_task`](tools/next-task.md).

## Inference Rules

Deterministic rules that fire automatically when matching nodes are ingested. They generate **hypothesis edges** — low-confidence relationships the LLM should evaluate.

**Lifecycle:**

```
1. Agent reports a finding (new node/edge enters the graph)
2. Engine checks all registered rules against the new node
3. Matching rules produce new edges (confidence 0.3–0.7)
4. New edges become frontier items (type: inferred_edge)
5. LLM sees them via next_task, decides whether to test
6. If tested successfully, confidence is raised to 1.0
```

**Example:** When a service node with `smb_signing: false` is ingested, the "SMB Signing → Relay" rule fires and creates `RELAY_TARGET` edges from all compromised hosts to that service.

Six built-in rules ship with Overwatch. Custom rules can be added at runtime via [`suggest_inference_rule`](tools/suggest-inference-rule.md). See [Architecture](architecture.md#inference-rules) for the full list.

## Confidence

A `0.0` to `1.0` value on every node and edge indicating how certain the information is:

| Range | Meaning | Example |
|-------|---------|---------|
| `0.0 – 0.3` | Hypothesis | Inferred `POTENTIAL_AUTH` edge from credential fanout |
| `0.3 – 0.7` | Likely | Service version from banner grab, unverified credential |
| `0.7 – 0.9` | Strong evidence | Successful authentication attempt |
| `1.0` | Confirmed | Verified admin access, dumped credentials |

Confidence affects frontier item prioritization — lower-confidence edges are more valuable to test because they have the most uncertainty to resolve.

## OPSEC Noise

A `0.0` to `1.0` rating on actions and edge types indicating how likely they are to trigger detection:

| Rating | Level | Examples |
|--------|-------|----------|
| `0.0 – 0.2` | Silent | DNS queries, passive enumeration |
| `0.2 – 0.4` | Quiet | Targeted port scans, LDAP queries |
| `0.4 – 0.6` | Moderate | SMB enumeration, Kerberoasting |
| `0.6 – 0.8` | Loud | Password spraying, brute force |
| `0.8 – 1.0` | Very loud | Mass scanning, exploit attempts |

The engagement's OPSEC profile sets a **`max_noise` ceiling**. Actions exceeding this ceiling are:

- Filtered from the frontier by the deterministic layer
- Rejected by [`validate_action`](tools/validate-action.md)

**Blacklisted techniques** (e.g., `zerologon`) are rejected regardless of noise level.

See [Configuration](configuration.md#opsec-profiles) for profile options.

## Compaction

When the LLM's context window overflows, Claude Code **compacts** — summarizing the conversation history to free up space. This would normally lose engagement state.

Overwatch survives compaction because the graph lives outside the context window. After compaction:

1. Claude Code starts a fresh context
2. The `AGENTS.md` instructions tell it to call `get_state()` first
3. `get_state()` reconstructs a complete briefing from the graph:
    - Scope and objectives
    - All discoveries and access
    - Current frontier items
    - Active agents
    - Recent activity
4. The LLM resumes exactly where it left off

This also works across server restarts, session handoffs, and multi-day engagements.

## Node ID Conventions

Every node needs a unique, deterministic ID. Overwatch uses these conventions:

| Node Type | Pattern | Example |
|-----------|---------|---------|
| Host | `host-<ip>` | `host-10-10-10-5` |
| Service | `svc-<ip>-<port>` | `svc-10-10-10-5-445` |
| Domain | `domain-<name>` | `domain-target-local` |
| User | `user-<domain>-<username>` | `user-target-local-administrator` |
| Group | `group-<domain>-<name>` | `group-target-local-domain-admins` |
| Credential | `cred-<type>-<user>` | `cred-ntlm-administrator` |
| Share | `share-<host>-<name>` | `share-10-10-10-5-c$` |
| Certificate | `cert-<template>` | `cert-user-template` |
| Objective | `obj-<id>` | `obj-da` |

Consistent IDs enable automatic deduplication — reporting the same node twice merges properties instead of creating duplicates.

## Action Lifecycle

Every significant action follows a structured lifecycle for traceability:

```
1. validate_action(description, target, technique)
   → Returns action_id + valid/invalid

2. log_action_event(action_id, event_type="action_started")
   → Records start time in activity log

3. Execute the tool/command (bash, nmap, nxc, etc.)

4. parse_output(tool_name, output, action_id)
   — or —
   report_finding(nodes, edges, action_id)
   → Ingests results into graph

5. log_action_event(action_id, event_type="action_completed")
   — or —
   log_action_event(action_id, event_type="action_failed")
   → Records outcome in activity log
```

The `action_id` links all steps together. This enables:

- **Retrospective analysis** — which actions led to which discoveries
- **RLVR training traces** — state→action→outcome triplets
- **Audit trail** — every graph change is attributable to a specific action

## Deterministic Layer vs LLM Layer

Overwatch splits decision-making into two layers:

**Deterministic layer** (the server) handles:

- Scope enforcement (CIDR/domain matching)
- Deduplication (already-tested edges)
- OPSEC hard vetoes (noise ceiling, blacklisted techniques)
- Dead host pruning
- Inference rule execution
- Graph persistence
- Frontier generation

**LLM layer** (Claude) handles:

- Attack chain spotting across multiple hops
- Sequencing (what should happen before what)
- Risk/reward assessment given defensive posture
- Creative path discovery beyond the frontier
- Tool command construction
- Output interpretation (for unsupported tools)
- Agent dispatch decisions

The deterministic layer is a **guardrail, not a brain**. It filters the obviously impossible. The LLM does the offensive thinking.

## Engagement State vs Graph State

These are related but distinct:

- **Graph state** — the raw graphology graph (nodes, edges, properties). This is what gets persisted to `state-<id>.json`.
- **Engagement state** — the synthesized view returned by `get_state()`. It includes graph summaries, computed frontier items, objective progress, agent status, and recent activity. This is derived from the graph state plus runtime data (active agents, activity log).

Both survive compaction and restarts. The graph state is the source of truth; the engagement state is a computed view of it.
