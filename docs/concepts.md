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
| `network_discovery` | CIDR scope with undiscovered hosts | Network sweep of 10.10.10.0/24 |
| `network_pivot` | Host reachable via pivot but without a session | Host in same subnet as session-holder |

Frontier items include **graph metrics** (hops to objective, fan-out estimate, node degree) but are **not scored** — scoring is the LLM's job. The deterministic layer only filters out items that are out-of-scope, duplicated, or exceed the OPSEC noise ceiling.

Access frontier items via [`next_task`](tools/next-task.md).

## Inference Rules

Deterministic rules that fire automatically when matching nodes are ingested. They generate **hypothesis edges** — low-confidence relationships the LLM should evaluate.

![Inference Lifecycle](assets/inference-lifecycle-light.svg#only-light)
![Inference Lifecycle](assets/inference-lifecycle-dark.svg#only-dark)

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

Fifty-five built-in rules ship with Overwatch across five domains: AD & service (21), ADCS (14), Linux privilege escalation (7), web application (8), MSSQL (2), and cloud infrastructure (3). This includes **edge-triggered rules** that require both a node property match and a matching inbound edge (e.g., LAPS readable requires `laps: true` + inbound `GENERIC_ALL`). When a new edge arrives, the engine re-evaluates inference on its endpoints.

Custom rules can be added at runtime via [`suggest_inference_rule`](tools/suggest-inference-rule.md). See [Graph Model — Inference Rules](graph-model.md#inference-rules) for the full rule reference with triggers and productions.

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

![Compaction Persistence](assets/compaction-persistence-light.svg#only-light)
![Compaction Persistence](assets/compaction-persistence-dark.svg#only-dark)

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

**Startup Reconciliation:** On restart, the engine automatically reconciles runtime-dependent state:
- **HAS_SESSION edges** are downgraded from `session_live=true` to `session_live=false` since no runtime sessions survive a restart.
- **Running agents** are marked as `interrupted` since the sub-agent processes no longer exist.
- **Tracked processes** are checked for PID liveness; dead PIDs are marked as completed.

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

4. parse_output(tool_name, output, action_id, ...)
   — or —
   report_finding(nodes, edges, action_id, ...)
   → Ingests results into graph (action_id and agent_id are optional)

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

![Hybrid Scoring](assets/hybrid-scoring-light.svg#only-light)
![Hybrid Scoring](assets/hybrid-scoring-dark.svg#only-dark)

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

## Credential Lifecycle

Credentials in Overwatch have a **lifecycle** tracked via the `credential_status` property:

| Status | Meaning |
|--------|----------|
| `active` | Credential is current and usable |
| `stale` | Credential may still work but hasn't been verified recently |
| `expired` | Credential has passed its `valid_until` time |
| `rotated` | Credential has been observed as changed |

The engine automatically:

- **Degrades** outbound `POTENTIAL_AUTH` edges from stale/expired credentials (confidence × 0.5)
- **Deprioritizes** frontier items sourced from stale/expired credentials (confidence × 0.1)
- **Tracks derivation chains** via `DERIVED_FROM` edges (e.g., hash → cracked password)
- **Infers credential domains** from graph topology when not explicitly provided

### Credential Expiry Estimation

The engine estimates credential expiry automatically based on credential type and domain policy:

| Credential Type | Default Lifetime | Policy Override |
|----------------|------------------|-----------------|
| `kerberos_tgt` | 10 hours | Domain `password_policy.maxAge` |
| `kerberos_tgs` | 10 hours | — |
| `token` | 1 hour | — |
| Password types | Domain policy `maxAge` | Requires `pwd_last_set` on the owning user |

When a domain has a `password_policy` with `maxAge` set and the associated user has `pwd_last_set`, the engine computes password expiry as `pwd_last_set + maxAge`. This feeds into graduated frontier scoring:

| Time Remaining | Frontier Score Multiplier |
|---------------|--------------------------|
| < 30 minutes | 0.3× (urgent — use it or lose it) |
| < 2 hours | 0.7× (expiring soon) |
| > 2 hours | 1.0× (healthy) |
| Stale/expired | 0.1× (deprioritized) |

The chain scorer similarly applies graduated quality points: healthy credentials score 3 points, expiring (<2h) score 2, near-expiry (<30min) score 1.

### Credential Provenance

The `getCredentialProvenance()` function traces a credential's full provenance chain by walking `DERIVED_FROM` and `DUMPED_FROM` edges. This enables:

- Identifying the original source of a cracked hash
- Tracing which host a credential was dumped from
- Understanding multi-hop derivation (e.g., NTDS dump → hash → cracked password → TGT)

The dashboard visualizes provenance chains via the `/api/evidence-chains/:nodeId` endpoint.

See [Graph Model — Credential Lifecycle Properties](graph-model.md#credential-lifecycle-properties) for the full property reference.

## IAM Policy Simulation

Overwatch includes a cloud IAM policy simulator (`evaluateIAM()`) that evaluates whether an identity is permitted to perform an action on a resource. The simulator understands the permission evaluation semantics of all three major cloud providers:

| Provider | Evaluation Logic |
|----------|-----------------|
| **AWS** | Deny-overrides-allow — explicit deny in any policy wins. Evaluates all attached policies, then checks for matching allow. |
| **Azure** | RBAC scope hierarchy — permissions at broader scopes (`/subscriptions/...`) inherit to child resources. Role assignments are evaluated against scope prefixes. |
| **GCP** | Deny policy precedence — deny policies are evaluated first, then allow. Supports wildcard action matching. |

The simulator traverses the graph to collect all policies reachable from an identity (including via group memberships and role assumptions), then evaluates them against the requested action and resource.

**Usage:** The IAM simulator is used internally by graph analysis tools and is accessible via the evidence chain API. It helps answer questions like "Can this service account delete S3 buckets?" or "Does this Azure role assignment cover this resource?"

## Web Attack Path Modeling

Overwatch models web application attack surfaces using three graph constructs:

1. **`api_endpoint` nodes** — represent individual API endpoints with `path`, `method`, `auth_required`, and `response_type` properties. Connected to their parent webapp via `HAS_ENDPOINT` edges.

2. **`AUTH_BYPASS` edges** — from a `vulnerability` node to a `webapp` or `api_endpoint` when the vulnerability enables authentication bypass. This is a bidirectional edge type — the engine considers both directions for path traversal.

3. **Inference rules** — Two rules automate web attack path discovery:
    - **Token → Webapp Auth** — When a credential with `cred_type=token` exists and a webapp has an `AUTHENTICATED_AS` edge, creates a `VALID_ON` edge (confidence 0.75)
    - **Auth Bypass Escalation** — When a vulnerability has an `AUTH_BYPASS` edge to a webapp, creates an `EXPLOITS` edge to the parent host (confidence 0.8)

Four inference selectors support web attack path rules: `default_credential_candidates`, `cms_credentials`, `hosted_webapps`, and `vulnerable_webapps`.

See [Graph Model — Web Application Surface](graph-model.md#web-application-surface) for edge definitions and [Graph Model — Inference Rules](graph-model.md#inference-rules) for the full rule reference.

## Identity Resolution

Overwatch automatically resolves node identities on ingest to prevent duplicates and merge fragmented data:

1. **Canonical ID generation** — Each node type has deterministic ID rules (e.g., `host-<ip>`, `user-<domain>-<username>`)
2. **Identity markers** — Nodes carry markers for matching: hostname variants, SIDs, domain-qualified names, credential fingerprints
3. **Alias merging** — When a canonical node is added and an existing node shares its identity markers, the weaker node is merged into the canonical one — edges are retargeted, properties merged
4. **Provenance preservation** — Merged nodes retain `first_seen_at`, `sources`, and discovery metadata from both originals

This handles the real-world messiness of BloodHound SIDs, manual findings, and parser outputs colliding on the same entity. Nodes can be `canonical` (primary), `unresolved` (ambiguous), or `superseded` (merged into another).

## Sessions

Overwatch maintains **persistent interactive sessions** — long-lived bidirectional I/O channels that survive across MCP tool calls. Sessions support SSH, local PTY, and TCP socket transports (for reverse shells and listeners).

### I/O Model

The core primitives are `write_session` (raw bytes) and `read_session` (cursor-based). Each session has a 128KB ring buffer with absolute monotonic positions. Agents track `end_pos` from each read and pass it as `from_pos` on the next to get only new output.

`send_to_session` is an experimental convenience tool that writes a command, waits for output to settle (idle timeout or regex match), and returns the captured output in one call.

### TTY Quality

Sessions track their terminal capability via `tty_quality`:

| Level | Description | Example |
|-------|-------------|---------|
| `none` | No terminal | Non-interactive exec |
| `dumb` | Raw I/O only | Raw reverse shell |
| `partial` | Line editing | After `python3 -c 'import pty; ...'` |
| `full` | Full PTY | SSH, local shell, fully upgraded shell |

Quality can be upgraded at runtime via `update_session` after a shell upgrade.

### Ownership

Sessions have a `claimed_by` field (agent ID). When set, only the claiming agent can write or control the session. Any agent can read. Use `update_session` to transfer ownership or `force: true` to override. Unclaimed sessions are open to all.

### Lifecycle

Sessions follow this state machine:

```
pending → connected → closed
                   → error
```

Socket sessions (reverse shells, listeners) start in `pending` and transition to `connected` when a connection is established. PTY and SSH sessions connect immediately. Sessions are ephemeral across server restarts — PTY file descriptors cannot be serialized.

See [Session Tools](tools/sessions.md) for the full API reference.

## Graph Compaction (Cold Store)

During large network sweeps, hundreds of hosts may respond to ping without offering any services. To keep the **hot graph** focused on actionable targets, Overwatch uses a **cold store** — an in-memory census that tracks these low-interest hosts outside the main graphology graph.

### Temperature Classification

Every host ingested into the graph is classified as **hot** or **cold**:

| Condition | Temperature | Reason |
|-----------|-------------|--------|
| Non-host node type | Hot | Always — services, users, credentials, etc. need full graph participation |
| Host with `alive !== true` | Hot | Dead or unconfirmed hosts need scope tracking |
| Host with hostname or OS | Hot | Identity-bearing — needed for reconciliation |
| Host with interesting edges | Hot | HAS_SESSION, ADMIN_TO, RUNS, HOSTS, etc. |
| Alive IP-only host, no services | **Cold** | Pure ping response — census only |

### Promotion

Cold nodes are **promoted** to the hot graph automatically when:

- A new edge references them (edge promotion guard)
- A later finding adds services, hostname, or OS
- A pivot session makes them reachable (pivot reachability inference)
- A scope expansion brings them into scope (`update_scope`)

Promotion is **one-way** — hot nodes are never demoted back to cold. This avoids cache invalidation complexity.

### Visibility

`get_state()` includes `cold_node_count` and `cold_nodes_by_subnet` (top 5) in the graph summary, giving the LLM awareness of the census without cluttering the frontier.

## Engagement State vs Graph State

These are related but distinct:

- **Graph state** — the raw graphology graph (nodes, edges, properties). This is what gets persisted to `state-<id>.json`.
- **Engagement state** — the synthesized view returned by `get_state()`. It includes graph summaries, computed frontier items, objective progress, agent status, and recent activity. This is derived from the graph state plus runtime data (active agents, activity log).

Both survive compaction and restarts. The graph state is the source of truth; the engagement state is a computed view of it.
