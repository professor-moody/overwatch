# Overwatch — Architecture & Codebase Review

> Offensive security engagement orchestrator — MCP server with graph-based state management

## Executive Summary

Overwatch is an MCP (Model Context Protocol) server that acts as the persistent state layer and reasoning substrate for LLM-powered penetration testing. Rather than stuffing engagement state into prompts, the LLM calls into a **persistent graph engine** that tracks every discovery, relationship, and hypothesis. After context compaction, a single `get_state()` call reconstructs a complete operational briefing with zero information loss.

The server exposes **25 MCP tools** covering the full engagement lifecycle — from initial reconnaissance through post-engagement retrospective analysis. A **directed property graph** (built on graphology) models the attack surface: hosts, services, credentials, users, groups, AD objects, and their relationships. An inference engine generates hypothetical edges, a frontier computer prioritizes next actions, and a path analyzer finds shortest routes to objectives.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    MCP Orchestrator Server                        │
│                                                                  │
│  ┌──────────────┐  ┌───────────────┐  ┌────────────────────┐    │
│  │ GraphEngine   │  │ Inference     │  │ FrontierComputer   │    │
│  │ (graphology)  │  │ Engine        │  │ (next actions)     │    │
│  └──────┬───────┘  └───────┬───────┘  └────────┬───────────┘    │
│         │                  │                    │                │
│  ┌──────▼──────────────────▼────────────────────▼────────────┐  │
│  │                 EngineContext (shared state)                │  │
│  └──────┬──────────────────┬────────────────────┬────────────┘  │
│         │                  │                    │                │
│  ┌──────▼───────┐  ┌──────▼───────┐  ┌────────▼───────────┐   │
│  │ Path         │  │ Identity     │  │ State              │   │
│  │ Analyzer     │  │ Resolution   │  │ Persistence        │   │
│  └──────────────┘  └──────────────┘  └────────────────────┘   │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              25 MCP Tools (Zod-validated)                  │  │
│  │  state · findings · scoring · exploration · agents ·       │  │
│  │  logging · parsing · bloodhound · inference · remediation  │  │
│  │  skills · toolcheck · processes · retrospective            │  │
│  └──────────────────────────┬────────────────────────────────┘  │
│                              │                                   │
│  ┌───────────────────────────▼───────────────────────────────┐  │
│  │  Dashboard Server (HTTP + WebSocket, port 8384)            │  │
│  │  sigma.js WebGL graph · real-time delta broadcast          │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────────────────────────────────┬───────────────────────────────┘
                                   │ stdio
              ┌────────────────────▼────────────────────┐
              │       LLM Operator (Claude/Opus)         │
              │    Primary Session + Sub-Agents          │
              └─────────────────────────────────────────┘
```

### Design Principles

- **Graph-as-memory** — All engagement state lives in the graph. After context compaction, `get_state()` reconstructs everything. No information loss across sessions.
- **Deterministic guardrails, LLM reasoning** — Scope checks, deduplication, and OPSEC vetoes are enforced deterministically. The LLM handles attack chain reasoning, scoring, and sequencing.
- **Report early, report often** — Every `report_finding()` triggers inference rules → new frontier items → reactive re-planning.
- **Identity resolution** — Nodes are canonicalized on ingest. BloodHound SIDs, hostname variants, and credential fingerprints are merged automatically.

---

## Graph Model

### Node Types (15)

| Type | Description |
|------|-------------|
| `host` | Network host (IP, hostname, OS) |
| `service` | Running service (port, protocol, version) |
| `domain` | Active Directory domain |
| `user` | Domain or local user account |
| `group` | AD security group |
| `credential` | Authentication material (password, hash, ticket, cert) |
| `share` | Network share (SMB, NFS) |
| `certificate` | X.509 certificate |
| `ca` | Certificate authority |
| `cert_template` | AD CS certificate template |
| `pki_store` | PKI store (NTAuth, issuance policy) |
| `gpo` | Group Policy Object |
| `ou` | Organizational Unit / container |
| `subnet` | Network subnet |
| `objective` | Engagement objective (virtual node) |

### Edge Types (37)

Relationship types include: `REACHABLE`, `RUNS`, `MEMBER_OF`, `MEMBER_OF_DOMAIN`, `ADMIN_TO`, `HAS_SESSION`, `CAN_RDPINTO`, `CAN_PSREMOTE`, `CAN_DCSYNC`, `OWNS_CRED`, `VALID_ON`, `DERIVED_FROM`, `DUMPED_FROM`, `DELEGATES_TO`, `WRITEABLE_BY`, `GENERIC_ALL`, `GENERIC_WRITE`, `WRITE_OWNER`, `WRITE_DACL`, `ADD_MEMBER`, `FORCE_CHANGE_PASSWORD`, `ALLOWED_TO_ACT`, `CAN_ENROLL`, `ESC1`–`ESC8`, `TRUSTS`, `SAME_DOMAIN`, `AS_REP_ROASTABLE`, `KERBEROASTABLE`, `CAN_DELEGATE_TO`, `CAN_READ_LAPS`, `CAN_READ_GMSA`, `RBCD_TARGET`, `RELAY_TARGET`, `NULL_SESSION`, `POTENTIAL_AUTH`, `PATH_TO_OBJECTIVE`, and `RELATED`.

All edges carry `confidence`, `discovered_at`, `discovered_by`, and optional `inferred` flag. Edge endpoints are validated against a schema defining valid (source_type → target_type) combinations.

### Inference Rules

Rules fire automatically when nodes are ingested. Each rule has:
- **Trigger** — node type + optional property match + optional `requires_edge` (for edge-triggered rules)
- **Selectors** — how to find related nodes (12 selector types: `trigger_node`, `parent_host`, `domain_nodes`, `domain_users`, `domain_credentials`, `all_compromised`, `compatible_services`, `compatible_services_same_domain`, `matching_domain`, `edge_peers`, `enrollable_users`, `trigger_service`)
- **Produces** — edge type + confidence + condition

Example: *"Host has SMB service with signing disabled → create RELAY_TARGET edge to domain hosts"*

Thirteen built-in rules cover: Kerberos→Domain, SMB Relay, MSSQL domain auth, credential fanout (domain-scoped), ADCS ESC1, unconstrained delegation, AS-REP roasting, Kerberoasting, constrained delegation, web login forms, LAPS/gMSA readable, and RBCD targets. Rules can be added at runtime via `suggest_inference_rule` and backfilled against existing graph nodes.

---

## Core Services

### GraphEngine (`src/services/graph-engine.ts` — ~1,415 lines)

Central orchestrator wrapping all submodules. Key capabilities:

| Area | Methods |
|------|---------|
| **Mutations** | `addNode`, `addEdge`, `ingestFinding`, `correctGraph` |
| **Inference** | `runInferenceRules`, `backfillRule`, `addInferenceRule` |
| **Frontier** | `computeFrontier`, `filterFrontier` |
| **Paths** | `findPaths`, `findPathsToObjective` |
| **Validation** | `validateAction` (scope + OPSEC) |
| **Queries** | `queryGraph` (type/filter/traversal) |
| **State** | `getState`, `exportGraph`, `getHealthReport` |
| **Persistence** | `persist`, `loadState`, `rollback`, `listSnapshots` |

### EngineContext (`src/services/engine-context.ts`)

Shared mutable state holder for all submodules: graph instance, config, inference rules, activity log, agent map, tracked processes, path graph cache, and `onUpdate` callbacks.

### StatePersistence (`src/services/state-persistence.ts`)

Atomic write-rename persistence with snapshot rotation (max 5 snapshots, every 30 seconds). Serializes: graph + activity log + agents + tracked processes. Supports rollback to any snapshot.

### InferenceEngine (`src/services/inference-engine.ts`)

Rule-based edge production. When nodes are ingested, matching rules fire to create hypothetical edges with confidence scores. Supports 9 selector types for relating trigger nodes to targets.

### FrontierComputer (`src/services/frontier.ts`)

Generates candidate next actions from two sources:
1. **Incomplete nodes** — missing key properties (e.g., host without services enumerated)
2. **Untested inferred edges** — hypothetical edges from inference awaiting validation

Each item carries fan-out estimates and OPSEC noise ratings.

### PathAnalyzer (`src/services/path-analyzer.ts`)

BFS-based shortest path on an undirected confidence-weighted projection. Resolves objective targets from engagement config criteria. Computes per-hop and total path confidence. Cached path graph with invalidation on mutations.

### Identity Resolution (`src/services/identity-resolution.ts`)

Resolves canonical IDs for nodes by type. Generates identity markers for matching (hostname variants, SIDs, domain-qualified usernames, credential fingerprints). Handles ambiguous BloodHound principals.

### Identity Reconciliation (`src/services/identity-reconciliation.ts`)

Post-ingest merge logic. When a canonical node is added, finds alias nodes sharing identity markers and merges them — retargets edges, merges properties, logs convergence events. Supports bidirectional merge (weaker canonical merges into stronger existing node).

### Graph Health (`src/services/graph-health.ts`)

Eight integrity checks:
1. Split host identities (multiple nodes claiming same IP/hostname)
2. Dangling edge references
3. Unresolved identity nodes
4. Credential identity ambiguities
5. Identity marker collisions
6. Shared credential material across accounts
7. Edge type constraint violations
8. Stale inferred edges

### Output Parsers (`src/services/output-parsers.ts`)

Eleven deterministic parsers with 21 aliases:

| Parser | Input | Output |
|--------|-------|--------|
| `nmap` | Nmap XML | host + service nodes, RUNS edges, OS detection |
| `nxc` / `netexec` | NXC stdout | host + SMB services + shares + users, access edges, NULL_SESSION |
| `certipy` | Certipy JSON | CA + cert_template nodes, ESC vulnerability edges |
| `secretsdump` | SAM/NTDS dump | credential + user nodes, OWNS_CRED + DUMPED_FROM + MEMBER_OF_DOMAIN edges |
| `kerbrute` | User enum / spray | user + domain + credential nodes |
| `hashcat` | Cracked hashes | credential nodes (Kerberoast, AS-REP, NTLMv2, NTLM) |
| `responder` | NTLMv2 captures | host + user + credential nodes |
| `ldapsearch` | LDIF / ldapdomaindump JSON | user + group + host + domain nodes, UAC flags, group memberships |
| `enum4linux` | JSON (-oJ) or text | host + SMB service + user + group + share nodes, null session detection |
| `rubeus` | Kerberoast / AS-REP / monitor | user + credential nodes, OWNS_CRED edges (TGT/TGS detection) |
| `gobuster` / `feroxbuster` / `ffuf` | Text or JSON | service node enrichment with discovered_paths, login form detection |

All parsers use canonical ID generation with SHA-1 fingerprinting for credential deduplication. Parsers accept optional `ParseContext` (`domain`, `source_host`) for ambient context.

### BloodHound Ingestion (`src/services/bloodhound-ingest.ts` — 701 lines)

Full SharpHound v4/v5 JSON parser. Maps all BH object types (computers, users, groups, domains, OUs, GPOs, cert templates, CAs, PKI stores) to Overwatch nodes. Processes ACEs, group memberships, sessions, local admins, delegation, SPN targets. Builds cross-file SID maps for reference resolution.

### Skill Index (`src/services/skill-index.ts`)

Local TF-IDF search over 29 markdown skill files. No external vector DB — runs entirely locally. Lightweight stemming, tag and name bonuses, ranked results with excerpts.

### Dashboard Server (`src/services/dashboard-server.ts`)

HTTP + WebSocket server on port 8384 (configurable). Serves a sigma.js WebGL dashboard SPA. Broadcasts graph deltas to connected clients with 500ms debounced batching via `DeltaAccumulator`. Read-only — no mutations from browser. API endpoints: `/api/state`, `/api/graph`.

### Lab Preflight (`src/services/lab-preflight.ts`)

Aggregate readiness checks for lab workflows (GOAD AD, single host, HTB). Validates config, scope, tool availability, graph health, persistence safety, dashboard status, and graph stage.

---

## MCP Tools (25)

All tools are wrapped in `withErrorBoundary` — unhandled errors return structured MCP error responses instead of crashing the server.

### State & Lifecycle

| Tool | Purpose |
|------|---------|
| `get_state` | Full engagement briefing (primary recovery after compaction) |
| `get_history` | Activity log with optional agent filtering |
| `export_graph` | Complete graph dump for reporting |
| `run_lab_preflight` | Lab readiness checks (profile-specific) |
| `run_graph_health` | Full graph integrity report |
| `recompute_objectives` | Re-evaluate objective achievement status |

### Findings & Parsing

| Tool | Purpose |
|------|---------|
| `report_finding` | Primary data ingestion — nodes + edges + evidence |
| `parse_output` | Deterministic tool output parsing (11 parsers, 21 aliases) |
| `ingest_bloodhound` | SharpHound/bloodhound-python JSON ingestion |

### Scoring & Planning

| Tool | Purpose |
|------|---------|
| `next_task` | Filtered frontier candidates for LLM scoring |
| `validate_action` | Pre-execution scope + OPSEC sanity check |
| `log_action_event` | Structured action lifecycle logging (plan → start → complete/fail) |

### Exploration

| Tool | Purpose |
|------|---------|
| `query_graph` | Structured graph queries with filtering and traversal |
| `find_paths` | Shortest path analysis between nodes or to objectives |

### Agents

| Tool | Purpose |
|------|---------|
| `register_agent` | Dispatch sub-agent with scoped subgraph |
| `dispatch_agents` | Batch agent dispatch from frontier items |
| `get_agent_context` | Scoped subgraph view for agents |
| `update_agent` | Mark agent task completed/failed |

### Infrastructure

| Tool | Purpose |
|------|---------|
| `get_skill` | RAG skill search and retrieval (29 skills) |
| `check_tools` | Offensive tool availability detection |
| `track_process` | Register long-running scan for tracking |
| `check_processes` | Check tracked process status |
| `suggest_inference_rule` | Custom inference rule creation + backfill |
| `correct_graph` | Transactional graph repair (drop/replace edges, patch nodes) |
| `run_retrospective` | Post-engagement analysis (5 structured outputs) |

---

## Validation Pipeline

Every finding passes through a multi-stage validation pipeline before entering the graph:

```
Raw Input (report_finding / parse_output / ingest_bloodhound)
    │
    ▼
┌─────────────────────────┐
│  Finding Validation      │  Normalize credentials, check edge constraints,
│  (finding-validation.ts) │  verify node references exist
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Identity Resolution     │  Generate canonical IDs, match identity markers,
│  (identity-resolution.ts)│  classify ambiguous principals
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Graph Ingestion         │  Add nodes/edges, merge properties,
│  (graph-engine.ts)       │  track provenance (first_seen, sources)
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Identity Reconciliation │  Merge alias nodes into canonicals,
│  (identity-reconcil...)  │  retarget edges, log convergence
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Inference Engine        │  Fire matching rules, produce hypothetical
│  (inference-engine.ts)   │  edges, update frontier
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Objective Evaluation    │  Check if any objective criteria are now
│  (graph-engine.ts)       │  satisfied by graph state
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Persistence + Broadcast │  Atomic write-rename to disk,
│  (state-persistence.ts)  │  WebSocket delta to dashboard
└─────────────────────────┘
```

---

## Retrospective Analysis

The `run_retrospective` tool produces five structured outputs:

1. **Inference Rule Suggestions** — Edge patterns observed 3+ times without matching rules
2. **Skill Gap Analysis** — Unused skills, missing skills for encountered scenarios, failed techniques
3. **Context Improvement Report** — Logging quality assessment, trace quality metrics
4. **Attack Path Report** — Client-deliverable markdown summarizing attack chains
5. **RLVR Training Traces** — State→action→outcome triplets with heuristic rewards for model fine-tuning

---

## Testing

**26 test files** across the codebase:

| Area | Files | Coverage |
|------|-------|----------|
| Integration | `mcp-server.integration.test.ts` | All 25 tools via stdio transport |
| Core Engine | `graph-engine.test.ts` | Seeding, ingestion, inference, persistence, rollback, identity |
| Services | 14 test files | CIDR, BloodHound, parsers (11), identity resolution, identity reconciliation, health, credentials, credential lifecycle, preflight, retrospective, dashboard, delta accumulator, graph schema |
| Tools | 3 test files | Error boundary, activity logging, process tracking |
| Dashboard | 4 test files | Boot, graph rendering, UI, WebSocket |
| CLI | `lab-smoke.test.ts` | End-to-end lab workflow |

The integration test spawns the actual MCP server via stdio and validates tool registration, state retrieval, health checks, BloodHound ingestion, output parsing, graph queries, agent lifecycle, and retrospective analysis.

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Runtime | Node.js (ESM) |
| Language | TypeScript (strict mode) |
| Protocol | MCP via `@modelcontextprotocol/sdk` |
| Graph | graphology + graphology-shortest-path + graphology-traversal |
| Validation | Zod schemas (runtime + compile-time) |
| XML Parsing | fast-xml-parser |
| Dashboard | sigma.js (WebGL) + graphology-layout-forceatlas2 |
| WebSocket | ws |
| IDs | uuid v4 |
| Testing | vitest |
| Persistence | Atomic JSON write-rename with snapshot rotation |

---

## Project Structure

```
overwatch/
├── src/
│   ├── index.ts                    # Thin entrypoint (~137 lines)
│   ├── config.ts                   # Config loading + validation
│   ├── types.ts                    # Zod schemas + TypeScript types (535 lines)
│   ├── tools/                      # 15 MCP tool modules
│   │   ├── state.ts                # get_state, preflight, health, history, export
│   │   ├── findings.ts             # report_finding
│   │   ├── scoring.ts              # next_task, validate_action
│   │   ├── exploration.ts          # query_graph, find_paths
│   │   ├── agents.ts               # register, dispatch, context, update
│   │   ├── logging.ts              # log_action_event
│   │   ├── parse-output.ts         # parse_output
│   │   ├── bloodhound.ts           # ingest_bloodhound
│   │   ├── inference.ts            # suggest_inference_rule
│   │   ├── remediation.ts          # correct_graph
│   │   ├── retrospective.ts        # run_retrospective
│   │   ├── skills.ts               # get_skill
│   │   ├── toolcheck.ts            # check_tools
│   │   ├── processes.ts            # track_process, check_processes
│   │   └── error-boundary.ts       # withErrorBoundary wrapper
│   ├── services/                   # Core business logic
│   │   ├── graph-engine.ts         # Central orchestrator (~1,415 lines)
│   │   ├── engine-context.ts       # Shared mutable state
│   │   ├── state-persistence.ts    # Atomic persistence + snapshots
│   │   ├── inference-engine.ts     # Rule-based edge production
│   │   ├── frontier.ts             # Frontier computation
│   │   ├── path-analyzer.ts        # BFS shortest paths
│   │   ├── identity-resolution.ts  # Canonical ID generation
│   │   ├── identity-reconciliation.ts # Alias node merging
│   │   ├── finding-validation.ts   # Pre-ingest validation
│   │   ├── graph-schema.ts         # Edge endpoint constraints
│   │   ├── graph-health.ts         # 8 integrity checks
│   │   ├── credential-utils.ts     # Credential classification + lifecycle
│   │   ├── output-parsers.ts       # 11 deterministic parsers (21 aliases)
│   │   ├── bloodhound-ingest.ts    # SharpHound v4/v5 (CE) JSON parser
│   │   ├── skill-index.ts          # TF-IDF skill search
│   │   ├── dashboard-server.ts     # HTTP + WebSocket server
│   │   ├── lab-preflight.ts        # Lab readiness checks
│   │   ├── agent-manager.ts        # Agent CRUD
│   │   ├── delta-accumulator.ts    # Graph delta batching
│   │   ├── parser-utils.ts         # Canonical ID helpers
│   │   ├── provenance-utils.ts     # Node provenance normalization
│   │   ├── retrospective.ts        # Post-engagement analysis (~1,186 lines)
│   │   └── tool-check.ts           # Tool availability detection
│   ├── dashboard/                  # Browser SPA
│   │   ├── index.html              # sigma.js WebGL graph
│   │   ├── main.js                 # Dashboard logic
│   │   ├── graph.js                # Graph rendering
│   │   └── styles.css              # Dark theme
│   └── cli/                        # CLI tools
│       ├── lab-smoke.ts            # Lab smoke test harness
│       ├── lab-smoke-lib.ts        # Smoke test library
│       └── retrospective.ts        # CLI retrospective runner
├── skills/                         # 29 offensive methodology guides
├── fixtures/                       # Test fixtures (GOAD synth data)
├── engagement.json                 # Example engagement config
├── package.json                    # Dependencies + scripts
└── tsconfig.json                   # TypeScript config (strict)
```

---

## Quality Assessment

### Strengths

- **Clean separation of concerns** — Each service has a single responsibility. The EngineContext pattern avoids tight coupling between submodules.
- **Robust validation pipeline** — Multi-stage: finding validation → schema check → identity resolution → reconciliation → inference. Bad data is rejected before it enters the graph.
- **Sophisticated identity resolution** — Canonical ID generation, marker-based matching, bidirectional merge, provenance preservation. Handles the real-world messiness of BloodHound SIDs + manual findings + parser outputs colliding.
- **Error resilience** — Every tool handler wrapped in error boundary. Server never crashes on tool errors.
- **Deterministic parsing** — 11 parsers (21 aliases) covering the core offensive tool chain. Reduces LLM token cost by handling structured output mechanically.
- **Action lifecycle correlation** — `action_id` links validate → start → complete → finding. Enables meaningful retrospectives and RLVR trace generation.
- **Comprehensive health checks** — 8 checks catching real graph integrity issues.
- **Atomic persistence** — Write-rename with snapshot rotation prevents data corruption on crash.

### Design Considerations

- **GraphEngine is the largest module** (~1,415 lines). It delegates well to submodules but acts as a facade for 40+ methods. Could benefit from interface segregation if it grows further.
- **BFS path analysis** is appropriate for pentest-scale graphs (hundreds to low thousands of nodes). For enterprise-scale BloodHound imports (tens of thousands), the undirected projection cache will be important.
- **Inference rule selectors are string-based** — The 12 selectors are resolved at runtime. Rule definitions rely on convention rather than compile-time safety.
