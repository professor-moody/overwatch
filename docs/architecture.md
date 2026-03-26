# Architecture

Overwatch inverts the typical "LLM-as-orchestrator" pattern. Instead of stuffing engagement state into a prompt, the orchestrator is a **persistent MCP server** that the LLM calls into.

## System Diagram

![Overwatch E2E Flow](assets/overwatch-e2e-flow.svg)

## Data Flow Example

Here's a concrete walkthrough of how data flows through the system during a typical engagement step:

```
1. Operator runs nmap against 10.10.10.0/24
2. LLM calls parse_output(tool_name="nmap", output="<xml>...")
3. Output parser extracts 5 hosts, 12 services
4. Engine ingests nodes: host-10-10-10-5, svc-10-10-10-5-445, ...
5. Inference rules fire:
   └─ SMB service with smb_signing: false → RELAY_TARGET edges created
   └─ Kerberos service detected → MEMBER_OF_DOMAIN edge to domain node
6. Frontier recomputed:
   └─ "Enumerate SMB shares on 10.10.10.5" (incomplete_node)
   └─ "Test relay to 10.10.10.5:445" (inferred_edge, confidence: 0.6)
7. State persisted to disk (atomic write-rename)
8. Dashboard broadcast:
   └─ WebSocket delta with 5 new nodes, 12 edges, 2 inferred edges
   └─ UI panels update: frontier, graph summary, activity
9. LLM calls next_task → sees new frontier items
10. LLM dispatches sub-agent to enumerate SMB shares
```

Every step is traceable: `action_id` links `validate_action` → `log_action_event` → `parse_output` → `report_finding`. The activity log records the full causal chain.

## Design Decisions

### Graph, Not Database

Engagements are directed property graphs — hosts, services, credentials, and the relationships between them. The graph structure means "credential X is valid on service Y which runs on host Z" is a traversable path, not three rows in a table.

The graph is powered by [graphology](https://graphology.github.io/), a robust JavaScript graph library, with shortest-path analysis via `graphology-shortest-path`.

### MCP Server, Not a Prompt

The orchestrator survives context compaction by design — it's not in the context window. After compaction, `get_state()` reconstructs a complete briefing from the graph. Zero information loss.

The current transport is **stdio** using the [Model Context Protocol](https://modelcontextprotocol.io/), the same protocol Claude Code uses for tool integrations. The core app bootstrap is transport-neutral so additional transports can be layered on later.

### Hybrid Scoring

The deterministic layer handles hard constraints:

- **Scope enforcement** — targets outside CIDRs/domains are rejected
- **Deduplication** — already-tested edges don't re-enter the frontier
- **OPSEC vetoes** — techniques exceeding the noise ceiling are filtered
- **Dead host pruning** — unreachable hosts are deprioritized

The LLM handles nuanced reasoning:

- **Attack chain spotting** — connecting discoveries across multiple hops
- **Sequencing** — determining what should happen before what
- **Risk assessment** — weighing reward against defensive posture
- **Creative path discovery** — finding non-obvious routes through the graph

### Inference Rules

When findings are reported, deterministic rules fire automatically to generate hypothesis edges. Thirteen built-in rules:

| Rule | Trigger | Produces |
|------|---------|----------|
| Kerberos → Domain | Service with `service_name: kerberos` | `MEMBER_OF_DOMAIN` to matching domain (hostname suffix) |
| SMB Signing → Relay | Service with `smb_signing: false` | `RELAY_TARGET` from compromised hosts |
| MSSQL + Domain | MSSQL on domain host | `POTENTIAL_AUTH` from domain credentials |
| Credential Fanout | New credential node | `POTENTIAL_AUTH` to compatible services in same domain |
| ADCS ESC1 | cert_template with enrollee-supplied subject | `ESC1` from enrollable users |
| Unconstrained Delegation | Host with `unconstrained_delegation: true` | `DELEGATES_TO` from domain users |
| AS-REP Roastable | User with `asrep_roastable: true` | `AS_REP_ROASTABLE` to domain nodes |
| Kerberoastable | User with `has_spn: true` | `KERBEROASTABLE` to domain nodes |
| Constrained Delegation | Host with `constrained_delegation: true` | `CAN_DELEGATE_TO` to domain nodes |
| Web Login Form | Service with `has_login_form: true` | `POTENTIAL_AUTH` from domain credentials |
| LAPS Readable | Host with `laps: true` + inbound `GENERIC_ALL` | `CAN_READ_LAPS` from edge peers |
| gMSA Readable | User with `gmsa: true` + inbound `GENERIC_ALL` | `CAN_READ_GMSA` from edge peers |
| RBCD Target | Host with `maq_gt_zero: true` + inbound `WRITEABLE_BY` | `RBCD_TARGET` from edge peers |

The last three use **edge-triggered inference** — they require a matching inbound edge in addition to the node property match. When a new edge arrives, inference also re-evaluates its endpoints.

These become frontier items for the LLM to evaluate. Custom rules can be added at runtime via [`suggest_inference_rule`](tools/suggest-inference-rule.md). See [Concepts](concepts.md#inference-rules) for how the rule lifecycle works.

### Full Graph Access

The LLM isn't restricted to scored frontier items. [`query_graph`](tools/query-graph.md) gives unrestricted access to the entire graph for creative path discovery. [`find_paths`](tools/find-paths.md) provides shortest-path analysis between any nodes or toward objectives.

## Component Overview

### Core

| Component | File | Purpose |
|-----------|------|---------|
| **Entrypoint** | `src/index.ts` | Config loading, server init, tool registration |
| **Config** | `src/config.ts` | Engagement config parsing and validation |
| **Types** | `src/types.ts` | Shared types + Zod schemas |

### Services

| Component | File | Purpose |
|-----------|------|---------|
| **Graph Engine** | `src/services/graph-engine.ts` | Core graph operations, state coordination |
| **Engine Context** | `src/services/engine-context.ts` | Mutable state container, update callbacks |
| **Frontier** | `src/services/frontier.ts` | Frontier item generation and filtering |
| **Inference Engine** | `src/services/inference-engine.ts` | Rule matching and hypothesis edge generation |
| **Path Analyzer** | `src/services/path-analyzer.ts` | Shortest-path and objective reachability |
| **Identity Resolution** | `src/services/identity-resolution.ts` | Canonical ID generation, marker matching |
| **Identity Reconciliation** | `src/services/identity-reconciliation.ts` | Alias node merging, edge retargeting |
| **Graph Schema** | `src/services/graph-schema.ts` | Node/edge type validation |
| **Graph Health** | `src/services/graph-health.ts` | Integrity checks and diagnostics |
| **Finding Validation** | `src/services/finding-validation.ts` | Input validation and normalization |
| **State Persistence** | `src/services/state-persistence.ts` | Atomic write-rename with snapshot rotation |
| **Skill Index** | `src/services/skill-index.ts` | TF-IDF search over skill library |
| **Output Parsers** | `src/services/output-parsers.ts` | 11 parsers / 21 aliases: nmap, nxc, certipy, secretsdump, kerbrute, hashcat, responder, ldapsearch, enum4linux, rubeus, web dir enum |
| **Parser Utils** | `src/services/parser-utils.ts` | Shared parsing helpers and canonical ID generation |
| **Credential Utils** | `src/services/credential-utils.ts` | Credential normalization, lifecycle, and domain inference |
| **Provenance Utils** | `src/services/provenance-utils.ts` | Source attribution tracking |
| **BloodHound Ingest** | `src/services/bloodhound-ingest.ts` | SharpHound v4/v5 (CE) JSON → graph |
| **Dashboard Server** | `src/services/dashboard-server.ts` | HTTP + WebSocket for live visualization |
| **Delta Accumulator** | `src/services/delta-accumulator.ts` | Debounced graph change tracking for broadcasts |
| **Agent Manager** | `src/services/agent-manager.ts` | Sub-agent task lifecycle |
| **Retrospective** | `src/services/retrospective.ts` | Post-engagement analysis and RLVR traces |
| **CIDR** | `src/services/cidr.ts` | CIDR parsing, expansion, and scope matching |
| **Tool Check** | `src/services/tool-check.ts` | Offensive tool availability detection |
| **Process Tracker** | `src/services/process-tracker.ts` | PID tracking for long-running scans |
| **Lab Preflight** | `src/services/lab-preflight.ts` | Lab readiness validation |
| **Session Manager** | `src/services/session-manager.ts` | Persistent interactive sessions, RingBuffer, ownership enforcement |
| **Session Adapters** | `src/services/session-adapters.ts` | LocalPty (node-pty), SSH, and Socket transport adapters |

### Tools

| Module | File | Tools |
|--------|------|-------|
| **State** | `src/tools/state.ts` | `get_state`, `run_lab_preflight`, `run_graph_health`, `recompute_objectives`, `get_history`, `export_graph` |
| **Scoring** | `src/tools/scoring.ts` | `next_task`, `validate_action` |
| **Findings** | `src/tools/findings.ts` | `report_finding` |
| **Exploration** | `src/tools/exploration.ts` | `query_graph`, `find_paths` |
| **Agents** | `src/tools/agents.ts` | `register_agent`, `dispatch_agents`, `get_agent_context`, `update_agent` |
| **Skills** | `src/tools/skills.ts` | `get_skill` |
| **Logging** | `src/tools/logging.ts` | `log_action_event` |
| **Parse Output** | `src/tools/parse-output.ts` | `parse_output` |
| **Inference** | `src/tools/inference.ts` | `suggest_inference_rule` |
| **BloodHound** | `src/tools/bloodhound.ts` | `ingest_bloodhound` |
| **Tool Check** | `src/tools/toolcheck.ts` | `check_tools` |
| **Processes** | `src/tools/processes.ts` | `track_process`, `check_processes` |
| **Remediation** | `src/tools/remediation.ts` | `correct_graph` |
| **Retrospective** | `src/tools/retrospective.ts` | `run_retrospective` |
| **Sessions** | `src/tools/sessions.ts` | `open_session`, `write_session`, `read_session`, `send_to_session`, `list_sessions`, `update_session`, `resize_session`, `signal_session`, `close_session` |

### Dashboard

| File | Purpose |
|------|---------|
| `src/dashboard/index.html` | Slim HTML shell loading CDN deps + local scripts |
| `src/dashboard/styles.css` | Dark theme, animations, responsive layout |
| `src/dashboard/graph.js` | Sigma.js, ForceAtlas2, drag, hover, path/neighborhood highlight, minimap |
| `src/dashboard/ui.js` | Sidebar panels, node detail, search, keyboard shortcuts |
| `src/dashboard/ws.js` | WebSocket connection, reconnect, HTTP polling |
| `src/dashboard/main.js` | Entry point wiring modules together |

## State Persistence

Graph state is persisted to `state-<engagement-id>.json` after every finding using atomic write-rename:

```
1. Serialize graph + metadata to JSON
2. Write to temporary file (state-<id>.json.tmp)
3. Atomic rename over the real file
4. Previous version moved to snapshot rotation
```

Features:

- **Snapshot rotation** — keeps recent snapshots for rollback
- **Crash recovery** — incomplete writes never corrupt state (temp file is discarded)
- **Resume anywhere** — restart Claude Code, restart the server, come back days later
- **Post-engagement analysis** — persisted state feeds retrospective analysis

## Broadcast Pipeline

When the graph changes, updates flow to the dashboard in real time:

```
GraphEngine.persist()
  → onUpdate callback fires
  → DeltaAccumulator collects changes (debounced)
  → DashboardServer broadcasts via WebSocket:
      - New connections: full_state message (complete graph + engagement state)
      - Existing connections: graph_update message (delta only)
  → Browser receives:
      - graph.js merges delta into graphology instance
      - ui.js updates sidebar panels
      - New nodes pulse for 2 seconds
      - Minimap redraws
```

The dashboard also polls `/api/state` every 5 seconds as a fallback when WebSocket is disconnected.
