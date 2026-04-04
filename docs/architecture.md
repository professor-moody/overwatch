# Architecture

Overwatch inverts the typical "LLM-as-orchestrator" pattern. Instead of stuffing engagement state into a prompt, the orchestrator is a **persistent MCP server** that the LLM calls into.

## System Diagram

![System Architecture](assets/system-architecture-light.svg#only-light)
![System Architecture](assets/system-architecture-dark.svg#only-dark)

## Data Flow Example

Here's a concrete walkthrough of how data flows through the system during a typical engagement step:

![Data Flow Lifecycle](assets/data-flow-lifecycle-light.svg#only-light)
![Data Flow Lifecycle](assets/data-flow-lifecycle-dark.svg#only-dark)

Every step is traceable: `action_id` links `validate_action` → `log_action_event` → `parse_output` → `report_finding`. The activity log records the full causal chain.

## Design Decisions

### Graph, Not Database

Engagements are directed property graphs — hosts, services, credentials, and the relationships between them. The graph structure means "credential X is valid on service Y which runs on host Z" is a traversable path, not three rows in a table.

The graph is powered by [graphology](https://graphology.github.io/), a robust JavaScript graph library, with shortest-path analysis via `graphology-shortest-path` and community detection via `graphology-communities-louvain`.

**Community detection** runs Louvain modularity optimization on an undirected projection of the graph. Each node gets a `community_id` attribute, materialized lazily and cached until the next topology change. Communities feed two consumers:

- **Frontier** — each `FrontierItem` carries `community_id` and `community_unexplored_count`, letting the LLM reason about cluster coverage
- **Dashboard** — convex hull overlays color-code communities in the graph visualization

### MCP Server, Not a Prompt

The orchestrator survives context compaction by design — it's not in the context window. After compaction, `get_state()` reconstructs a complete briefing from the graph. Zero information loss.

Two transports are supported:

- **stdio** — the default, using the [Model Context Protocol](https://modelcontextprotocol.io/) over standard I/O. This is how Claude Code connects.
- **HTTP/SSE** — streamable HTTP transport for remote deployment, web-based consumers, and multiple simultaneous clients. Enable with `OVERWATCH_TRANSPORT=http` or the `--http` CLI flag.

The core app bootstrap (`src/app.ts`) is transport-neutral — both transports share the same `GraphEngine`, skills, and services. Each HTTP session gets its own `McpServer` instance (SDK limitation: one `connect()` per server) but all sessions share the underlying graph.

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

When findings are reported, deterministic rules fire automatically to generate hypothesis edges. Twenty-two built-in rules span AD, Linux privilege escalation, web application, MSSQL, and cloud domains:

| Domain | Rules | Examples |
|--------|-------|----------|
| **AD & Service** | 13 | Kerberos → Domain, SMB Relay, Credential Fanout, ADCS ESC1, Delegation, Roasting, LAPS/gMSA, RBCD |
| **Linux Privesc** | 4 | SUID root, SSH key reuse, Docker escape, NFS no_root_squash |
| **Web** | 1 | Webapp login spray |
| **MSSQL** | 1 | Linked server → REACHABLE |
| **Cloud** | 3 | Overprivileged policy, public bucket, cross-account role |

Three AD rules use **edge-triggered inference** — they require a matching inbound edge in addition to the node property match. When a new edge arrives, inference also re-evaluates its endpoints.

See [Graph Model — Inference Rules](graph-model.md#inference-rules) for the full rule reference with triggers and productions. Custom rules can be added at runtime via [`suggest_inference_rule`](tools/suggest-inference-rule.md). See [Concepts](concepts.md#inference-rules) for how the rule lifecycle works.

### Full Graph Access

The LLM isn't restricted to scored frontier items. [`query_graph`](tools/query-graph.md) gives unrestricted access to the entire graph for creative path discovery. [`find_paths`](tools/find-paths.md) provides shortest-path analysis between any nodes or toward objectives.

## Component Overview

![Service Decomposition](assets/service-decomposition-light.svg#only-light)
![Service Decomposition](assets/service-decomposition-dark.svg#only-dark)

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
| **Output Parsers** | `src/services/output-parsers.ts` | 17 parsers / 30 aliases: nmap, nxc, certipy, secretsdump, kerbrute, hashcat, responder, ldapsearch, enum4linux, rubeus, web dir enum, linpeas/linenum, nuclei, nikto, testssl/sslscan, pacu, prowler |
| **Parser Utils** | `src/services/parser-utils.ts` | Shared parsing helpers and canonical ID generation |
| **Credential Utils** | `src/services/credential-utils.ts` | Credential normalization, lifecycle, and domain inference |
| **Provenance Utils** | `src/services/provenance-utils.ts` | Source attribution tracking |
| **BloodHound Ingest** | `src/services/bloodhound-ingest.ts` | SharpHound v4/v5 (CE) JSON → graph |
| **AzureHound Ingest** | `src/services/azurehound-ingest.ts` | AzureHound / ROADtools JSON → graph |
| **Community Detection** | `src/services/community-detection.ts` | Louvain modularity for graph clustering |
| **Dashboard Server** | `src/services/dashboard-server.ts` | HTTP + WebSocket for live visualization |
| **Delta Accumulator** | `src/services/delta-accumulator.ts` | Debounced graph change tracking for broadcasts |
| **Cold Store** | `src/services/cold-store.ts` | Promotion-only compaction for large network sweeps |
| **Agent Manager** | `src/services/agent-manager.ts` | Sub-agent task lifecycle |
| **Retrospective** | `src/services/retrospective.ts` | Post-engagement analysis and RLVR traces |
| **CIDR** | `src/services/cidr.ts` | CIDR parsing, expansion, and scope matching |
| **Tool Check** | `src/services/tool-check.ts` | Offensive tool availability detection |
| **Process Tracker** | `src/services/process-tracker.ts` | PID tracking for long-running scans |
| **Lab Preflight** | `src/services/lab-preflight.ts` | Lab readiness validation |
| **Session Manager** | `src/services/session-manager.ts` | Persistent interactive sessions, RingBuffer, ownership enforcement |
| **Session Adapters** | `src/services/session-adapters.ts` | LocalPty (node-pty), SSH, and Socket transport adapters |
| **Prompt Generator** | `src/services/prompt-generator.ts` | Dynamic system prompt generation for primary and sub-agent roles |
| **Report Generator** | `src/services/report-generator.ts` | Per-finding sections, evidence chains, attack narrative, auto-remediation |
| **Report HTML** | `src/services/report-html.ts` | Self-contained HTML report renderer with themes and print CSS |

### Tools

| Module | File | Tools |
|--------|------|-------|
| **State** | `src/tools/state.ts` | `get_state`, `run_lab_preflight`, `run_graph_health`, `recompute_objectives`, `get_history`, `export_graph` |
| **Scoring** | `src/tools/scoring.ts` | `next_task`, `validate_action` |
| **Findings** | `src/tools/findings.ts` | `report_finding` |
| **Exploration** | `src/tools/exploration.ts` | `query_graph`, `find_paths` |
| **Agents** | `src/tools/agents.ts` | `register_agent`, `dispatch_agents`, `get_agent_context`, `update_agent`, `dispatch_subnet_agents` |
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
| **Scope** | `src/tools/scope.ts` | `update_scope` |
| **Instructions** | `src/tools/instructions.ts` | `get_system_prompt` |
| **Reporting** | `src/tools/reporting.ts` | `generate_report` |
| **AzureHound** | `src/tools/azurehound.ts` | `ingest_azurehound` |

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

## Session + Transport Architecture

![Session Transport](assets/session-transport-light.svg#only-light)
![Session Transport](assets/session-transport-dark.svg#only-dark)

Two MCP transports (stdio default, HTTP/SSE for remote). Persistent interactive sessions with 3 adapters (LocalPty, SSH, Socket), 128KB ring buffers, cursor-based I/O, and TTY quality tracking.

## Broadcast Pipeline

When the graph changes, updates flow to the dashboard in real time. The dashboard also polls `/api/state` every 5 seconds as a fallback when WebSocket is disconnected.
