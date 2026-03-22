# Architecture

Overwatch inverts the typical "LLM-as-orchestrator" pattern. Instead of stuffing engagement state into a prompt, the orchestrator is a **persistent MCP server** that the LLM calls into.

## System Diagram

![Overwatch E2E Flow](assets/overwatch-e2e-flow.svg)

## Design Decisions

### Graph, Not Database

Engagements are directed property graphs — hosts, services, credentials, and the relationships between them. The graph structure means "credential X is valid on service Y which runs on host Z" is a traversable path, not three rows in a table.

The graph is powered by [graphology](https://graphology.github.io/), a robust JavaScript graph library, with shortest-path analysis via `graphology-shortest-path`.

### MCP Server, Not a Prompt

The orchestrator survives context compaction by design — it's not in the context window. After compaction, `get_state()` reconstructs a complete briefing from the graph. Zero information loss.

Communication happens over **stdio** using the [Model Context Protocol](https://modelcontextprotocol.io/), the same protocol Claude Code uses for all tool integrations.

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

When findings are reported, deterministic rules fire automatically to generate hypothesis edges. Examples:

| Rule | Trigger | Produces |
|------|---------|----------|
| SMB Signing → Relay | Service with `smb_signing: false` | `RELAY_TARGET` edges from compromised hosts |
| Credential Fanout | New credential node | `POTENTIAL_AUTH` to all compatible services |
| ADCS ESC1 | Certificate with enrollee-supplied subject | `ESC1` from enrollable users |

These become frontier items for the LLM to evaluate. Custom rules can be added at runtime via [`suggest_inference_rule`](tools/suggest-inference-rule.md).

### Full Graph Access

The LLM isn't restricted to scored frontier items. [`query_graph`](tools/query-graph.md) gives unrestricted access to the entire graph for creative path discovery. [`find_paths`](tools/find-paths.md) provides shortest-path analysis between any nodes or toward objectives.

## Component Overview

| Component | File | Purpose |
|-----------|------|---------|
| **Entrypoint** | `src/index.ts` | Config loading, server init, tool registration |
| **Graph Engine** | `src/services/graph-engine.ts` | Core graph operations, frontier computation, inference, persistence |
| **Frontier** | `src/services/frontier.ts` | Frontier item generation and filtering |
| **Inference Engine** | `src/services/inference-engine.ts` | Rule matching and edge generation |
| **Path Analyzer** | `src/services/path-analyzer.ts` | Shortest-path and objective reachability |
| **Skill Index** | `src/services/skill-index.ts` | TF-IDF search over skill library |
| **Output Parsers** | `src/services/output-parsers.ts` | Deterministic parsing for nmap, nxc, certipy, etc. |
| **BloodHound Ingest** | `src/services/bloodhound-ingest.ts` | SharpHound/bloodhound-python JSON → graph |
| **Dashboard Server** | `src/services/dashboard-server.ts` | HTTP + WebSocket for live visualization |
| **State Persistence** | `src/services/state-persistence.ts` | Atomic write-rename with snapshot rotation |
| **Retrospective** | `src/services/retrospective.ts` | Post-engagement analysis and RLVR traces |
| **Tool Modules** | `src/tools/*.ts` | MCP tool registration (one module per domain) |
| **Types** | `src/types.ts` | Shared types + Zod schemas |

## State Persistence

Graph state is persisted to `state-<engagement-id>.json` after every finding using atomic write-rename. Features:

- **Snapshot rotation** — keeps recent snapshots for rollback
- **Crash recovery** — incomplete writes never corrupt state
- **Resume anywhere** — restart Claude Code, restart the server, come back days later
- **Post-engagement analysis** — persisted state feeds retrospective analysis
