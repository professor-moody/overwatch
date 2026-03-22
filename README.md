# Overwatch

An offensive security engagement orchestrator built as an MCP server. The persistent state layer and reasoning substrate for LLM-powered penetration testing.

> **[Full Documentation](https://keys.github.io/overwatch/)**

## What is Overwatch?

Overwatch inverts the typical "LLM-as-orchestrator" pattern. Instead of stuffing engagement state into a prompt, the orchestrator is a **persistent MCP server** that the LLM calls into. The graph holds every discovery, relationship, and hypothesis. The LLM proposes actions. The server validates them. After context compaction, `get_state()` reconstructs a complete briefing — zero information loss.

## Key Features

- **Graph-based state** — directed property graphs (hosts, services, credentials, relationships) with traversable attack paths
- **Hybrid scoring** — deterministic layer handles scope/dedup/OPSEC vetoes; the LLM handles attack chain reasoning
- **Inference rules** — automatic hypothesis generation (e.g., "SMB signing disabled → relay target")
- **22 MCP tools** — state management, graph exploration, output parsing, sub-agent dispatch, and more
- **29 offensive skills** — RAG-searchable methodology library covering AD, cloud, web, and infrastructure
- **Live dashboard** — real-time WebGL graph visualization with sigma.js
- **Deterministic parsers** — nmap, nxc, certipy, secretsdump, kerbrute, hashcat, responder
- **Retrospective analysis** — post-engagement skill gaps, inference suggestions, RLVR training traces

## Quick Start

```bash
git clone https://github.com/keys/overwatch.git
cd overwatch
npm install
npm run build
```

Add to your Claude Code MCP config:

```json
{
  "mcpServers": {
    "overwatch": {
      "command": "node",
      "args": ["<path-to-overwatch>/dist/index.js"],
      "env": {
        "OVERWATCH_CONFIG": "<path-to-engagement.json>",
        "OVERWATCH_SKILLS": "<path-to-overwatch>/skills"
      }
    }
  }
}
```

Then run `claude` — see the full [Getting Started](https://keys.github.io/overwatch/getting-started/) guide.

## Architecture

```
┌──────────────┐
│   Operator    │  scope, objectives, OPSEC profile
└──────┬───────┘
       │
┌──────▼────────────────────────────────────────────────┐
│              MCP Orchestrator Server                   │
│                                                        │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Graph Engine │  │ Scoring /    │  │  OPSEC       │  │
│  │ (graphology) │  │ Frontier     │  │  Policy      │  │
│  └──────┬──────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                │                  │          │
│  ┌──────▼────────────────▼──────────────────▼───────┐  │
│  │              MCP Tool Interface                   │  │
│  │  get_state · next_task · validate_action ·        │  │
│  │  log_action_event · parse_output ·                │  │
│  │  report_finding · query_graph · find_paths · ...  │  │
│  └──────────────────────┬────────────────────────────┘  │
└─────────────────────────┼──────────────────────────────┘
                          │ stdio
       ┌──────────────────▼──────────────────┐
       │        Claude Code (Opus)            │
       │     Primary Session + Sub-Agents     │
       └──────────────────────────────────────┘
```

## MCP Tools

| Tool | Purpose |
|------|---------|
| `get_state` | Full engagement briefing from graph |
| `next_task` | Filtered frontier candidates for scoring |
| `validate_action` | Pre-execution sanity check |
| `log_action_event` | Record action lifecycle events |
| `parse_output` | Parse supported tool output into findings |
| `report_finding` | Submit new nodes/edges to the graph |
| `query_graph` | Open-ended graph exploration |
| `find_paths` | Shortest paths to objectives |
| `get_skill` | RAG search over skill library |
| `register_agent` / `get_agent_context` / `update_agent` | Sub-agent lifecycle |
| `ingest_bloodhound` | Import BloodHound JSON collections |
| `run_lab_preflight` / `run_graph_health` | Environment and graph health checks |
| `check_tools` / `track_process` / `check_processes` | System utilities |
| `suggest_inference_rule` | Add custom inference rules |
| `run_retrospective` | Post-engagement analysis |
| `get_history` / `export_graph` | Activity log and graph export |

Full reference: **[Tool Documentation](https://keys.github.io/overwatch/tools/)**

## Documentation

- **[Getting Started](https://keys.github.io/overwatch/getting-started/)** — install, configure, connect
- **[Architecture](https://keys.github.io/overwatch/architecture/)** — design decisions and component overview
- **[Configuration](https://keys.github.io/overwatch/configuration/)** — engagement config, OPSEC profiles, env vars
- **[Graph Model](https://keys.github.io/overwatch/graph-model/)** — node types, edge types, inference rules
- **[Tool Reference](https://keys.github.io/overwatch/tools/)** — all 22 MCP tools with parameters and examples
- **[Skills Library](https://keys.github.io/overwatch/skills/)** — 29 offensive methodology guides
- **[Operator Playbook](https://keys.github.io/overwatch/playbook/)** — lab workflows, session instructions, best practices
- **[Development](https://keys.github.io/overwatch/development/)** — project structure, testing, extending

## Development

```bash
npm run build    # Compile TypeScript + copy dashboard
npm run dev      # Watch mode
npm start        # Run server (stdio)
npm test         # Run all tests
```

## License

TBD

## Disclaimer

This tool is designed for authorized security testing only. Do not run against production systems without explicit written authorization.
