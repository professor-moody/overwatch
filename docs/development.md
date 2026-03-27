# Development

## Build & Run

```bash
npm run build    # Compile TypeScript + copy dashboard assets
npm run dev      # Watch mode (tsc --watch)
npm start        # Run server (stdio)
npm start -- --http  # Run server (HTTP/SSE transport)
npm test         # Run fast source-level tests
npm run test:integration:stdio   # Fresh-build stdio integration suite
npm run test:integration:http    # Fresh-build HTTP transport integration suite
npm run verify   # Source + stdio integration + HTTP integration + dist freshness check
```

## Project Structure

```
overwatch/
├── src/
│   ├── app.ts                # Core app/bootstrap + transport-neutral tool registration
│   ├── index.ts              # Stdio entrypoint + graceful shutdown
│   ├── config.ts             # Config parsing and validation
│   ├── types.ts              # Shared types + Zod schemas
│   ├── tools/                # MCP tool modules (one per domain)
│   │   ├── state.ts          # get_state, run_lab_preflight, run_graph_health, get_history, export_graph
│   │   ├── scoring.ts        # next_task, validate_action
│   │   ├── findings.ts       # report_finding
│   │   ├── exploration.ts    # query_graph, find_paths
│   │   ├── agents.ts         # register_agent, get_agent_context, update_agent
│   │   ├── skills.ts         # get_skill
│   │   ├── bloodhound.ts     # ingest_bloodhound
│   │   ├── toolcheck.ts      # check_tools
│   │   ├── processes.ts      # track_process, check_processes
│   │   ├── inference.ts      # suggest_inference_rule
│   │   ├── parse-output.ts   # parse_output
│   │   ├── logging.ts        # log_action_event
│   │   ├── retrospective.ts  # run_retrospective
│   │   ├── remediation.ts    # correct_graph
│   │   ├── sessions.ts       # open_session, write/read/send_to/list/update/resize/signal/close_session
│   │   ├── scope.ts          # update_scope
│   │   ├── instructions.ts   # get_system_prompt
│   │   └── error-boundary.ts # Shared error handling wrapper
│   ├── services/             # Core business logic (29 modules)
│   │   ├── graph-engine.ts   # Graph operations, state coordination
│   │   ├── engine-context.ts # Mutable state container, update callbacks
│   │   ├── frontier.ts       # Frontier item generation and filtering
│   │   ├── inference-engine.ts # Rule matching and edge generation
│   │   ├── path-analyzer.ts  # Shortest-path and objective reachability
│   │   ├── identity-resolution.ts  # Canonical ID generation, marker matching
│   │   ├── identity-reconciliation.ts # Alias node merging, edge retargeting
│   │   ├── graph-schema.ts   # Node/edge type validation
│   │   ├── graph-health.ts   # Integrity checks and diagnostics
│   │   ├── finding-validation.ts # Input validation for findings
│   │   ├── state-persistence.ts  # Atomic write-rename + snapshots
│   │   ├── skill-index.ts    # TF-IDF search over skill library
│   │   ├── output-parsers.ts # 11 parsers / 21 aliases: nmap, nxc, certipy, secretsdump, kerbrute, hashcat, responder, ldapsearch, enum4linux, rubeus, web dir enum
│   │   ├── parser-utils.ts   # Shared parsing helpers
│   │   ├── credential-utils.ts # Credential normalization, lifecycle, and domain inference
│   │   ├── provenance-utils.ts # Source attribution tracking
│   │   ├── bloodhound-ingest.ts # SharpHound v4/v5 (CE) JSON → graph
│   │   ├── dashboard-server.ts  # HTTP + WebSocket server (static file serving)
│   │   ├── delta-accumulator.ts # Debounced graph change tracking
│   │   ├── agent-manager.ts  # Agent task lifecycle
│   │   ├── retrospective.ts  # Post-engagement analysis + RLVR traces
│   │   ├── cidr.ts           # CIDR parsing, expansion, scope matching
│   │   ├── tool-check.ts     # Offensive tool detection
│   │   ├── process-tracker.ts # PID tracking for long-running scans
│   │   ├── lab-preflight.ts  # Lab readiness validation
│   │   ├── session-manager.ts # Persistent sessions, RingBuffer, ownership
│   │   ├── session-adapters.ts # LocalPty (node-pty), SSH, Socket adapters
│   │   └── prompt-generator.ts # Dynamic system prompt generation
│   ├── cli/                  # Command-line tools
│   │   ├── retrospective.ts  # npm run retrospective
│   │   └── lab-smoke.ts      # npm run lab:smoke
│   ├── dashboard/            # Interactive graph visualization (6 files)
│   │   ├── index.html        # Slim HTML shell (~180 lines)
│   │   ├── styles.css        # Dark theme, animations (~580 lines)
│   │   ├── graph.js          # Sigma.js, FA2, drag, hover, path highlight, minimap
│   │   ├── ui.js             # Sidebar, detail panel, search, keyboard shortcuts
│   │   ├── ws.js             # WebSocket + HTTP polling, reconnect
│   │   └── main.js           # Entry point wiring modules
│   └── __tests__/
│       ├── app-bootstrap.test.ts
│       ├── mcp-server.integration.test.ts
│       └── http-transport.integration.test.ts
├── skills/                   # 32 offensive methodology guides
├── engagement.json           # Engagement configuration
├── mkdocs.yml                # Documentation config
└── docs/                     # Documentation source
```

## Testing

Tests use [Vitest](https://vitest.dev/). **865 tests across 31 test files** are split between fast source tests and two build-backed integration suites (stdio and HTTP) so local iteration stays fast while release verification exercises both transport paths.

```bash
npm test                        # Fast source tests (862 tests)
npm run test:integration:stdio  # Stdio integration (24 tests)
npm run test:integration:http   # HTTP transport integration (6 tests)
npm run verify                  # All of the above + dist freshness check
```

Integration suites auto-skip in restricted environments (e.g., EPERM on `listen()`) using async bind probes.

Test files are co-located with their modules under `__tests__/` directories:

| Test File | Coverage |
|-----------|----------|
| `graph-engine.test.ts` | Graph operations, frontier, inference, persistence, identity |
| `cidr.test.ts` | CIDR parsing, scope matching, hostname resolution |
| `skill-index.test.ts` | Skill search and indexing |
| `bloodhound-ingest.test.ts` | BloodHound JSON parsing, SharpHound CE adapter |
| `output-parsers.test.ts` | All 11 parsers: nmap, nxc, certipy, secretsdump, kerbrute, hashcat, responder, ldapsearch, enum4linux, rubeus, web dir enum |
| `parser-utils.test.ts` | Shared parsing utilities, canonical ID generation |
| `credential-utils.test.ts` | Credential normalization, lifecycle, domain inference |
| `credential-lifecycle.test.ts` | Credential status, expiry, derivation chains, degradation |
| `identity-resolution.test.ts` | Canonical ID generation, marker matching |
| `graph-schema.test.ts` | Edge endpoint constraints |
| `dashboard-server.test.ts` | HTTP endpoints, WebSocket, /api/history |
| `graph-health.test.ts` | Graph integrity checks |
| `lab-preflight.test.ts` | Lab readiness validation |
| `retrospective.test.ts` | Retrospective analysis, credential chains, RLVR traces |
| `process-tracker.test.ts` | PID tracking |
| `delta-accumulator.test.ts` | Graph change tracking |
| `activity-logging.test.ts` | Action event logging, dispatch_agents |
| `error-boundary.test.ts` | Error handling wrapper |
| `processes.test.ts` | Process tool integration |
| `session-manager.test.ts` | RingBuffer, SessionManager, ownership enforcement, adapters |
| `sprint8-architecture-prep.test.ts` | Scope expansion (URL glob, cloud resource), profile inference, frontier REQUIRED_PROPERTIES, session→graph integration |
| `community-detection.test.ts` | Louvain community detection, stats, undirected projection |
| `prompt-generator.test.ts` | Primary and sub-agent prompt generation, state reflection |
| `config.test.ts` | Config parsing and Zod schema validation |
| `boot.test.ts` | Dashboard boot and module wiring |
| `graph.test.ts` | Dashboard graph: shortest path, attack path, credential flow, community hulls |
| `main.test.ts` | Dashboard main entry point |
| `ui.test.ts` | Dashboard UI: sidebar, detail panel, derivation chains |
| `ws.test.ts` | Dashboard WebSocket client, reconnect logic |
| `lab-smoke.test.ts` | Lab smoke test CLI harness |
| `app-bootstrap.test.ts` | Transport-neutral app/bootstrap and tool registration (36 tools) |
| `mcp-server.integration.test.ts` | End-to-end MCP protocol via fresh-built stdio server |
| `http-transport.integration.test.ts` | HTTP/SSE transport: tool listing, state, findings, concurrent sessions |

## Adding a New Parser

1. Add the parser function in `src/services/output-parsers.ts`
2. Register the parser name in the `parsers` map
3. Add tests in `src/services/__tests__/output-parsers.test.ts`
4. Update the `parse_output` tool description in `src/tools/parse-output.ts`

## Adding an Inference Rule (Programmatic)

```typescript
engine.addInferenceRule({
  id: 'rule-custom',
  name: 'Custom Rule Name',
  description: 'What this rule detects',
  trigger: {
    node_type: 'service',
    property_match: { service_name: 'tomcat', version_major: 9 }
  },
  produces: [{
    edge_type: 'RELATED',
    source_selector: 'trigger_node',
    target_selector: 'domain_nodes',
    confidence: 0.65
  }]
});
```

## Adding a New Tool

1. Create a new file in `src/tools/` following the pattern of existing modules
2. Define the tool with `server.registerTool()` using Zod schemas for input validation
3. Wrap the handler with `withErrorBoundary()` for consistent error handling
4. Import and call the registration function in `src/app.ts` (`registerAllTools`)
5. Add tests in `src/tools/__tests__/`
