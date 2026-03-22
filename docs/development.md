# Development

## Build & Run

```bash
npm run build    # Compile TypeScript + copy dashboard assets
npm run dev      # Watch mode (tsc --watch)
npm start        # Run server (stdio)
npm test         # Run all tests (vitest)
```

## Project Structure

```
overwatch/
├── src/
│   ├── index.ts              # Entrypoint — config, server init, tool registration
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
│   │   └── error-boundary.ts # Shared error handling wrapper
│   ├── services/             # Core business logic
│   │   ├── graph-engine.ts   # Graph operations, frontier, inference, persistence
│   │   ├── frontier.ts       # Frontier item generation and filtering
│   │   ├── inference-engine.ts # Rule matching and edge generation
│   │   ├── path-analyzer.ts  # Shortest-path and objective reachability
│   │   ├── skill-index.ts    # TF-IDF search over skill library
│   │   ├── output-parsers.ts # Parsers for nmap, nxc, certipy, secretsdump, etc.
│   │   ├── bloodhound-ingest.ts # BloodHound JSON → graph
│   │   ├── dashboard-server.ts  # HTTP + WebSocket server
│   │   ├── state-persistence.ts # Atomic write-rename + snapshots
│   │   ├── graph-health.ts   # Integrity checks
│   │   ├── lab-preflight.ts  # Lab readiness validation
│   │   ├── retrospective.ts  # Post-engagement analysis
│   │   ├── cidr.ts           # CIDR parsing and matching
│   │   ├── tool-check.ts     # Offensive tool detection
│   │   ├── process-tracker.ts # PID tracking for long-running scans
│   │   ├── agent-manager.ts  # Agent task lifecycle
│   │   ├── credential-utils.ts # Credential normalization
│   │   ├── parser-utils.ts   # Shared parsing helpers
│   │   ├── provenance-utils.ts # Source attribution
│   │   ├── delta-accumulator.ts # Graph change tracking
│   │   └── engine-context.ts # Engine dependency injection
│   ├── cli/                  # Command-line tools
│   │   ├── retrospective.ts  # npm run retrospective
│   │   └── lab-smoke.ts      # npm run lab:smoke
│   ├── dashboard/
│   │   └── index.html        # Self-contained SPA
│   └── __tests__/
│       └── mcp-server.integration.test.ts
├── skills/                   # 29 offensive methodology guides
├── engagement.json           # Engagement configuration
├── mkdocs.yml                # Documentation config
└── docs/                     # Documentation source
```

## Testing

Tests use [Vitest](https://vitest.dev/). Run the full suite:

```bash
npm test
```

Test files are co-located with their modules under `__tests__/` directories:

| Test File | Coverage |
|-----------|----------|
| `graph-engine.test.ts` | Graph operations, frontier, inference, persistence |
| `cidr.test.ts` | CIDR parsing and scope matching |
| `skill-index.test.ts` | Skill search and indexing |
| `bloodhound-ingest.test.ts` | BloodHound JSON parsing |
| `output-parsers.test.ts` | Nmap, NXC, Certipy, Secretsdump, etc. |
| `parser-utils.test.ts` | Shared parsing utilities |
| `credential-utils.test.ts` | Credential normalization |
| `dashboard-server.test.ts` | HTTP endpoints + WebSocket |
| `graph-health.test.ts` | Graph integrity checks |
| `lab-preflight.test.ts` | Lab readiness validation |
| `retrospective.test.ts` | Retrospective analysis |
| `process-tracker.test.ts` | PID tracking |
| `delta-accumulator.test.ts` | Graph change tracking |
| `activity-logging.test.ts` | Action event logging |
| `error-boundary.test.ts` | Error handling wrapper |
| `processes.test.ts` | Process tool integration |
| `mcp-server.integration.test.ts` | End-to-end MCP protocol |

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
4. Import and call the registration function in `src/index.ts`
5. Add tests in `src/tools/__tests__/`
