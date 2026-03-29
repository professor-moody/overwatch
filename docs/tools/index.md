# Tool Reference

Overwatch exposes 39 MCP tools organized by function. Each tool uses Zod schemas for input validation and returns structured JSON.

## Tool Overview

| Tool | Purpose | Read-only |
|------|---------|-----------|
| [`get_state`](get-state.md) | Full engagement briefing from graph | :white_check_mark: |
| [`run_lab_preflight`](run-lab-preflight.md) | Aggregate lab-readiness checks | :white_check_mark: |
| [`run_graph_health`](run-graph-health.md) | Full graph integrity report | :white_check_mark: |
| [`recompute_objectives`](#) | Re-evaluate objective achievement status | :x: |
| [`get_history`](get-history.md) | Full activity log | :white_check_mark: |
| [`export_graph`](export-graph.md) | Complete graph dump | :white_check_mark: |
| [`next_task`](next-task.md) | Filtered frontier candidates for scoring | :x: |
| [`validate_action`](validate-action.md) | Pre-execution sanity check | :x: |
| [`log_action_event`](log-action-event.md) | Record action lifecycle events | :x: |
| [`report_finding`](report-finding.md) | Submit new nodes/edges to the graph | :x: |
| [`parse_output`](parse-output.md) | Parse supported tool output into findings | :x: |
| [`query_graph`](query-graph.md) | Open-ended graph exploration | :white_check_mark: |
| [`find_paths`](find-paths.md) | Shortest paths to objectives | :white_check_mark: |
| [`register_agent`](register-agent.md) | Dispatch a sub-agent task | :x: |
| [`dispatch_agents`](#) | Batch-dispatch agents from frontier | :x: |
| [`get_agent_context`](get-agent-context.md) | Scoped subgraph for an agent | :white_check_mark: |
| [`update_agent`](update-agent.md) | Mark agent task complete/failed | :x: |
| [`dispatch_subnet_agents`](dispatch-subnet-agents.md) | Dispatch one agent per scope CIDR for parallel enumeration | :x: |
| [`get_skill`](get-skill.md) | RAG search over skill library | :white_check_mark: |
| [`suggest_inference_rule`](suggest-inference-rule.md) | Add a custom inference rule | :x: |
| [`ingest_bloodhound`](ingest-bloodhound.md) | Import BloodHound JSON collections | :x: |
| [`check_tools`](check-tools.md) | Inspect installed offensive tooling | :white_check_mark: |
| [`track_process`](track-process.md) | Register a long-running scan | :x: |
| [`check_processes`](check-processes.md) | Inspect tracked process state | :white_check_mark: |
| [`correct_graph`](correct-graph.md) | Transactional graph repair | :x: |
| [`run_retrospective`](run-retrospective.md) | Post-engagement analysis | :white_check_mark: |
| [`open_session`](sessions.md) | Create persistent interactive session (SSH, PTY, socket) | :x: |
| [`write_session`](sessions.md) | Write raw bytes to a session | :x: |
| [`read_session`](sessions.md) | Cursor-based read from session buffer | :white_check_mark: |
| [`send_to_session`](sessions.md) | [Experimental] Write + wait + read | :x: |
| [`list_sessions`](sessions.md) | List sessions with metadata | :white_check_mark: |
| [`update_session`](sessions.md) | Update capabilities, title, ownership | :x: |
| [`resize_session`](sessions.md) | Resize terminal dimensions | :x: |
| [`signal_session`](sessions.md) | Send signal to session process | :x: |
| [`close_session`](sessions.md) | Close and destroy a session | :x: |
| [`update_scope`](update-scope.md) | Confirmation-gated runtime scope expansion/contraction | :x: |
| [`get_system_prompt`](get-system-prompt.md) | Generate dynamic agent instructions from engagement state | :white_check_mark: |
| [`generate_report`](generate-report.md) | Full pentest report with findings, narrative, evidence, remediation | :white_check_mark: |
| [`ingest_azurehound`](ingest-azurehound.md) | Import AzureHound / ROADtools JSON collections | :x: |

## Tool Categories

### State & Health
Tools for understanding the current engagement state and verifying system health.

### Scoring & Validation
The core action loop — get frontier items, validate proposed actions, log execution.

### Findings & Parsing
How new information enters the graph — manual findings or deterministic parsing.

### Graph Exploration
Direct graph access for creative analysis beyond the scored frontier.

### Agents
Sub-agent lifecycle — register, scope, and track parallel work.

### Skills & Inference
Methodology guidance and dynamic rule creation.

### Ingestion
Bulk data import from external tools (BloodHound, AzureHound/ROADtools).

### Utilities
System-level checks and process tracking.

### Sessions
Persistent interactive sessions — SSH, local PTY, and TCP socket (reverse shell). Cursor-based I/O with ownership enforcement.

### Reporting
Pentest report generation with per-finding detail, attack narrative, evidence chains, and HTML export.

### Analysis
Post-engagement retrospective and training data export.
