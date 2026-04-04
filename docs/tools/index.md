# Tool Reference

Overwatch exposes 40 MCP tools organized by function. Each tool uses Zod schemas for input validation and returns structured JSON.

## Tool Overview

| Tool | Purpose | Read-only |
|------|---------|-----------|
| [`get_state`](get-state.md) | Full engagement briefing from graph | Yes |
| [`run_lab_preflight`](run-lab-preflight.md) | Aggregate lab-readiness checks | Yes |
| [`run_graph_health`](run-graph-health.md) | Full graph integrity report | Yes |
| [`recompute_objectives`](#) | Re-evaluate objective achievement status | No |
| [`get_history`](get-history.md) | Full activity log | Yes |
| [`export_graph`](export-graph.md) | Complete graph dump | Yes |
| [`next_task`](next-task.md) | Filtered frontier candidates for scoring | No |
| [`validate_action`](validate-action.md) | Pre-execution sanity check | No |
| [`log_action_event`](log-action-event.md) | Record action lifecycle events | No |
| [`report_finding`](report-finding.md) | Submit new nodes/edges to the graph | No |
| [`get_evidence`](#) | Retrieve full-fidelity evidence by ID or list stored evidence records | Yes |
| [`parse_output`](parse-output.md) | Parse supported tool output into findings | No |
| [`query_graph`](query-graph.md) | Open-ended graph exploration | Yes |
| [`find_paths`](find-paths.md) | Shortest paths to objectives | Yes |
| [`register_agent`](register-agent.md) | Dispatch a sub-agent task | No |
| [`dispatch_agents`](#) | Batch-dispatch agents from frontier | No |
| [`get_agent_context`](get-agent-context.md) | Scoped subgraph for an agent | Yes |
| [`update_agent`](update-agent.md) | Mark agent task complete/failed | No |
| [`dispatch_subnet_agents`](dispatch-subnet-agents.md) | Dispatch one agent per scope CIDR for parallel enumeration | No |
| [`get_skill`](get-skill.md) | RAG search over skill library | Yes |
| [`suggest_inference_rule`](suggest-inference-rule.md) | Add a custom inference rule | No |
| [`ingest_bloodhound`](ingest-bloodhound.md) | Import BloodHound JSON collections | No |
| [`check_tools`](check-tools.md) | Inspect installed offensive tooling | Yes |
| [`track_process`](track-process.md) | Register a long-running scan | No |
| [`check_processes`](check-processes.md) | Inspect tracked process state | Yes |
| [`correct_graph`](correct-graph.md) | Transactional graph repair | No |
| [`run_retrospective`](run-retrospective.md) | Post-engagement analysis | Yes |
| [`open_session`](sessions.md) | Create persistent interactive session (SSH, PTY, socket) | No |
| [`write_session`](sessions.md) | Write raw bytes to a session | No |
| [`read_session`](sessions.md) | Cursor-based read from session buffer | Yes |
| [`send_to_session`](sessions.md) | [Experimental] Write + wait + read | No |
| [`list_sessions`](sessions.md) | List sessions with metadata | Yes |
| [`update_session`](sessions.md) | Update capabilities, title, ownership | No |
| [`resize_session`](sessions.md) | Resize terminal dimensions | No |
| [`signal_session`](sessions.md) | Send signal to session process | No |
| [`close_session`](sessions.md) | Close and destroy a session | No |
| [`update_scope`](update-scope.md) | Confirmation-gated runtime scope expansion/contraction | No |
| [`get_system_prompt`](get-system-prompt.md) | Generate dynamic agent instructions from engagement state | Yes |
| [`generate_report`](generate-report.md) | Full pentest report with findings, narrative, evidence, remediation | Yes |
| [`ingest_azurehound`](ingest-azurehound.md) | Import AzureHound / ROADtools JSON collections | No |

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
