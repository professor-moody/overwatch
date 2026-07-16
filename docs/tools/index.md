# Tool Reference

Overwatch exposes its MCP tools organized by function (the live count comes from `get_system_prompt(role="primary")`). Each tool uses Zod schemas for input validation and returns structured JSON.

## Tool Overview

| Tool | Purpose | Read-only |
|------|---------|-----------|
| [`get_state`](get-state.md) | Full engagement briefing from graph | Yes |
| [`get_recovery_status`](get-recovery-status.md) | WAL/state recovery and active config convergence | Yes |
| [`run_lab_preflight`](run-lab-preflight.md) | Aggregate lab-readiness checks | Yes |
| [`run_graph_health`](run-graph-health.md) | Full graph integrity report | Yes |
| [`get_opsec_status`](get-opsec-status.md) | Noise budget, recommended approach, defensive signals | Yes |
| [`recompute_objectives`](recompute-objectives.md) | Re-evaluate objective achievement status | No |
| [`verify_activity_chain`](verify-activity-chain.md) | Verify the tamper-evident activity hash chain | Yes |
| [`get_history`](get-history.md) | Full activity log | Yes |
| [`export_graph`](export-graph.md) | Complete graph dump | Yes |
| [`bundle_engagement`](bundle-engagement.md) | Portable archive with state, evidence, reports, manifest, and journal | No |
| [`next_task`](next-task.md) | Filtered frontier candidates for scoring | No |
| [`validate_action`](validate-action.md) | Pre-execution sanity check | No |
| [`approve_action`](approve-action.md) | Approve a pending action's live approval gate | No |
| [`deny_action`](deny-action.md) | Deny a pending action's live approval gate | No |
| [`log_action_event`](log-action-event.md) | Record action lifecycle events | No |
| [`log_thought`](log-thought.md) | Record plans, hypotheses, decisions, and reflections | No |
| [`run_bash`](run-bash.md) | Auto-instrumented one-shot shell execution | No |
| [`run_tool`](run-tool.md) | Auto-instrumented argv-form tool execution | No |
| [`report_finding`](report-finding.md) | Submit new nodes/edges to the graph | No |
| [`get_evidence`](get-evidence.md) | Retrieve full-fidelity evidence by ID or list stored evidence records | Yes |
| [`get_finding_readiness`](get-finding-readiness.md) | Per-finding proof-readiness audit (client_ready / needs_validation / draft) + gaps | Yes |
| [`parse_output`](parse-output.md) | Parse supported tool output into findings | No |
| [`ingest_json`](ingest-json.md) | Generic JSON/JSONL ingestion using caller-provided mappings | No |
| [`query_graph`](query-graph.md) | Open-ended graph exploration | Yes |
| [`find_paths`](find-paths.md) | Shortest paths to objectives | Yes |
| [`register_agent`](register-agent.md) | Dispatch a sub-agent task (TTL-leased) | No |
| [`dispatch_agents`](dispatch-agents.md) | Batch-dispatch agents from frontier | No |
| [`get_agent_context`](get-agent-context.md) | Scoped subgraph for an agent | Yes |
| [`update_agent`](update-agent.md) | Mark agent task complete/failed | No |
| [`submit_agent_transcript`](transcripts.md) | Sub-agent wrap-up with optional transcript evidence | No |
| [`propose_plan`](propose-plan.md) | Planner-role sub-agent: submit a free-form operator command as a confirmable plan of ops | No |
| [`ask_operator`](ask-operator.md) | Sub-agent escalates a decision to the operator and waits for an answer (delivered on heartbeat) | No |
| [`manage_agent_directive`](manage-agent-directive.md) | Steer a running sub-agent (pause/resume/stop/narrow/skip/prioritize/instruct) | No |
| [`acknowledge_agent_directive`](acknowledge-agent-directive.md) | Sub-agent confirms it received a directive | No |
| [`research_cve`](research-cve.md) | Record operator-style CVE/exploit research for a versioned service | No |
| [`agent_heartbeat`](agent-heartbeat.md) | Sub-agent liveness ping (extends lease) | No |
| [`dispatch_subnet_agents`](dispatch-subnet-agents.md) | Dispatch one agent per scope CIDR for parallel enumeration | No |
| [`dispatch_campaign_agents`](dispatch-campaign-agents.md) | Dispatch agents for a campaign's grouped frontier items | No |
| [`manage_campaign`](manage-campaign.md) | Create, monitor, pause, resume, or abort campaigns | No |
| [`get_decision_log`](get-decision-log.md) | Per-decision timeline (frontier → completed) over the activity log | Yes |
| [`explain_action`](explain-action.md) | "Why did the agent do X?" — full chain for an action_id | Yes |
| [`get_timeline`](get-timeline.md) | Per-node/edge "what was true at time T" view | Yes |
| [`ingest_transcript`](transcripts.md) | Import external chat/IDE JSONL transcript into the activity log | No |
| [`register_tape_session`](tape-sessions.md) | Register an external JSON-RPC tape pointer for retrospectives | No |
| [`get_skill`](get-skill.md) | RAG search over skill library | Yes |
| [`suggest_inference_rule`](suggest-inference-rule.md) | Add a custom inference rule | No |
| [`ingest_bloodhound`](ingest-bloodhound.md) | Import BloodHound JSON collections | No |
| [`ingest_azurehound`](ingest-azurehound.md) | Import AzureHound / ROADtools JSON collections | No |
| [`connect_postgres`](postgres.md) | Open an in-process PostgreSQL connection for this server session | No |
| [`list_postgres_tables`](postgres.md) | List visible PostgreSQL tables from the active connection | Yes |
| [`ingest_postgres_table`](postgres.md) | Ingest rows from a PostgreSQL table into graph nodes | No |
| [`validate_token_credential`](token-credential.md) | Replay a token credential against a provider API | No |
| [`test_webapp_credential`](test-webapp-credential.md) | Test a credential against a web app (form/basic/bearer/cookie) | No |
| [`ingest_screenshots`](ingest-screenshots.md) | Ingest gowitness/aquatone PNGs as viewable screenshot evidence | No |
| [`expand_aws_credential`](cloud-playbooks.md) | Generate a dependency-aware AWS recon plan from a captured credential | Yes |
| [`expand_github_credential`](cloud-playbooks.md) | Generate a paginated GitHub recon plan from a captured token | Yes |
| [`expand_entra_credential`](cloud-playbooks.md) | Generate a tenant-bound Entra ID / Microsoft Graph recon plan | Yes |
| [`exchange_refresh_token`](cloud-playbooks.md) | Generate a refresh-token exchange step for Entra tokens | Yes |
| [`expand_oidc_capture`](cloud-playbooks.md) | Generate replay steps for captured CI/CD OIDC tokens | Yes |
| [`check_tools`](check-tools.md) | Inspect installed offensive tooling | Yes |
| [`track_process`](track-process.md) | Register a long-running scan | No |
| [`check_processes`](check-processes.md) | Inspect tracked process state | Yes |
| [`correct_graph`](correct-graph.md) | Transactional graph repair | No |
| [`run_retrospective`](run-retrospective.md) | Post-engagement analysis | Yes |
| [`open_session`](sessions.md) | Create persistent interactive session (SSH, PTY, socket) | No |
| [`write_session`](sessions.md) | Write raw bytes to a session | No |
| [`read_session`](sessions.md) | Cursor-based read from session buffer | Yes |
| [`send_to_session`](sessions.md) | Instrumented command send with validation, action logging, and evidence capture | No |
| [`list_sessions`](sessions.md) | List sessions with metadata | Yes |
| [`resume_session`](sessions.md) | Explicitly rebind a recovered rearm listener | No |
| [`update_session`](sessions.md) | Update capabilities, title, ownership | No |
| [`resize_session`](sessions.md) | Resize terminal dimensions | No |
| [`signal_session`](sessions.md) | Send signal to session process | No |
| [`close_session`](sessions.md) | Close and destroy a session | No |
| [`update_scope`](update-scope.md) | Confirmation-gated runtime scope expansion/contraction | No |
| [`resolve_config_divergence`](resolve-config-divergence.md) | Reconcile active config using explicit file or durable-state authority | No |
| [`create_engagement`](create-engagement.md) | Build + persist a new engagement config (no hand-edited JSON; create-then-start) | No |
| [`list_engagements`](list-engagements.md) | List persisted engagement configs + which is active | No |
| [`add_objective`](add-objective.md) | Add an objective to the active engagement | No |
| [`set_opsec`](set-opsec.md) | Update the active engagement's OPSEC policy (confirmation-gated) | No |
| [`get_system_prompt`](get-system-prompt.md) | Generate dynamic agent instructions from engagement state | No |
| [`generate_report`](generate-report.md) | Full pentest report with findings, narrative, evidence, remediation | Yes |
| [`register_mock_service`](register-mock-service.md) | Register an operator-controlled decoy / listener / relay as a graph node | No |

## Tool Categories

### Engagement Setup

Conversational engagement creation + configuration — so nobody hand-edits
`engagement.json`. [`create_engagement`](create-engagement.md) /
[`list_engagements`](list-engagements.md) build + list configs (create-then-start:
restart to activate); [`add_objective`](add-objective.md),
[`set_opsec`](set-opsec.md), and [`update_scope`](update-scope.md) configure the
active engagement.

If the active file, runtime, and durable state disagree, use
[`get_recovery_status`](get-recovery-status.md) to inspect the exact observed
hashes, then [`resolve_config_divergence`](resolve-config-divergence.md) to make
an explicit, optimistic-concurrency-checked authority choice.

### State & Health
Tools for understanding the current engagement state and verifying system health.

### Scoring & Validation
The core action loop — get frontier items, validate proposed actions, log execution.

### Findings & Parsing
How new information enters the graph — manual findings or deterministic parsing.

### Graph Exploration
Direct graph access for creative analysis beyond the scored frontier.

### Agents
Sub-agent lifecycle — register, scope, heartbeat, and track parallel work. Frontier leases (`register_agent`) prevent agent races; the watchdog reaps silent agents past their `heartbeat_ttl_seconds`. Specialized roles carry allowlist-restricted toolsets: `research` (web + `research_cve`, no target execution) and `planner` (graph read + `propose_plan`, translates a free-form operator command into a confirmable plan — proposes only, never executes).

### Visibility & Introspection
"What did the agent do, and why?" — the [decision log](get-decision-log.md), [`explain_action`](explain-action.md) for a single action's full chain, and [`get_timeline`](get-timeline.md) for per-node/edge "what was true at time T" queries. All read-only and derived from the activity log.

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

### Operator Infrastructure
First-class graph nodes for decoys, listeners, and relays the operator stands up — Responder, `ntlmrelayx`, fake LDAP, redirectors, reverse-shell catchers — so captured credentials, baited callers, and relay chains attribute back to the listener that caused them. See [`register_mock_service`](register-mock-service.md).

### Analysis
Post-engagement retrospective and training data export.
