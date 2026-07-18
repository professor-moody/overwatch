# Tool Reference

Overwatch exposes its generated MCP inventory organized by function. Each tool uses Zod input validation. Successful results currently use MCP text content containing JSON unless a tool documents another format; the manifest records `output_schema: null` until structured MCP output contracts are added rather than inventing permissive schemas.

The checked-in [schema manifest](../reference/tool-schema-manifest.json) records the canonical names, categories, annotations, documentation paths, archetype exposure, persistence behavior, MCP-compatible input schemas, and SHA-256 hashes. CI rejects drift from runtime registration.

## Tool Overview

<!-- BEGIN:tool-inventory -->
| Tool | Purpose | Category | Persistence |
|------|---------|----------|-------------|
| [`find_paths`](find-paths.md) | Find paths through the graph from current access to objectives or between specific nodes. | State & readiness | Read-only |
| [`get_opsec_status`](get-opsec-status.md) | Read the engagement's OPSEC posture: noise budget spent, the recommended approach (quiet/normal/loud), and any defensive signals observed (lockouts, rate limits, honeypots, connection resets, blocks). | State & readiness | Read-only |
| [`get_recovery_status`](get-recovery-status.md) | Inspect WAL/state recovery, persisted state/journal format migration, active file/runtime/state configuration convergence, and unresolved detached-process ownership. | State & readiness | Read-only |
| [`get_skill`](get-skill.md) | Search the skill library for methodology guidance relevant to a scenario. | State & readiness | Read-only |
| [`get_state`](get-state.md) | Returns the current operational briefing synthesized from durable engagement state. | State & readiness | Conditional |
| [`get_system_prompt`](get-system-prompt.md) | Generate a dynamic system prompt for an MCP consumer based on the current engagement state. | State & readiness | Conditional |
| [`next_task`](next-task.md) | Returns frontier items (candidate next actions) with graph context attached. | State & readiness | Mutating |
| [`query_graph`](query-graph.md) | Direct access to the engagement graph for open-ended analysis. | State & readiness | Read-only |
| [`run_graph_health`](run-graph-health.md) | Run read-only graph integrity checks across the current engagement graph. | State & readiness | Read-only |
| [`run_lab_preflight`](run-lab-preflight.md) | Run a read-only lab-readiness check for the current engagement. | State & readiness | Read-only |
| [`approve_action`](approve-action.md) | Approve a currently pending Overwatch action by action_id. | Execution & approval | Mutating |
| [`check_processes`](check-processes.md) | List all tracked processes and their current status. | Execution & approval | Mutating |
| [`check_tools`](check-tools.md) | Check which offensive security tools are installed on this system. | Execution & approval | Read-only |
| [`deny_action`](deny-action.md) | Deny a currently pending Overwatch action by action_id. | Execution & approval | Mutating |
| [`log_action_event`](log-action-event.md) | Record a structured action lifecycle event for work Overwatch cannot observe directly. | Execution & approval | Mutating |
| [`log_thought`](log-thought.md) | Persist a piece of the agent's reasoning into the engagement activity log. | Execution & approval | Mutating |
| [`run_bash`](run-bash.md) | Execute a shell command via bash -c with full action-lifecycle instrumentation. | Execution & approval | Mutating |
| [`run_tool`](run-tool.md) | Execute a binary with an explicit argv array, fully instrumented like run_bash. | Execution & approval | Mutating |
| [`track_process`](track-process.md) | Register a long-running scan or process for tracking. | Execution & approval | Mutating |
| [`validate_action`](validate-action.md) | Validate a proposed action against the graph state and OPSEC policy BEFORE executing it. | Execution & approval | Mutating |
| [`correct_graph`](correct-graph.md) | Repair existing graph state explicitly and transactionally. | Graph & data | Mutating |
| [`export_graph`](export-graph.md) | Export the complete engagement graph with all nodes, edges, and properties. | Graph & data | Read-only |
| [`get_evidence`](get-evidence.md) | Retrieve full-fidelity evidence stored during findings. | Graph & data | Read-only |
| [`get_finding_readiness`](get-finding-readiness.md) | Audit findings for proof readiness before reporting. | Graph & data | Read-only |
| [`ingest_azurehound`](ingest-azurehound.md) | Parse and ingest AzureHound or ROADtools JSON output into the engagement graph. | Graph & data | Mutating |
| [`ingest_bloodhound`](ingest-bloodhound.md) | Parse and ingest SharpHound or bloodhound-python JSON output into the engagement graph. | Graph & data | Mutating |
| [`ingest_json`](ingest-json.md) | Ingest tool output in JSON or JSONL format directly into the engagement graph without a dedicated parser. | Graph & data | Mutating |
| [`ingest_screenshots`](ingest-screenshots.md) | Read a visual-recon report's PNG files off disk and ingest them so they're VIEWABLE in the dashboard. | Graph & data | Mutating |
| [`parse_output`](parse-output.md) | Parse raw output from common offensive tools into structured graph data. | Graph & data | Mutating |
| [`recompute_objectives`](recompute-objectives.md) | Re-evaluate all engagement objectives from the current graph state. | Graph & data | Mutating |
| [`report_finding`](report-finding.md) | Report a discovery from agent execution. | Graph & data | Mutating |
| [`suggest_inference_rule`](suggest-inference-rule.md) | Propose a new inference rule to add to the engagement's active rule set. | Graph & data | Mutating |
| [`acknowledge_agent_directive`](acknowledge-agent-directive.md) | Sub-agents call this to confirm they received a steering directive (delivered via the pending_directive field on agent_heartbeat). | Agents & planning | Mutating |
| [`agent_heartbeat`](agent-heartbeat.md) | Sub-agents call this periodically (recommended every 30–60 seconds) to signal liveness. | Agents & planning | Mutating |
| [`ask_operator`](ask-operator.md) | Escalate a decision to the human operator and WAIT for their answer. | Agents & planning | Mutating |
| [`dispatch_agents`](dispatch-agents.md) | Batch-register sub-agent tasks from the current filtered frontier. | Agents & planning | Mutating |
| [`dispatch_campaign_agents`](dispatch-campaign-agents.md) | Dispatch sub-agents for each item in a campaign, using campaign-aware scoping. | Agents & planning | Mutating |
| [`dispatch_subnet_agents`](dispatch-subnet-agents.md) | Dispatch one sub-agent per scope CIDR for parallel network enumeration. | Agents & planning | Mutating |
| [`find_duplicate_agent_work`](agent-work.md) | Find groups of agent tasks that have the same canonical work signature. | Agents & planning | Read-only |
| [`get_agent_context`](get-agent-context.md) | Returns the scoped subgraph view for a registered agent. | Agents & planning | Read-only |
| [`handoff_agent_work`](agent-work.md) | Create one durable successor for a terminal agent task. | Agents & planning | Mutating |
| [`manage_agent_directive`](manage-agent-directive.md) | Steer a running sub-agent. | Agents & planning | Mutating |
| [`manage_campaign`](manage-campaign.md) | Create, control, and manage campaigns. | Agents & planning | Mutating |
| [`merge_duplicate_agent_work`](agent-work.md) | Mark terminal exact-duplicate agent tasks as merged into one canonical task. | Agents & planning | Mutating |
| [`propose_plan`](propose-plan.md) | Submit a plan of operator operations for the human operator to confirm. | Agents & planning | Mutating |
| [`register_agent`](register-agent.md) | Register a new sub-agent task. | Agents & planning | Mutating |
| [`research_cve`](research-cve.md) | Record the outcome of operator-style CVE/exploit research for a versioned service. | Agents & planning | Mutating |
| [`split_agent_work`](agent-work.md) | Split one terminal ad-hoc node task into two to twenty durable child tasks. | Agents & planning | Mutating |
| [`submit_agent_transcript`](transcripts.md) | Sub-agent wrap-up: hand the primary session a short summary plus an optional raw transcript blob. | Agents & planning | Mutating |
| [`update_agent`](update-agent.md) | Update the status of a running agent task. | Agents & planning | Mutating |
| [`complete_playbook_attempt`](cloud-playbooks.md) | Record a pre-execution failure or the durable outcome and evidence/finding references for an attempt that crossed the instrumented execution boundary. | Credentials & playbooks | Mutating |
| [`connect_postgres`](postgres.md) | Establish a read-only connection to an operator-controlled PostgreSQL database. | Credentials & playbooks | Mutating |
| [`exchange_refresh_token`](cloud-playbooks.md) | Generate a step to exchange a captured Entra refresh token for a fresh access token via Microsoft's /oauth2/v2.0/token endpoint. | Credentials & playbooks | Mutating |
| [`expand_aws_credential`](cloud-playbooks.md) | Generate a dependency-aware AWS reconnaissance plan for a captured credential. | Credentials & playbooks | Mutating |
| [`expand_entra_credential`](cloud-playbooks.md) | Generate a tenant-dump recon plan for a captured Entra access token. | Credentials & playbooks | Mutating |
| [`expand_github_credential`](cloud-playbooks.md) | Generate a structured recon plan for a captured GitHub credential (PAT / OAuth token / fine-grained PAT / GitHub App installation token). | Credentials & playbooks | Mutating |
| [`expand_oidc_capture`](cloud-playbooks.md) | For a captured OIDC token (GitHub Actions / GitLab CI / CircleCI), walk the inferred ASSUMES_ROLE edges (from OIDC_FEDERATION_PIVOT) and emit one validate_token_credential step per candidate cloud role. | Credentials & playbooks | Mutating |
| [`get_playbook_run`](cloud-playbooks.md) | Inspect one durable credential-playbook run, including every retained plan revision and attempt. | Credentials & playbooks | Read-only |
| [`ingest_postgres_table`](postgres.md) | Read rows from a postgres table and ingest them into the engagement graph. | Credentials & playbooks | Mutating |
| [`interrupt_playbook_attempt`](cloud-playbooks.md) | Release an active step claim that will not be executed or completed. | Credentials & playbooks | Mutating |
| [`list_playbook_runs`](cloud-playbooks.md) | List durable credential-playbook runs, their step states, and append-only attempts. | Credentials & playbooks | Read-only |
| [`list_postgres_tables`](postgres.md) | List tables and columns in the connected postgres database. | Credentials & playbooks | Read-only |
| [`resume_playbook_run`](cloud-playbooks.md) | Re-open interrupted steps after restart. | Credentials & playbooks | Mutating |
| [`retry_playbook_step`](cloud-playbooks.md) | Append a new attempt for a failed or interrupted step and return its resolved execution descriptor. | Credentials & playbooks | Mutating |
| [`skip_playbook_step`](cloud-playbooks.md) | Skip one non-terminal step while retaining the reason and every prior attempt. | Credentials & playbooks | Mutating |
| [`start_playbook_step`](cloud-playbooks.md) | Reserve exactly one ready playbook step and return its resolved execution descriptor. | Credentials & playbooks | Mutating |
| [`test_webapp_credential`](test-webapp-credential.md) | Test a credential already in the graph against a web application in one call, then record the result so credential coverage retires and authenticated re-scan fires. | Credentials & playbooks | Mutating |
| [`validate_token_credential`](token-credential.md) | Probe an IdP / cloud API with a captured token credential to confirm it actually authenticates, then update the credential's status + emit a VALID_FOR_APP edge based on the response. | Credentials & playbooks | Mutating |
| [`close_session`](sessions.md) | Close and destroy a session. | Sessions & runtime | Mutating |
| [`list_sessions`](sessions.md) | List all sessions with metadata (no output buffers). | Sessions & runtime | Read-only |
| [`open_session`](sessions.md) | Create a new persistent interactive session. | Sessions & runtime | Mutating |
| [`read_session`](sessions.md) | Read output from a session buffer using cursor-based positioning. | Sessions & runtime | Read-only |
| [`register_mock_service`](register-mock-service.md) | Register an operator-controlled decoy / listener / relay as a first-class node in the engagement graph. | Sessions & runtime | Mutating |
| [`resize_session`](sessions.md) | Resize terminal dimensions. | Sessions & runtime | Mutating |
| [`resume_session`](sessions.md) | Explicitly rebind a recovered rearm socket listener. | Sessions & runtime | Mutating |
| [`send_to_session`](sessions.md) | Run a command in a persistent session with full action-lifecycle instrumentation. | Sessions & runtime | Mutating |
| [`signal_session`](sessions.md) | Send a signal to the session process. | Sessions & runtime | Mutating |
| [`update_session`](sessions.md) | Update session metadata: capabilities, title, notes, or ownership. | Sessions & runtime | Mutating |
| [`write_session`](sessions.md) | Write raw bytes to a session. | Sessions & runtime | Mutating |
| [`add_objective`](add-objective.md) | Add an objective (goal) to the ACTIVE engagement. | Configuration & scope | Mutating |
| [`create_engagement`](create-engagement.md) | Build + persist a new engagement config so nobody hand-edits engagement.json. | Configuration & scope | Mutating |
| [`list_engagements`](list-engagements.md) | List the persisted engagement configs (engagements/.json) and which one is currently active. | Configuration & scope | Read-only |
| [`resolve_config_divergence`](resolve-config-divergence.md) | Explicitly choose file or durable-state authority when active configuration representations diverge. | Configuration & scope | Mutating |
| [`set_opsec`](set-opsec.md) | Update the ACTIVE engagement's OPSEC policy (noise ceiling, enforcement, approval mode, time window, technique blacklist) — no hand-edited config. | Configuration & scope | Mutating |
| [`update_scope`](update-scope.md) | Expand or contract the engagement scope at runtime. | Configuration & scope | Mutating |
| [`bundle_engagement`](bundle-engagement.md) | Package all engagement artefacts into a single portable .tar.gz archive. | Audit & reporting | Conditional |
| [`explain_action`](explain-action.md) | Returns the full "why" for any action_id: the frontier item that motivated it, the agent's recorded thoughts and considered alternatives, prior action references, validation and approval state, and the terminal outcome. | Audit & reporting | Read-only |
| [`generate_report`](generate-report.md) | Generate a comprehensive penetration test report from the engagement graph and activity history. | Audit & reporting | Conditional |
| [`get_decision_log`](get-decision-log.md) | Returns the derived decision log: each entry is one decision (frontier item or action) with its full chain of stages — frontier_emitted → agent_picked → log_thought → validated → approved/denied → started → completed/… | Audit & reporting | Read-only |
| [`get_history`](get-history.md) | Returns paginated activity log entries for the engagement. | Audit & reporting | Read-only |
| [`get_timeline`](get-timeline.md) | Returns per-node and per-edge timeline entries. | Audit & reporting | Read-only |
| [`ingest_transcript`](transcripts.md) | Pull an external chat/IDE transcript JSONL into the engagement after the fact. | Audit & reporting | Mutating |
| [`register_tape_session`](tape-sessions.md) | Register an external JSON-RPC tape (produced by overwatch-mcp-tape) with this engagement. | Audit & reporting | Mutating |
| [`run_retrospective`](run-retrospective.md) | Perform a structured post-engagement retrospective analysis. | Audit & reporting | Conditional |
| [`verify_activity_chain`](verify-activity-chain.md) | Verify the tamper-evident hash chain over the engagement's live activity log. | Audit & reporting | Read-only |
<!-- END:tool-inventory -->

## Tool Categories

### Engagement Setup

Conversational engagement creation + configuration — so nobody hand-edits
`engagement.json`. [`create_engagement`](create-engagement.md) creates an
inactive config and [`list_engagements`](list-engagements.md) lists active and
inactive configs; neither switches the running daemon, and dashboard switching
is not currently supported. [`add_objective`](add-objective.md),
[`set_opsec`](set-opsec.md), and [`update_scope`](update-scope.md) configure the
current active engagement through the revisioned write-through path.

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
