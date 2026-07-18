# FAQ

Frequently asked questions about Overwatch.

## General

### How does Overwatch survive context compaction?

Durable engagement truth lives **outside** the context window in the Overwatch
daemon and its persisted state. When Claude Code compacts, it may lose
conversation detail, but it can rebuild an operational briefing by calling
`get_state()`: scope, discoveries, access, objectives, frontier, agents, and
recent activity. That briefing is not a lossless export of every event or
evidence byte. Retrieve those through `get_history`, `get_evidence`, reports,
or `bundle_engagement`.

Live PTYs, socket connections, process objects, terminal buffers, and database
connections are ephemeral. Overwatch persists truthful descriptors and resume
intent where supported; it does not claim those live handles survived a
process restart.

See [Compaction](concepts.md#compaction) for details.

### What is the current engagement model?

One daemon owns one current active engagement. Terminal Claude, the dashboard,
the CLI, planners, and deployed agents all share it. Add scope through
**Console → Add Targets** or `update_scope`; edit objectives and OPSEC through
**Settings** or `add_objective` / `set_opsec`.

**New Engagement** and `create_engagement` can write another inactive
configuration, and `list_engagements` can list it. Creation does not switch the
running daemon, and the dashboard does not currently support engagement
switching.

### Can I run multiple engagements simultaneously?

Not in a single server instance. Each Overwatch server runs one engagement. To run multiple engagements, start multiple server instances with different `OVERWATCH_CONFIG` paths and `OVERWATCH_DASHBOARD_PORT` values, and configure separate MCP entries in Claude Code.

### Can I use this with models other than Claude?

Overwatch is a standard MCP server with stdio and authenticated streamable HTTP
transports. Any compatible client can use the corresponding transport. The
shipped `AGENTS.md` session instructions and managed headless-agent runner are
written for Claude Code specifically; another model/client needs equivalent
operator instructions and may not support dashboard-managed workers.

The core server functionality (graph operations, inference rules, parsers, persistence) is model-agnostic.

### How do I validate a change to the agent prompt?

Use the [behavior-eval harness](prompt-eval.md), not your judgment. A deterministic rubric grader + structural affordance guard run in CI ($0) and catch a prompt that drops a load-bearing affordance. To measure real agent behavior, run the on-demand, cost-bounded real-model A/B: `npm run prompt-eval -- --real --variant lean --yes` compares a candidate prompt variant against the cached `control` baseline and flags any per-criterion regression.

### How do I reset an engagement?

Stop the daemon, preserve the complete engagement directory, and restart with a
new explicit state path:

```bash
cp -a /path/to/engagement /path/to/engagement-before-reset
export OVERWATCH_STATE_FILE=/path/to/engagement/state-<engagement-id>-fresh-$(date +%Y%m%d%H%M%S).json
# Restart Overwatch with the same validated engagement.json
```

Do not reset by deleting only `state-<id>.json`: a retained WAL, snapshot,
rollback intent, or migration intent deliberately prevents silent reseeding.
Using a new path creates a fresh graph while preserving the old state, evidence,
reports, and rollback authority.

### How do I resume a previous engagement?

Start the same daemon with the same `OVERWATCH_CONFIG` and state path. It loads
the newest valid base and replays complete committed journal transactions. Call
`get_recovery_status` (or `overwatch recovery`) first if startup is degraded,
then `get_state` for the current operational briefing. Do not delete state,
snapshots, WAL, or intents to force startup.

## Graph & Findings

### What's the difference between `parse_output` and `report_finding`?

- **`parse_output`** — deterministic parser for supported tools (nmap, nxc, certipy, secretsdump, kerbrute, hashcat, responder, ldapsearch, enum4linux, rubeus, gobuster/feroxbuster/ffuf, linpeas/linenum, nuclei, nikto, testssl/sslscan, pacu, prowler, burp, zap, sqlmap, wpscan). Extracts structured nodes/edges without LLM involvement. Token-efficient and consistent. Its shared parser context can carry credential, tenant, repository/branch, cloud, target, domain, host, and provider-extension attribution.
- **`report_finding`** — manual finding submission for unsupported tools, analyst observations, or already-structured data. The LLM constructs the nodes and edges.

Use `parse_output` whenever possible. See [parse_output vs report_finding](playbook/parse-vs-report.md) for detailed guidance.

### How do I add a custom parser?

1. Add the parser function in `src/services/parsers/`
2. Register the parser name in the `parsers` map
3. Add tests in `src/services/__tests__/output-parsers.test.ts`
4. Update the `parse_output` tool description in `src/tools/parse-output.ts`

See [Development — Adding a New Parser](development.md#adding-a-new-parser).

### What if the state file gets corrupted?

Do not delete or rename the state, WAL, snapshots, config intents, or migration
intents. Startup evaluates the primary plus retained `.snapshots/` bases and
replays the WAL without discarding an unreadable or unsupported tail.

1. Stop target execution and run `overwatch recovery` if the service starts.
2. Run `overwatch state migrate --check --state-file <path> --config-file <path>`
   against the stopped/copy engagement.
3. Copy the complete engagement directory before attempting manual repair.
4. Preserve any `.quarantine-*`, `.migration-backups/`, rollback intent, and
   config-intent artifacts for diagnosis.

If no valid base exists, Overwatch remains read-only instead of silently
creating an empty engagement over durable bytes. Restore a verified backup or
repair the copied bundle; do not reseed in place.

### How do I add custom inference rules at runtime?

Use [`suggest_inference_rule`](tools/suggest-inference-rule.md):

```json
{
  "name": "Tomcat Manager Default Creds",
  "description": "Tomcat manager services often have default credentials",
  "trigger": {
    "node_type": "service",
    "property_match": { "service_name": "http", "version": "Apache Tomcat" }
  },
  "produces": [{
    "edge_type": "POTENTIAL_AUTH",
    "source_selector": "domain_credentials",
    "target_selector": "trigger_node",
    "confidence": 0.4
  }]
}
```

The rule takes effect immediately and fires on all existing matching nodes plus any future ones.

## Agents

### How do sub-agents get their scope?

When the primary session calls [`register_agent`](tools/register-agent.md), it can provide `subgraph_node_ids` — the specific node IDs relevant to the task. If omitted, the server auto-computes a scope from the frontier item's target nodes using N-hop BFS traversal.

The sub-agent then calls [`get_agent_context`](tools/get-agent-context.md) with its `task_id` to receive its scoped subgraph view — only the nodes and edges relevant to its task.

### Can agents conflict with each other?

Terminal Claude, the dashboard, the CLI, and managed agents intentionally share
one engine. The engine coordinates them through application-command
idempotency, frontier leases, durable playbook ownership, and transactional
writes:

- Node IDs are deterministic, so duplicate discoveries merge automatically.
- Edge properties are merged (higher confidence wins).
- Inference rules fire on each new finding independently.
- The activity log preserves the ordered sequence of recorded events from all agents.
- A duplicate command/idempotency key returns its original outcome rather than
  dispatching twice.
- A playbook step has one active owner/attempt; an operator who decides not to
  run a prepared step releases it with `interrupt_playbook_attempt`.

For **frontier item** races (two agents trying to claim the same item), the engine takes a TTL lease at `register_agent` time. The losing agent gets `lease_conflict` and picks a different item. See [Concepts → Agent Heartbeat and Watchdog](concepts.md#agent-heartbeat-and-watchdog) and [`register_agent`](tools/register-agent.md).

Run exactly one Overwatch daemon for an engagement. The default `npm run setup`
points terminal Claude at that owner; it must not launch a parallel stdio
writer.

### Will dashboard agents interfere with Claude in my terminal?

They share engagement state on purpose, but they do not share a Claude session.
Each dashboard-managed worker launches with a temporary task-specific MCP
configuration, strict MCP isolation, user-only Claude settings, and Claude
session persistence disabled. This keeps your normal user authentication while
excluding the terminal checkout's project MCP servers, hooks/settings, and
resume history. Durable task leases and playbook ownership coordinate actual
Overwatch work across both surfaces.

If planners repeatedly fail immediately, run `npm run doctor`: it verifies that
the installed Claude CLI supports the isolation flags required by managed
workers. Also confirm the daemon build matches the checkout.

### Why does a dashboard planner appear stuck or finish without a plan?

Planning is asynchronous and server-owned. The dashboard records the command
and planner task, follows that durable command across reloads, and does not
declare failure merely because a browser timer expired. If the worker exits
without calling `propose_plan`, the command records that terminal outcome.

Run `npm run doctor` first. It catches the two common local causes: a running
daemon built from an older checkout, and a Claude CLI that lacks the strict MCP,
setting-source, or no-session-persistence flags required for isolated workers.
For a genuine worker failure, inspect `logs/agents/<task-id>.ndjson`; the task ID
is shown in the Fleet/command activity. Preserve that log when reporting the
problem.

### What's `engagement_nonce`? Why do new engagements have it but old ones don't?

The `engagement_nonce` is 32 random bytes minted at engagement creation. When present, the engine uses it to derive **deterministic** action and event IDs (`act_<16hex>` / `evt_<16hex>` from `sha256(nonce | agent | ts | cmd | seq)`) instead of `uuidv4`. Same inputs → same IDs across runs. This is what makes byte-identical replay possible.

**Strict migration**: legacy engagements (no nonce) keep `uuidv4` IDs forever. We do not retroactively recompute. If you need replay/audit guarantees on an existing engagement, create a fresh one and re-run the work.

### What's the difference between hash chain and content-addressed evidence?

They cover different attack surfaces:

- **Hash chain** (`hash_chain_enabled`, default true) protects the **activity log**. Each event carries `prev_hash` + `event_hash`. Modifying any old entry breaks the chain and is detectable via [`verify_activity_chain`](tools/verify-activity-chain.md). Signed checkpoints let verifiers resume without re-walking from genesis.
- **Content-addressed evidence** protects the **evidence files on disk**. Each evidence row's `content_hash = sha256(content)`. Tampering with content changes the address; the manifest no longer resolves. `get_evidence` lookups accept either UUID or hash.

You want both: the chain proves the log is intact, the addresses prove the evidence is intact.

## Dashboard

### How do I access the dashboard?

Open `http://localhost:8384` (or your configured port) in any modern browser. It starts automatically with the MCP server.

### Can I interact with the graph from the dashboard?

Yes. Graph exploration itself is read-mostly, but the dashboard is an operator
surface, not a read-only viewer. You can dispatch and steer agents, approve or
deny actions, manage campaigns and durable credential playbooks, edit active
scope/settings, reconcile configuration recovery, and generate reports. Those
mutations use the same validated command and persistence services as MCP and
the CLI.

You can:

- Drag nodes to reposition them
- Shift+click two nodes to see the shortest path
- Double-click to isolate a neighborhood
- Click frontier items to zoom to their target nodes
- Export PNG screenshots or SVG files via the Export dropdown
- Toggle **Attack Path** overlay to see the actual path taken (gold) and compare against the theoretical shortest path (cyan)
- Toggle **Credential Flow** to visualize credential relationships and derivation chains with status badges
- View credential derivation chains in the node detail panel
- Dispatch a canonical frontier item or ad-hoc target
- Approve actions and answer agent questions
- Confirm planner proposals and manage campaigns/playbooks

### The dashboard is blank or shows errors

- Run `npm run doctor`. It detects a stale compiled dashboard/runtime, an old
  daemon with a different build, unsupported managed-worker Claude flags, an
  unusable MCP token, and unexpected port ownership.
- Check that `OVERWATCH_DASHBOARD_PORT` is not `0` (disabled).
- Verify the port is not owned by another process. Overwatch deliberately
  refuses to start a second runtime owner.
- After a pull, run `npm run upgrade`, then `npm run doctor` and hard-reload the
  browser. Upgrade validates before downtime and preserves engagement artifacts.
- If a recovery banner reports read-only mode, inspect `overwatch recovery`.
  Do not delete engagement state; reconcile only with the exact hashes and
  allowed mode shown by the service.
- Open the browser console (F12) for JavaScript errors
- The dashboard requires WebGL — check browser compatibility
- Try a hard refresh (Ctrl+Shift+R)

### How do I open a remote authenticated dashboard?

Set `OVERWATCH_DASHBOARD_TOKEN` on a non-loopback deployment and enter through
`https://host/?token=<token>`. The dashboard stores the token for the tab under
`overwatch.dashboard.token`, scrubs it from browser history, sends Bearer auth
on API/media/download requests, and adds an encoded token to its main, session,
and action-output WebSocket URLs. If session storage is blocked, the token lasts
only for that page lifetime. Use TLS for remote access.

## OPSEC

### How does OPSEC enforcement work?

Three layers:

1. **Frontier filtering** — `next_task` removes items exceeding `max_noise`
2. **Validation** — `validate_action` rejects blacklisted techniques and over-noise actions
3. **Time window** — `validate_action` warns (soft) when outside authorized hours

The deterministic layer enforces hard constraints. The LLM can still reason about OPSEC — it sees noise ratings on frontier items and can choose quieter approaches.

### What happens if I ignore a validation warning?

Warnings are non-blocking — the `valid` field is still `true`. They flag potential concerns:

- Out-of-hours execution
- High noise but within ceiling
- Target node has limited graph context

Errors are blocking — `valid: false`. These should never be overridden:

- Out-of-scope target
- Blacklisted technique
- Target node doesn't exist

### How do credential lifecycle states work?

Credentials track their lifecycle via the `credential_status` property (`active`, `stale`, `expired`, `rotated`). The engine automatically degrades outbound `POTENTIAL_AUTH` edges from expired/stale credentials and deprioritizes frontier items that depend on them. Derivation chains (`DERIVED_FROM` edges) connect credentials through cracking or extraction steps. See [Concepts — Credential Lifecycle](concepts.md#credential-lifecycle) for details.

### What is identity resolution?

Overwatch automatically canonicalizes node IDs and merges alias nodes on ingest. When a BloodHound SID, parser output, and manual finding all reference the same host or user, identity resolution detects the overlap via identity markers and merges them into a single canonical node — retargeting edges and preserving provenance. See [Concepts — Identity Resolution](concepts.md#identity-resolution).

### How do I fix bad data in the graph?

Use [`correct_graph`](tools/correct-graph.md) for transactional graph repair. It supports dropping edges, replacing edges (change type/endpoints/confidence), and patching node properties. All operations in a batch are atomic.

## Sessions

### What are sessions?

Sessions are **persistent interactive I/O channels** — SSH connections, local PTY shells, or TCP sockets (for catching reverse shells). Unlike MCP tool calls which are request-response, sessions stay open across multiple tool calls. You write commands with `write_session`, read output with `read_session`, and the session stays alive until you `close_session`.

### How does session ownership work?

When a session is opened with `agent_id`, that agent **claims** the session. Only the claiming agent (or a caller with `force: true`) can write, resize, signal, update, or close the session. Any agent can read from any session. Unclaimed sessions (no `agent_id`) are open to all callers.

Ownership can be transferred via `update_session` by the current owner.

### Do sessions survive server restarts?

Live PTYs, sockets, buffers, secrets, and process handles do not survive. Their
secret-free descriptors do: owner, target references, validation defaults,
capabilities, listener intent, and connection-generation history are restored.

SSH, local PTY, and socket-connect sessions return as `interrupted`. A rearmed
socket listener returns as `resume_available` and remains inert until the
operator explicitly calls `resume_session` (or uses the dashboard/CLI Resume
action). Rebinding preserves the listener ID and generation counter, but no
`HAS_SESSION` access exists until a fresh target connection is accepted.

### What's the difference between `write_session` and `send_to_session`?

- **`write_session`** — raw I/O primitive. Writes bytes, returns the new buffer position. You call `read_session` separately to get output.
- **`send_to_session`** — audited command path. It validates the command against session/default scope metadata, writes it, waits for output to settle, stores captured output as evidence, and emits action lifecycle events. Use `write_session`/`read_session` for interactive prompts, password entry, REPL navigation, or streaming output where a single command lifecycle would be misleading.

### How does credential expiry estimation work?

The engine estimates expiry based on credential type: TGTs/TGS default to 10 hours, tokens to 1 hour, and passwords use the domain's `password_policy.maxAge` combined with the user's `pwd_last_set` timestamp. Frontier scoring applies graduated multipliers — credentials expiring within 30 minutes get a 0.3× factor (urgent), within 2 hours get 0.7× (soon), and healthy credentials get full weight. See [Concepts — Credential Lifecycle](concepts.md#credential-lifecycle) for details.

### What is the IAM policy simulator?

The `evaluateIAM()` function evaluates whether a cloud identity can perform an action on a resource. It traverses the graph to collect all reachable policies (via group memberships and role assumptions) and applies provider-specific evaluation logic: AWS deny-overrides-allow, Azure RBAC scope hierarchy, and GCP deny policy precedence. See [Concepts — IAM Policy Simulation](concepts.md#iam-policy-simulation).

### What Impacket tools are supported by parse_output?

Seven Impacket parsers are supported with 14 aliases: `getnpusers`/`impacket-getnpusers` (AS-REP hashes), `getuserspns`/`impacket-getuserspns` (TGS hashes), `gettgt`/`impacket-gettgt` (TGT tickets), `getst`/`impacket-getst` (service tickets), `smbclient`/`impacket-smbclient` (shares/files), `wmiexec`/`impacket-wmiexec` (remote execution), `psexec`/`impacket-psexec` (remote execution). See [parse_output](tools/parse-output.md) for the full parser table.

### How do I use the evidence chain API?

The dashboard exposes two evidence endpoints:

- **`/api/evidence-chains/:nodeId`** — Returns the full provenance chain for a node by walking `DERIVED_FROM`, `DUMPED_FROM`, and `OWNS_CRED` edges. Useful for tracing credential origins.
- **`/api/paths/:objectiveId`** — Returns shortest paths from compromised nodes to an engagement objective. Useful for attack path visualization.

Both endpoints are read-only and return JSON. Access them via the dashboard at `http://localhost:8384` (or your configured port).

## Retrospective

### When should I run a retrospective?

At the **end of every engagement**, even partial ones. The retrospective analyzes the full activity log and graph state to identify:

- Inference rules the engagement discovered that should be built-in
- Skills that were needed but missing from the library
- Patterns in how frontier items were scored
- Training data for model improvement

See [Retrospectives](playbook/retrospective.md) for details.

### What are RLVR training traces?

State→action→outcome triplets extracted from the engagement. Each trace captures what the graph looked like, what action was taken, and what changed as a result. These can be fed into reinforcement learning pipelines to improve model decision-making.

Traces are scored by confidence (`low`/`medium`/`high`) based on data quality — well-logged actions with clear outcomes produce high-confidence traces.
