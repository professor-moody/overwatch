# FAQ

Frequently asked questions about Overwatch.

## General

### How does Overwatch survive context compaction?

The engagement graph lives **outside** the context window — it's persisted in the MCP server process and on disk. When Claude Code compacts, it loses the conversation history but not the graph. The `AGENTS.md` file instructs Claude to call `get_state()` as its first action in any new or compacted session, which reconstructs a complete briefing from the graph: scope, discoveries, access, frontier, agents, and recent activity.

See [Compaction](concepts.md#compaction) for details.

### Can I run multiple engagements simultaneously?

Not in a single server instance. Each Overwatch server runs one engagement. To run multiple engagements, start multiple server instances with different `OVERWATCH_CONFIG` paths and `OVERWATCH_DASHBOARD_PORT` values, and configure separate MCP entries in Claude Code.

### Can I use this with models other than Claude?

Overwatch is a standard MCP server. Today the shipped runtime transport is stdio, and any MCP-compatible client that can talk to a stdio MCP server can connect to it. However, the `AGENTS.md` session instructions and sub-agent dispatch are written for Claude Code specifically. You'd need to adapt the session instructions for other clients.

The core server functionality (graph operations, inference rules, parsers, persistence) is model-agnostic.

### How do I reset an engagement?

Delete the state file and restart:

```bash
rm state-<engagement-id>.json
# Restart the MCP server
```

The server will seed a fresh graph from `engagement.json`.

### How do I resume a previous engagement?

Just start the server with the same `OVERWATCH_CONFIG`. The server automatically loads the persisted state file (`state-<engagement-id>.json`) if it exists. Call `get_state` to see where you left off.

## Graph & Findings

### What's the difference between `parse_output` and `report_finding`?

- **`parse_output`** — deterministic parser for supported tools (nmap, nxc, certipy, secretsdump, kerbrute, hashcat, responder, ldapsearch, enum4linux, rubeus, gobuster/feroxbuster/ffuf). Extracts structured nodes/edges without LLM involvement. Token-efficient and consistent. Accepts an optional `context` parameter for domain and source host hints.
- **`report_finding`** — manual finding submission for unsupported tools, analyst observations, or already-structured data. The LLM constructs the nodes and edges.

Use `parse_output` whenever possible. See [parse_output vs report_finding](playbook/parse-vs-report.md) for detailed guidance.

### How do I add a custom parser?

1. Add the parser function in `src/services/output-parsers.ts`
2. Register the parser name in the `parsers` map
3. Add tests in `src/services/__tests__/output-parsers.test.ts`
4. Update the `parse_output` tool description in `src/tools/parse-output.ts`

See [Development — Adding a New Parser](development.md#adding-a-new-parser).

### What if the state file gets corrupted?

The atomic write-rename mechanism prevents corruption during normal operation. If corruption occurs (e.g., disk full):

1. Delete the corrupted `state-<id>.json`
2. Check for snapshot backups (`state-<id>.json.bak.*`)
3. Rename the most recent valid snapshot to `state-<id>.json`
4. Restart the server

If no valid snapshots exist, delete the state file and restart — the server creates a fresh graph from `engagement.json`. You'll lose discovered data but can re-ingest from tool output.

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

Agents write to the same graph concurrently. The engine handles this safely:

- Node IDs are deterministic, so duplicate discoveries merge automatically
- Edge properties are merged (higher confidence wins)
- Inference rules fire on each new finding independently
- The activity log preserves the full timeline from all agents

There's no locking or conflict resolution needed because the graph is append-mostly and node/edge IDs are globally unique.

## Dashboard

### How do I access the dashboard?

Open `http://localhost:8384` (or your configured port) in any modern browser. It starts automatically with the MCP server.

### Can I interact with the graph from the dashboard?

The dashboard is **read-only** — you can explore, search, filter, and highlight but not modify the graph. All mutations go through MCP tools.

You can:

- Drag nodes to reposition them
- Shift+click two nodes to see the shortest path
- Double-click to isolate a neighborhood
- Click frontier items to zoom to their target nodes
- Export PNG screenshots or SVG files via the Export dropdown
- Toggle **Attack Path** overlay to see the actual path taken (gold) and compare against the theoretical shortest path (cyan)
- Toggle **Credential Flow** to visualize credential relationships and derivation chains with status badges
- View credential derivation chains in the node detail panel

### The dashboard is blank or shows errors

- Check that `OVERWATCH_DASHBOARD_PORT` is not `0` (disabled)
- Verify the port isn't in use by another process
- Open the browser console (F12) for JavaScript errors
- The dashboard requires WebGL — check browser compatibility
- Try a hard refresh (Ctrl+Shift+R)

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

No. Sessions are **ephemeral runtime state** — PTY file descriptors and socket connections cannot be serialized. When the server shuts down, all sessions are closed and their final output is captured. After restart, agents must open new sessions.

The engagement graph (findings, frontier, objectives) survives restarts. Sessions do not.

### What's the difference between `write_session` and `send_to_session`?

- **`write_session`** — raw I/O primitive. Writes bytes, returns the new buffer position. You call `read_session` separately to get output.
- **`send_to_session`** — convenience sugar (experimental). Writes a command, waits for output to settle (idle timeout or regex match), then returns the captured output in one call. Simpler but less flexible — use `write`/`read` for interactive prompts, password entry, or REPL input.

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
