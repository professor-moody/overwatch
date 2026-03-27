# CLI Adapter Playbook

How to operate Overwatch through the CLI adapter — for environments where native MCP is unavailable (policy restrictions, non-MCP clients, manual operator use).

## Operator Flow — Three Transport Modes

Overwatch supports three transport modes. The graph, state, and tools are identical across all three — only the transport differs.

### Mode A: MCP over stdio (default)

```
+----------------+              +------------------------+
|  Claude Code   | --stdio----> |  Overwatch MCP Server  |
|  (Opus/Sonnet) | <--stdio---- |  (graph + inference)   |
+----------------+              +------------------------+
```

- Claude Code connects as a native MCP client over stdin/stdout
- Tools appear directly in Claude's tool palette
- No network required — server runs as a child process
- **Env:** `OVERWATCH_TRANSPORT=stdio` (default)
- **Use when:** Claude Code has unrestricted MCP access

### Mode B: MCP over HTTP

```
+----------------+              +------------------------+
|  Claude Code   | --HTTP-----> |  Overwatch MCP Server  |
|  (Opus/Sonnet) | <--JSON----- |  (graph + inference)   |
+----------------+              +------------------------+
```

- Claude Code connects as a native MCP client over StreamableHTTP
- Same MCP protocol, but over the network instead of stdio
- Server runs independently — survives Claude Code restarts
- **Env:** `OVERWATCH_TRANSPORT=http` (binds to `http://127.0.0.1:3000/mcp`)
- **Use when:** You want the server to persist independently, or multiple clients need to connect

### Mode C: CLI Adapter

```
+----------------+              +-----------------+              +------------------------+
|  Claude Code   | --bash-----> |  overwatch CLI  | --HTTP-----> |  Overwatch MCP Server  |
|  (Opus/Sonnet) | <--stdout--- |  (thin relay)   | <--JSON----- |  (graph + inference)   |
+----------------+              +-----------------+              +------------------------+
```

- Claude Code invokes `overwatch` shell commands via its bash tool
- CLI handles MCP session caching between invocations (transparent)
- Output is JSON by default (machine-readable for Claude)
- Requires the server running in HTTP mode (Mode B)
- **Env:** `OVERWATCH_URL=http://127.0.0.1:3000`
- **Use when:** MCP is blocked by policy, or you want shell-level auditability

!!! note "Manual operator use"
    The CLI adapter also works for humans typing commands in a terminal. Add `--human` for readable output. Same commands, same graph — just a different consumer.

## Do I Need a Skill File?

**No.** The `get_system_prompt` tool generates dynamic instructions at runtime — engagement-aware, with the live tool table, current state snapshot, and OPSEC constraints. No static skill file can match that. The bootstrap is:

```bash
overwatch get-system-prompt --role primary
```

This returns the full operator instructions that Claude Code needs. The existing 32 offensive technique skills (network-recon, kerberoasting, lateral-movement, etc.) are still available via `get_skill` during the engagement — they're methodology guides, not adapter-specific.

## Bootstrap Sequence

### 1. Start the Overwatch HTTP server

```bash
cd /path/to/overwatch
OVERWATCH_TRANSPORT=http node dist/index.js
```

The server binds to `http://127.0.0.1:3000/mcp` by default.

### 2. Verify connectivity

```bash
overwatch health
```

Expected output:

```
Connected to Overwatch at http://127.0.0.1:3000
Engagement: Dante Run (dante-1)
Nodes: 0, Edges: 0
```

This also migrates the session cache to an engagement-aware key.

### 3. Fetch dynamic instructions (for Claude Code)

```bash
overwatch get-system-prompt --role primary
```

Returns the full system prompt with core loop, tool table, state snapshot, and OPSEC profile. Claude Code should call this at session start.

### 4. Drop the AGENTS.md template

Create this file in your project root. Claude Code reads it automatically:

```markdown
# Overwatch — CLI Adapter Mode

MCP is not available in this environment. Use the `overwatch` CLI adapter instead.
All Overwatch tools are available as shell commands. Output is JSON by default.

## Session Start

Run these two commands at the start of every session (including after compaction):

    overwatch get-system-prompt --role primary

Read the returned instructions carefully — they contain the engagement briefing,
core loop, tool table, and OPSEC constraints. Then:

    overwatch get-state

## Command Patterns

Scalar inputs use flags:

    overwatch get-state
    overwatch next-task --count 5
    overwatch get-system-prompt --role primary
    overwatch log-action --action-id act-001 --type action_started

Complex payloads use --stdin or --file:

    echo '{"action_type":"network_scan","target_node_id":"host-1","command":"nmap -sV 10.0.0.1"}' | overwatch validate-action --stdin
    overwatch report-finding --file finding.json
    overwatch parse-output --stdin

## Key Commands

    overwatch get-state              # Load engagement briefing
    overwatch next-task              # Get frontier candidates
    overwatch validate-action --stdin # Validate before executing
    overwatch log-action             # Log action lifecycle
    overwatch parse-output --stdin   # Parse tool output (nmap, nxc, etc.)
    overwatch report-finding --stdin # Report manual observations
    overwatch query-graph --stdin    # Query the graph
    overwatch tools                  # List all available tools
    overwatch health                 # Verify connectivity

## Session Management

Session continuity is automatic — the CLI caches the MCP session ID between
invocations. If things go wrong:

    overwatch reset-session          # Clear local cache (no network)
    overwatch close                  # Terminate server session + clear cache

## Output Convention

All output is JSON. Parse it directly. Do not add --human flag.
```

## What's Manual vs. Automatic

Once the AGENTS.md is in place and Claude Code starts, **everything is autonomous**. Claude reads the AGENTS.md, bootstraps via `get-system-prompt`, then drives the entire engagement loop through bash.

| Step | Who | When |
|------|-----|------|
| Write `engagement.json` | Human | Once, before engagement |
| Start Overwatch HTTP server | Human | Once, before engagement |
| Place `AGENTS.md` in project root | Human | Once, before engagement |
| Start Claude Code | Human | Once |
| Everything else below | Claude Code | Autonomous |

The walkthrough below shows exactly what Claude Code does — every command is run by Claude via its bash tool. The human just watches (and approves bash commands if Claude Code's policy requires it).

## Walkthrough: Network Engagement via CLI

What Claude Code actually does during a Dante-style network engagement, step by step.

### Phase 0 — Human Setup (one-time)

The human creates `engagement.json` in the Overwatch directory:

```json
{
  "id": "dante-1",
  "name": "Dante Run",
  "profile": "network",
  "scope": { "cidrs": ["10.10.110.0/24"], "domains": [], "exclusions": ["10.10.110.2"] },
  "objectives": [{ "id": "compromise", "description": "Compromise the Dante infrastructure", "target_node_type": "credential", "target_criteria": { "privileged": true }, "achieved": false }],
  "opsec": { "name": "pentest", "max_noise": 0.7 }
}
```

The human starts the server and launches Claude Code:

```bash
OVERWATCH_TRANSPORT=http node dist/index.js
claude
```

**From here on, Claude Code runs everything.**

### Phase 1 — Claude Bootstraps

Claude reads the AGENTS.md, then:

```bash
# Fetch full dynamic instructions (core loop, tool table, state, OPSEC)
overwatch get-system-prompt --role primary

# Load engagement state
overwatch get-state

# Run preflight — checks tools, config, graph health
echo '{"profile":"network"}' | overwatch call run_lab_preflight --stdin

# See what offensive tools are available on PATH
overwatch call check_tools
```

Claude now has the engagement briefing, knows the scope, and has the full tool table.

### Phase 2 — Claude Discovers the Network

Claude validates, runs nmap, and parses — all in one flow:

```bash
# 1. Validate the scan
echo '{
  "action_type": "network_scan",
  "target_node_id": "cidr-10-10-110-0-24",
  "command": "nmap -sS -sV -sC -O -p- --min-rate=1000 -oX /tmp/scan.xml 10.10.110.0/24"
}' | overwatch validate-action --stdin
# → returns action_id: "act-xxx"

# 2. Log execution start
overwatch log-action --action-id act-xxx --type action_started --frontier-item-id fi-yyy

# 3. Run nmap (Claude executes this directly via bash)
nmap -sS -sV -sC -O -p- --min-rate=1000 -oX /tmp/scan.xml 10.10.110.0/24

# 4. Feed results into the graph
echo '{"tool_name": "nmap", "output": "'$(cat /tmp/scan.xml | jq -Rs .| tr -d '"')'", "agent_id": "primary", "action_id": "act-xxx", "frontier_item_id": "fi-yyy"}' | overwatch parse-output --stdin

# 5. Log completion
overwatch log-action --action-id act-xxx --type action_completed
```

### Phase 3 — Claude Enumerates Services

Claude checks the frontier, picks the highest-priority target, and works it:

```bash
# See what the frontier suggests
overwatch next-task --count 10

# Validate SMB enumeration on the top candidate
echo '{
  "action_type": "smb_enum",
  "target_node_id": "svc-10-10-110-10-445",
  "command": "nxc smb 10.10.110.10 --shares -u \"\" -p \"\""
}' | overwatch validate-action --stdin

overwatch log-action --action-id act-002 --type action_started

# Run nxc (Claude executes this directly)
NXC_OUTPUT=$(nxc smb 10.10.110.10 --shares -u '' -p '' 2>&1)

# Parse results into the graph
echo "{\"tool_name\": \"nxc\", \"output\": $(echo "$NXC_OUTPUT" | jq -Rs .), \"agent_id\": \"primary\", \"action_id\": \"act-002\"}" | overwatch parse-output --stdin

overwatch log-action --action-id act-002 --type action_completed
```

Claude repeats this loop for each frontier candidate — validate, execute, parse, log.

### Phase 4 — Claude Reports Findings

When Claude uses a tool without a built-in parser, it structures the findings manually:

```bash
echo '{
  "agent_id": "primary",
  "action_id": "act-003",
  "nodes": [
    {"id": "cred-plaintext-sql-svc", "type": "credential", "label": "sql_svc:Password123!", "cred_type": "plaintext", "username": "sql_svc", "cred_value": "Password123!"}
  ],
  "edges": [
    {"source": "user-north-sql-svc", "target": "cred-plaintext-sql-svc", "type": "OWNS_CRED", "confidence": 1.0}
  ]
}' | overwatch report-finding --stdin
```

### Phase 5 — Claude Explores the Graph

Claude queries the graph to plan attack paths:

```bash
# Query all hosts
echo '{"node_type": "host"}' | overwatch query-graph --stdin

# Find paths from a credential to the objective
echo '{"source_id": "cred-plaintext-sql-svc", "target_id": "obj-compromise"}' | overwatch call find_paths --stdin

# Look up methodology for a technique
echo '{"query": "kerberoasting"}' | overwatch call get_skill --stdin
```

### Phase 6 — Session Recovery

If the server restarts or the session expires, Claude handles it transparently. The CLI retries once with a fresh session automatically. If things are truly broken:

```bash
# Clear stale local cache
overwatch reset-session

# Reconnect
overwatch health

# Resume — graph state is intact on the server
overwatch get-state
```

When the engagement is complete:

```bash
overwatch close
```

## Quick Reference Card

```
SESSION
  overwatch health                          # verify connectivity
  overwatch get-system-prompt --role primary # fetch dynamic instructions
  overwatch reset-session                   # clear local cache (no network)
  overwatch close                           # terminate session + clear cache
  overwatch --version                       # show adapter version

STATE
  overwatch get-state                       # full engagement briefing
  overwatch next-task                       # frontier candidates
  overwatch next-task --count 5             # limit results

ACTIONS
  ... | overwatch validate-action --stdin   # validate before executing
  overwatch log-action --action-id ID --type action_started
  overwatch log-action --action-id ID --type action_completed
  overwatch log-action --action-id ID --type action_failed

FINDINGS
  ... | overwatch parse-output --stdin      # deterministic parser (nmap, nxc, etc.)
  ... | overwatch report-finding --stdin    # manual observations
  overwatch report-finding --file f.json    # from file

GRAPH
  ... | overwatch query-graph --stdin       # query nodes/edges
  overwatch call find_paths --stdin         # shortest path analysis
  overwatch call export_graph               # full graph dump

TOOLS
  overwatch tools                           # list all available tools
  overwatch call <tool_name> --stdin        # generic escape hatch
  overwatch call <tool_name> --file p.json  # from file
  overwatch call <tool_name>                # no args

SESSIONS (managed shells)
  overwatch open-session --kind pty --target 10.0.0.1 --port 22
  overwatch write-session --id SID --data "whoami\n"
  overwatch read-session --id SID --from-pos 0
  overwatch send-to-session --id SID --command "id" --wait-ms 2000
  overwatch list-sessions
  overwatch close-session --id SID

OUTPUT
  overwatch get-state                       # JSON (default, for Claude)
  overwatch get-state --human               # human-readable (for operator)
```
