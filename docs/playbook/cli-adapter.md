# CLI Adapter Playbook

How to operate Overwatch through the CLI adapter — for environments where native MCP is unavailable (policy restrictions, non-MCP clients, manual operator use).

## Operator Flow — Three Modes

Overwatch supports three consumption modes. The graph, state, and tools are identical across all three — only the transport differs.

### Mode A: Native MCP (default)

```
┌──────────────┐   stdio/HTTP   ┌─────────────────────┐
│  Claude Code  │──────────────▶│  Overwatch MCP Server │
│  (Opus/Sonnet)│◀──────────────│  (graph + inference)  │
└──────────────┘   MCP protocol └─────────────────────┘
```

- Claude Code connects directly as an MCP client
- Session managed by the SDK (transparent)
- Tools appear in Claude's tool palette
- **Use when:** Claude Code has unrestricted MCP access

### Mode B: CLI Adapter (Claude Code via bash)

```
┌──────────────┐   bash tool   ┌───────────────┐   HTTP   ┌─────────────────────┐
│  Claude Code  │─────────────▶│  overwatch CLI  │────────▶│  Overwatch MCP Server │
│  (Opus/Sonnet)│◀─ stdout ────│  (thin relay)   │◀───────│  (graph + inference)  │
└──────────────┘               └───────────────┘          └─────────────────────┘
```

- Claude Code invokes `overwatch` commands via its bash tool
- CLI handles session caching between invocations (transparent)
- Output is JSON by default (machine-readable for Claude)
- **Use when:** MCP is blocked by policy, or you want shell-level auditability

### Mode C: Manual Operator

```
┌──────────────┐   terminal    ┌───────────────┐   HTTP   ┌─────────────────────┐
│  Human        │─────────────▶│  overwatch CLI  │────────▶│  Overwatch MCP Server │
│  Operator     │◀─ stdout ────│  (thin relay)   │◀───────│  (graph + inference)  │
└──────────────┘               └───────────────┘          └─────────────────────┘
```

- Human types commands directly in a terminal
- Use `--human` flag for readable output
- Same commands, same graph — just a different consumer
- **Use when:** debugging, spot-checking, or operating without an LLM

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

## Walkthrough: Network Engagement via CLI

A Dante-style network engagement translated to CLI commands.

### Phase 0 — Config

Ensure `engagement.json` exists in the Overwatch directory:

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

Start the server:

```bash
OVERWATCH_TRANSPORT=http node dist/index.js
```

### Phase 1 — Bootstrap

```bash
# Verify connectivity and engagement identity
overwatch health

# Load full engagement state
overwatch get-state

# Run preflight checks
echo '{"profile":"network"}' | overwatch call run_lab_preflight --stdin

# Check available offensive tools on PATH
overwatch call check_tools
```

### Phase 2 — Discovery

Validate, execute, parse:

```bash
# Validate the scan action
echo '{
  "action_type": "network_scan",
  "target_node_id": "cidr-10-10-110-0-24",
  "command": "nmap -sS -sV -sC -O -p- --min-rate=1000 -oX scan.xml 10.10.110.0/24"
}' | overwatch validate-action --stdin
# → returns action_id: "act-xxx"

# Log execution start
overwatch log-action --action-id act-xxx --type action_started --frontier-item-id fi-yyy

# (operator runs nmap separately)

# Parse results into the graph
cat scan.xml | python3 -c "
import sys, json
xml = sys.stdin.read()
print(json.dumps({'tool_name': 'nmap', 'output': xml, 'agent_id': 'primary', 'action_id': 'act-xxx', 'frontier_item_id': 'fi-yyy'}))
" | overwatch parse-output --stdin

# Log completion
overwatch log-action --action-id act-xxx --type action_completed
```

### Phase 3 — Enumerate

```bash
# Check what the frontier suggests
overwatch next-task --count 10

# For each candidate, validate → execute → report
# Example: SMB enumeration
echo '{
  "action_type": "smb_enum",
  "target_node_id": "svc-10-10-110-10-445",
  "command": "nxc smb 10.10.110.10 --shares -u \"\" -p \"\""
}' | overwatch validate-action --stdin

overwatch log-action --action-id act-002 --type action_started

# (operator runs nxc)

echo '{
  "tool_name": "nxc",
  "output": "SMB  10.10.110.10  445  DC01  [*] Windows Server 2019 ...",
  "agent_id": "primary",
  "action_id": "act-002"
}' | overwatch parse-output --stdin

overwatch log-action --action-id act-002 --type action_completed
```

### Phase 4 — Report manual findings

For unsupported tools or manual observations:

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

### Phase 5 — Query and explore

```bash
# Query all hosts
echo '{"node_type": "host"}' | overwatch query-graph --stdin

# Query specific node
echo '{"node_id": "host-10-10-110-10"}' | overwatch query-graph --stdin

# Find paths to objective
echo '{"source_id": "cred-plaintext-sql-svc", "target_id": "obj-compromise"}' | overwatch call find_paths --stdin

# Get methodology for a technique
echo '{"query": "kerberoasting"}' | overwatch call get_skill --stdin
```

### Phase 6 — Session management

```bash
# Check current state anytime
overwatch get-state

# If session seems stale (server restarted, etc.)
overwatch reset-session
overwatch health

# When done — terminate cleanly
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
