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

### 2. Build the CLI adapter

```bash
cd /path/to/overwatch-adapter
npm install
npm run build
```

Note the absolute path to the built adapter (e.g., `/home/op/overwatch-adapter`). Claude Code will invoke it as `node /home/op/overwatch-adapter/dist/cli.js <command>`.

### 3. Place the CLAUDE.md template

Create `CLAUDE.md` in your project root **before starting Claude Code**. Claude Code reads it automatically at session start.

!!! note "Windsurf uses AGENTS.md"
    If you're using Windsurf instead of Claude Code, save this template as `AGENTS.md` instead of `CLAUDE.md`. The content is identical — only the filename differs.

Replace `/home/op/overwatch-adapter` and `<OVERWATCH_SERVER>` with the actual values from steps 1-2:

```markdown
# Overwatch — CLI Adapter Mode

MCP is not available in this environment. Use the Overwatch CLI adapter instead.
All Overwatch tools are available as shell commands. Output is JSON by default.

## Bootstrap

Create a wrapper script as your FIRST action. This persists across bash calls:

    cat > ./ow << 'WRAPPER'
    #!/bin/bash
    export OVERWATCH_URL="http://<OVERWATCH_SERVER>:3000"
    exec node /home/op/overwatch-adapter/dist/cli.js "$@"
    WRAPPER
    chmod +x ./ow

Then use `./ow <command>` for ALL subsequent Overwatch calls.

## Execution Model — READ THIS CAREFULLY

There are TWO execution contexts. Confusing them is the #1 failure mode.

**`./ow` commands** run locally and talk to the Overwatch server via HTTP.
Use `./ow` for ALL Overwatch API calls (get-state, validate-action, report-finding, etc.).

**Offensive tools** (nmap, nxc, ldapsearch, smbclient, etc.) must run on the
**target VM**, not on your local machine. You have two options:

Option A — SSH into the VM and run tools there:

    ssh op@<VM_IP> "nmap -Pn -sT -oX - 10.0.0.1"

Option B — Use Overwatch sessions for a persistent remote shell:

    ./ow open-session --kind ssh --target <VM_IP> --title "recon-shell"
    # Returns a session_id (SID)
    ./ow send-to-session --id SID --command "nmap -Pn -sT -oX - 10.0.0.1" --wait-ms 60000
    ./ow read-session --id SID

Note: `--kind ssh` opens a shell on the remote VM. `--kind local_pty` opens a
shell on the Overwatch server itself — only use that if the server IS the VM.

`check-tools` reports what is installed on the **Overwatch server**, not locally
and not on the SSH target. If the server and target VM are different machines,
verify tool availability on the VM itself (e.g. `which nmap` via a session).

## Session Start

Run these commands at the start of every session (including after compaction):

    ./ow get-system-prompt --role primary

Read the returned instructions carefully — they contain the engagement briefing,
core loop, tool table, and OPSEC constraints. Then:

    ./ow get-state

## Command Patterns

Scalar inputs use flags:

    ./ow get-state
    ./ow next-task --count 5
    ./ow log-action --action-id ID --type action_started --frontier-item-id FRONTIER_ID

Complex payloads use --stdin:

    cat << 'EOF' | ./ow validate-action --stdin
    {
      "description": "Port scan host for open services",
      "target_ip": "10.0.0.1",
      "technique": "portscan",
      "frontier_item_id": "frontier-abc123"
    }
    EOF

## JSON Cheat Sheet — Exact Field Names

### validate-action

    cat << 'EOF' | ./ow validate-action --stdin
    {
      "description": "Enumerate SMB shares on DC",
      "target_ip": "10.0.0.1",
      "technique": "smb_enum",
      "frontier_item_id": "frontier-abc123"
    }
    EOF

### report-finding (edges use `source`/`target`, NOT `from`/`to`)

    cat << 'EOF' | ./ow report-finding --stdin
    {
      "action_id": "ACTION_ID",
      "frontier_item_id": "frontier-abc123",
      "nodes": [
        {"id": "host-10-0-0-1", "type": "host", "label": "10.0.0.1", "properties": {"ip": "10.0.0.1"}},
        {"id": "svc-10-0-0-1-445", "type": "service", "label": "SMB:445", "properties": {"port": 445, "protocol": "tcp", "service_name": "smb"}}
      ],
      "edges": [
        {"source": "host-10-0-0-1", "target": "svc-10-0-0-1-445", "type": "RUNS"}
      ]
    }
    EOF

### parse-output (field is `tool_name`, NOT `parser`)

    cat << 'EOF' | ./ow parse-output --stdin
    {
      "tool_name": "nmap",
      "output": "<xml nmap output here>",
      "action_id": "ACTION_ID",
      "frontier_item_id": "frontier-abc123"
    }
    EOF

### update-scope (`reason` is required)

    cat << 'EOF' | ./ow update-scope --stdin
    {
      "add_cidrs": ["10.0.0.0/24"],
      "reason": "Discovered subnet via DNS enumeration",
      "confirm": false
    }
    EOF

Set `confirm: false` first to preview, then `confirm: true` to apply.

### log-action (flags only)

    ./ow log-action --action-id ACTION_ID --type action_started --frontier-item-id FRONTIER_ID
    ./ow log-action --action-id ACTION_ID --type action_completed
    ./ow log-action --action-id ACTION_ID --type action_failed --description "Connection refused"

## Common Mistakes

- ❌ `from`/`to` on edges → ✅ `source`/`target`
- ❌ `parser` in parse-output → ✅ `tool_name`
- ❌ Running nmap/nxc locally → ✅ Run on VM via SSH or `open-session`
- ❌ Omitting `frontier_item_id` → ✅ Thread it from `next-task` through every call
- ❌ `nmap -sT 10.0.0.1` (text) → ✅ `nmap -oX - 10.0.0.1` (XML for parser)
- ❌ `update-scope` without `reason` → ✅ Always include `reason`
- ❌ Observations for structured data → ✅ Use `nodes`/`edges` arrays

## Parser Tips

- **nmap**: Output MUST be XML. Use `-oX -` to write XML to stdout.
  `nmap -Pn -sT -oX - 10.0.0.1` then pipe the XML into `parse-output`.
- **nxc / netexec**: Raw terminal output works directly as `tool_name: "nxc"`.
- **ldapsearch**: Not a supported parser — use `report-finding` manually.
- **certipy, secretsdump, kerbrute, hashcat, responder, enum4linux, rubeus**:
  All supported. Use the tool name as `tool_name`.
- Run `./ow tools` to see the full list of supported parsers.

## Key Commands

    ./ow get-state              # Load engagement briefing
    ./ow next-task              # Get frontier candidates (returns frontier_item_id)
    ./ow validate-action --stdin # Validate before executing (pass frontier_item_id)
    ./ow log-action             # Log action lifecycle (pass frontier_item_id)
    ./ow parse-output --stdin   # Parse tool output (use tool_name, not parser)
    ./ow report-finding --stdin # Report findings (nodes/edges with source/target)
    ./ow query-graph --stdin    # Query the graph
    ./ow check-tools            # List tools installed on the SERVER
    ./ow open-session           # Open shell (--kind ssh for remote VM, local_pty for server)
    ./ow send-to-session        # Run command in session (--id SID --command "...")
    ./ow read-session           # Read session output (--id SID)
    ./ow health                 # Verify connectivity

## Session Management

Session continuity is automatic — the CLI caches the MCP session ID between
invocations. If things go wrong:

    ./ow reset-session          # Clear local cache (no network)
    ./ow close                  # Terminate server session + clear cache

## Output Convention

All output is JSON. Parse it directly. Do not add --human flag.
```

### 4. Start Claude Code

```bash
claude
```

Claude reads the CLAUDE.md, creates the wrapper script, calls `./ow get-system-prompt --role primary` to fetch dynamic instructions, then drives the engagement autonomously.

## What's Manual vs. Automatic

Once the CLAUDE.md is in place and Claude Code starts, **everything is autonomous**. Claude reads the CLAUDE.md, bootstraps via `get-system-prompt`, then drives the entire engagement loop through bash.

| Step | Who | When |
|------|-----|------|
| Write `engagement.json` | Human | Once, before engagement |
| Start Overwatch HTTP server | Human | Once, before engagement |
| Build CLI adapter (`npm install && npm run build`) | Human | Once, before engagement |
| Place `CLAUDE.md` in project root (with adapter path) | Human | Once, before engagement |
| Start Claude Code | Human | Once |
| Everything else below | Claude Code | Autonomous |

The walkthrough below shows exactly what Claude Code does — every command is run by Claude via its bash tool. The human just watches (and approves bash commands if Claude Code's policy requires it).

## Walkthrough: Network Engagement via CLI

What Claude Code actually does during a Dante-style network engagement, step by step.

### Phase 0 — Human Setup (one-time)

The human creates `engagement.json` in the Overwatch directory, places the CLAUDE.md template (see [Bootstrap Sequence](#bootstrap-sequence) above), then:

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

Claude reads the CLAUDE.md, then:

```bash
# Create the wrapper script (see CLAUDE.md template)
cat > ./ow << 'WRAPPER'
#!/bin/bash
export OVERWATCH_URL="http://<VM_IP>:3000"
exec node /home/op/overwatch-adapter/dist/cli.js "$@"
WRAPPER
chmod +x ./ow

# Fetch full dynamic instructions (core loop, tool table, state, OPSEC)
./ow get-system-prompt --role primary

# Load engagement state
./ow get-state

# Run preflight — checks tools, config, graph health
echo '{"profile":"network"}' | ./ow call run_lab_preflight --stdin

# See what offensive tools are available on PATH
./ow call check_tools
```

Claude now has the engagement briefing, knows the scope, and has the full tool table.

### Phase 2 — Claude Discovers the Network

Claude validates, runs nmap, and parses — all in one flow:

```bash
# 1. Validate the scan
echo '{
  "description": "Full port scan of target subnet",
  "target_ip": "10.10.110.0",
  "technique": "portscan",
  "frontier_item_id": "fi-yyy"
}' | ./ow validate-action --stdin
# → returns action_id: "act-xxx"

# 2. Log execution start
./ow log-action --action-id act-xxx --type action_started --frontier-item-id fi-yyy

# 3. Run nmap ON THE VM (not locally — tools live on the server)
#    Option A: SSH
ssh op@<VM_IP> "nmap -sS -sV -sC -O -p- --min-rate=1000 -oX - 10.10.110.0/24" > /tmp/scan.xml
#    Option B: Overwatch session
#    ./ow open-session --type local_pty --title "nmap-scan"
#    ./ow send-to-session --session-id SID --command "nmap -sS -sV -sC -O -p- --min-rate=1000 -oX - 10.10.110.0/24" --timeout 300

# 4. Feed results into the graph (use tool_name, not parser)
cat /tmp/scan.xml | jq -Rs '{tool_name: "nmap", output: ., agent_id: "primary", action_id: "act-xxx", frontier_item_id: "fi-yyy"}' | ./ow parse-output --stdin

# 5. Log completion
./ow log-action --action-id act-xxx --type action_completed
```

### Phase 3 — Claude Enumerates Services

Claude checks the frontier, picks the highest-priority target, and works it:

```bash
# See what the frontier suggests
./ow next-task --count 10

# Validate SMB enumeration on the top candidate
echo '{
  "description": "Enumerate SMB shares with null session",
  "target_node": "svc-10-10-110-10-445",
  "technique": "smb_enum",
  "frontier_item_id": "fi-zzz"
}' | ./ow validate-action --stdin

./ow log-action --action-id act-002 --type action_started

# Run nxc ON THE VM (not locally)
NXC_OUTPUT=$(ssh op@<VM_IP> "nxc smb 10.10.110.10 --shares -u '' -p ''" 2>&1)

# Parse results into the graph (field is tool_name, not parser)
echo "{\"tool_name\": \"nxc\", \"output\": $(echo "$NXC_OUTPUT" | jq -Rs .), \"agent_id\": \"primary\", \"action_id\": \"act-002\", \"frontier_item_id\": \"fi-zzz\"}" | ./ow parse-output --stdin

./ow log-action --action-id act-002 --type action_completed
```

Claude repeats this loop for each frontier candidate — validate, execute, parse, log.

### Phase 4 — Claude Reports Findings

When Claude uses a tool without a built-in parser, it structures the findings manually:

```bash
echo '{
  "agent_id": "primary",
  "action_id": "act-003",
  "frontier_item_id": "fi-aaa",
  "nodes": [
    {"id": "cred-plaintext-sql-svc", "type": "credential", "label": "sql_svc:Password123!", "properties": {"cred_type": "plaintext", "username": "sql_svc", "cred_value": "Password123!"}}
  ],
  "edges": [
    {"source": "user-north-sql-svc", "target": "cred-plaintext-sql-svc", "type": "OWNS_CRED", "confidence": 1.0}
  ]
}' | ./ow report-finding --stdin
```

### Phase 5 — Claude Explores the Graph

Claude queries the graph to plan attack paths:

```bash
# Query all hosts
echo '{"node_type": "host"}' | ./ow query-graph --stdin

# Find paths from a credential to the objective
echo '{"source_id": "cred-plaintext-sql-svc", "target_id": "obj-compromise"}' | ./ow call find_paths --stdin

# Look up methodology for a technique
echo '{"query": "kerberoasting"}' | ./ow call get_skill --stdin
```

### Phase 6 — Session Recovery

If the server restarts or the session expires, Claude handles it transparently. The CLI retries once with a fresh session automatically. If things are truly broken:

```bash
# Clear stale local cache
./ow reset-session

# Reconnect
./ow health

# Resume — graph state is intact on the server
./ow get-state
```

When the engagement is complete:

```bash
./ow close
```

## Quick Reference Card

```
SESSION
  ./ow health                          # verify connectivity
  ./ow get-system-prompt --role primary # fetch dynamic instructions
  ./ow reset-session                   # clear local cache (no network)
  ./ow close                           # terminate session + clear cache
  ./ow --version                       # show adapter version

STATE
  ./ow get-state                       # full engagement briefing
  ./ow next-task                       # frontier candidates
  ./ow next-task --count 5             # limit results

ACTIONS
  ... | ./ow validate-action --stdin   # validate before executing
  ./ow log-action --action-id ID --type action_started
  ./ow log-action --action-id ID --type action_completed
  ./ow log-action --action-id ID --type action_failed

FINDINGS
  ... | ./ow parse-output --stdin      # deterministic parser (nmap, nxc, etc.)
  ... | ./ow report-finding --stdin    # structured findings (nodes + edges)
  ./ow report-finding --file f.json    # from file

GRAPH
  ... | ./ow query-graph --stdin       # query nodes/edges
  ./ow call find_paths --stdin         # shortest path analysis
  ./ow call export_graph               # full graph dump

TOOLS
  ./ow tools                           # list all available tools
  ./ow call <tool_name> --stdin        # generic escape hatch
  ./ow call <tool_name> --file p.json  # from file
  ./ow call <tool_name>                # no args

SESSIONS (managed shells)
  ./ow open-session --kind ssh --target <VM_IP> --title "recon"  # remote shell
  ./ow open-session --kind local_pty --title "local"             # local server shell
  ./ow write-session --id SID --data "whoami\n"
  ./ow read-session --id SID --from-pos 0
  ./ow send-to-session --id SID --command "id" --wait-ms 2000
  ./ow list-sessions
  ./ow close-session --id SID

OUTPUT
  ./ow get-state                       # JSON (default, for Claude)
  ./ow get-state --human               # human-readable (for operator)
```
