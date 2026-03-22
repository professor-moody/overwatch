# Overwatch — Complete Handoff Document

## What This Is

Overwatch is an offensive security engagement orchestrator built as an MCP server for Claude Code. It provides persistent engagement state as a directed property graph, hybrid deterministic + LLM scoring, inference-driven attack surface expansion, and OPSEC-aware validation. It is designed for authorized penetration testing by skilled human operators assisted by LLM agents.

This document is the complete reference for understanding, setting up, extending, and operating the system.

---

## Architecture Summary

Overwatch inverts the "LLM-as-orchestrator" pattern used by projects like red-run (BLS) and hexstrike-ai. Instead of the LLM holding engagement state in its context window (red-run) or wrapping tools as MCP functions (hexstrike), Overwatch puts the **intelligence infrastructure** in the MCP server and lets the LLM do what it's best at: offensive reasoning and tool execution via Claude Code's native bash.

```
┌─────────────────────────────────────────────────────────────┐
│  OPERATOR LAYER                                             │
│  engagement.json → scope, objectives, OPSEC profile         │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│  MCP ORCHESTRATOR SERVER (TypeScript, persistent process)   │
│                                                             │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐ │
│  │ Graph Engine  │ │ Inference    │ │ OPSEC Policy +       │ │
│  │ (graphology)  │ │ Rules Engine │ │ Validation           │ │
│  └──────┬───────┘ └──────┬───────┘ └──────────┬───────────┘ │
│         │                │                     │             │
│  ┌──────▼────────────────────▼─────────────────────▼──────────┐ │
│  │  19 MCP Tools                                          │ │
│  │  get_state · next_task · report_finding ·              │ │
│  │  validate_action · query_graph · find_paths ·          │ │
│  │  get_skill · register_agent · get_agent_context ·      │ │
│  │  update_agent · get_history · export_graph ·           │ │
│  │  ingest_bloodhound · check_tools · parse_output ·     │ │
│  │  track_process · check_processes ·                     │ │
│  │  suggest_inference_rule · run_retrospective            │ │
│  └────────────────────────┬───────────────────────────────┘ │
└───────────────────────────┼─────────────────────────────────┘
                            │ stdio
┌───────────────────────────▼─────────────────────────────────┐
│  CLAUDE CODE (Opus primary session)                         │
│                                                             │
│  Calls MCP tools for state + scoring + validation           │
│  Executes security tools via native bash                    │
│  Dispatches Sonnet sub-agents for parallel work             │
└─────────────────────────────────────────────────────────────┘
```

### Key Difference From Red-Run (BLS)

Red-run's orchestrator is a markdown skill loaded into Claude Code's context. State lives in SQLite rows the LLM re-reads after compaction. Routing is prompt-driven.

Overwatch's orchestrator is an external persistent process. State lives in a graph with traversable relationships. Routing is hybrid: deterministic filtering + LLM reasoning. The LLM calls into the server, not the other way around. Context compaction causes zero information loss because the graph is outside the context window.

### Key Difference From HexStrike-AI

HexStrike wraps 150+ tools as individual MCP functions (nmap_scan(), gobuster_scan(), etc.). The LLM calls these wrappers to execute tools. There's no engagement state, no scoring, no attack path tracking.

Overwatch does NOT wrap tools as MCP functions. The LLM executes tools via Claude Code's native bash — it already knows how to run nmap, nxc (netexec), certipy, etc. Overwatch provides the intelligence layer that tells the LLM WHAT to do, WHERE to do it, and validates the plan before execution. Tool output gets reported back to the graph via `report_finding`.

### What We Borrow From HexStrike

- **Tool availability checking** — the server should verify that required tools are installed (nmap, nxc, etc.) and report missing ones. This is a startup health check, not an MCP tool wrapper.
- **Process management** — long-running scans (nmap -p-, feroxbuster) need tracking. The MCP server can track active processes and their status.
- **Retry/recovery on execution failure** — if a tool fails, the system should suggest alternatives or retry with adjusted parameters. This logic lives in the skills, not in tool wrappers.

---

## How Tool Execution Actually Works

This is the critical flow that connects the orchestrator's intelligence to real-world tool execution:

### Step-by-step: From Graph to Shell to Graph

```
1. LLM calls next_task()
   └─→ Server returns: "Enumerate services on 10.10.10.1, priority: high"

2. LLM calls get_skill(query="network recon port scanning")
   └─→ Server returns: network-recon.md methodology

3. LLM calls validate_action(target_node="host-10-10-10-1", technique="portscan")
   └─→ Server returns: { valid: true, warnings: [] }

4. LLM executes via Claude Code bash:
   └─→ $ nmap -sS -sV --top-ports 1000 10.10.10.1

5. LLM parses nmap output and calls report_finding():
   └─→ nodes: [
         { id: "svc-10.10.10.1-445", type: "service", port: 445,
           service_name: "smb", smb_signing: false },
         { id: "svc-10.10.10.1-88", type: "service", port: 88,
           service_name: "kerberos" }
       ]
       edges: [
         { source: "host-10-10-10-1", target: "svc-10.10.10.1-445", type: "RUNS" },
         { source: "host-10-10-10-1", target: "svc-10.10.10.1-88", type: "RUNS" }
       ]

6. Server ingests finding:
   └─→ Inference rules fire automatically:
       - Kerberos found → MEMBER_OF_DOMAIN edge inferred
       - SMB signing disabled → RELAY_TARGET edge inferred
   └─→ Frontier recomputed with new items
   └─→ State persisted to disk

7. LLM calls next_task() again
   └─→ New frontier includes: "Test relay to 10.10.10.1 (signing disabled)"
   └─→ Loop continues
```

### The LLM's Dual Role

The LLM does two things:

**1. Offensive reasoning** — calling MCP tools to understand the engagement state, score priorities, spot attack chains, and plan next moves.

**2. Tool execution** — running security tools via Claude Code's native bash, parsing their output, and reporting structured findings back to the graph.

The MCP server NEVER executes tools itself. It only manages state and validates plans. This is a deliberate design choice:
- Claude Code already has bash execution with permission controls
- The LLM can construct complex command lines with context-specific flags
- The LLM can parse diverse tool output formats (nmap XML, JSON, plaintext)
- No need to maintain 150+ tool wrappers that go stale

### Sub-Agent Execution Model

When the primary session dispatches a sub-agent (Claude Code subprocess):

```
Primary (Opus):
  1. Calls register_agent(agent_id="ad-agent-1", subgraph_node_ids=[...])
  2. Spawns Sonnet subprocess with instructions

Sub-Agent (Sonnet):
  1. Calls get_agent_context(task_id="...")  → receives scoped subgraph
  2. Calls get_skill(query="active directory enumeration")
  3. Calls validate_action(target_node="...", technique="ldap_enum")
  4. Executes via Claude Code bash:
   └─→ $ nxc smb 10.10.10.1 -u user -p pass --users
  5. Calls report_finding() with discovered users/groups/edges
  6. Repeats until task complete

Primary (Opus):
  Periodically calls get_state() — sees new findings from agent
  Can dispatch new agents immediately based on discoveries
```

---

## E2E Engagement Flow

### Phase 0 — Pre-Engagement Setup

Operator creates `engagement.json`:
- Target scope (CIDRs, domains, exclusions)
- Objectives (domain admin, file access, etc.) with criteria
- OPSEC profile (noise ceiling, time windows, blacklisted techniques)
- Weight preset selection (ctf/pentest/redteam/assumed_breach)

Server starts, seeds graph with bare scope nodes. No edges exist yet.

### Phase 1 — Bootstrap (Cold Start)

Primary Opus session connects, calls `get_state()`. Receives bare nodes with no edges. Frontier is entirely "incomplete node" items — hosts needing alive status.

The LLM calls `get_skill(query="host discovery")`, gets the network-recon methodology, then executes ping sweeps / ARP scans via bash. Reports alive/dead hosts via `report_finding()`. Dead hosts exit frontier.

For alive hosts, frontier shifts to "missing: services". LLM runs port scans, reports service nodes and RUNS edges. Inference rules fire: Kerberos → domain membership, SMB signing → relay targets, etc.

Graph transitions from empty to a real attack surface with confirmed and inferred edges.

### Phase 2 — Main Scoring Loop

This runs continuously:

**Layer 1 — Deterministic filter** (server-side, no LLM):
- Removes out-of-scope targets
- Removes exact duplicate already-tested actions
- Applies hard OPSEC noise ceiling vetoes
- Removes dead hosts
- Attaches graph metrics to each remaining item (hops to objective, fan-out estimate, node degree, confidence)

**Layer 2 — LLM reasoning** (the primary session):
- Receives filtered candidates with full graph context
- Spots multi-step attack chains across candidates
- Estimates impact of each action
- Assesses likely defensive posture
- Recommends sequencing (what should happen before what)
- Uses `query_graph()` to explore patterns the frontier doesn't surface
- Returns scored priorities with reasoning

**Layer 3 — Deterministic validation** (server-side):
- Sanity-checks LLM proposals against graph
- Verifies referenced nodes exist
- Confirms proposed paths are valid
- Catches hallucinated targets

**Layer 4 — Operator review**:
- Sees ranked, annotated task list with reasoning
- Approves, redirects, or overrides
- Can inject new objectives or shift OPSEC profile

### Phase 3 — Agent Dispatch + Execution

When frontier diverges (e.g., both AD and web attack surfaces), primary session spawns sub-agents. Each agent:
- Connects to same MCP server
- Receives scoped subgraph view (only relevant nodes/edges)
- Follows validate → execute → report loop
- Reports findings in real time (not batched)

Primary session monitors via periodic `get_state()` calls, sees new frontier items from agent discoveries, dispatches follow-up agents immediately.

Inference rules fire on every `report_finding()`:
- New credential → POTENTIAL_AUTH edges to all compatible services
- SMB signing disabled → RELAY_TARGET edges
- Kerberos service → MEMBER_OF_DOMAIN edges
- ADCS misconfiguration → ESC1-ESC8 edges
- Unconstrained delegation → DELEGATES_TO edges

### Phase 4 — Compaction / Recovery

When context fills and compacts (or a fresh session starts):
1. LLM calls `get_state()`
2. Server generates complete briefing from graph: current access, objective progress, active agents, frontier, recent activity
3. LLM is immediately productive — zero information loss

This also enables:
- Resuming engagements after hours/days
- Handing off between operators
- Running retrospectives from fresh sessions

### Phase 5 — Objective Tracking

After every graph update, server evaluates: does a confirmed path exist from current access to any objective node? Matching is criteria-based (e.g., credential node with `privileged: true` and `cred_domain: "target.local"` satisfies the "domain admin" objective).

When an objective is achieved, it's marked complete. Scoring shifts to remaining objectives. Operator can add new objectives mid-engagement.

### Phase 6 — Post-Engagement Retrospective

LLM calls `get_history()` and `export_graph()` to review the full engagement. Produces:
- New inference rules (patterns the deterministic layer should recognize)
- Skill library updates (methodology gaps discovered during execution)
- Weight preset tuning (if scoring consistently misjudged priorities)
- Full attack path graph for client reporting
- Structured engagement traces (future RLVR training signal)

---

## Graph Model Reference

### Node Types (12)

| Type | Key Properties |
|------|----------------|
| `host` | ip, hostname, os, os_version, alive, edr, domain_joined |
| `service` | port, protocol, service_name, version, banner |
| `domain` | domain_name, functional_level |
| `user` | username, display_name, enabled, privileged, sid |
| `group` | display_name, sid, member_of |
| `credential` | cred_type, cred_value, cred_user, cred_domain |
| `share` | share_name, share_path, readable, writable |
| `certificate` | template_name, ca_name, eku, enrollee_supplies_subject |
| `gpo` | (extensible) |
| `ou` | (extensible) |
| `subnet` | (extensible) |
| `objective` | objective_description, objective_achieved |

### Edge Types (33)

**Network:** REACHABLE, RUNS
**Domain:** MEMBER_OF, MEMBER_OF_DOMAIN, TRUSTS, SAME_DOMAIN
**Access:** ADMIN_TO, HAS_SESSION, CAN_RDPINTO, CAN_PSREMOTE
**Credentials:** VALID_ON, OWNS_CRED, POTENTIAL_AUTH
**AD Attacks:** CAN_DCSYNC, DELEGATES_TO, WRITEABLE_BY, GENERIC_ALL, GENERIC_WRITE, WRITE_OWNER, WRITE_DACL, ADD_MEMBER, FORCE_CHANGE_PASSWORD, ALLOWED_TO_ACT
**ADCS:** CAN_ENROLL, ESC1, ESC2, ESC3, ESC4, ESC6, ESC8
**Lateral:** RELAY_TARGET, NULL_SESSION
**Meta:** PATH_TO_OBJECTIVE, RELATED

### Built-in Inference Rules (6)

| Rule | Trigger | Produces | Confidence |
|------|---------|----------|------------|
| Kerberos → Domain | Service: kerberos | MEMBER_OF_DOMAIN → domain nodes | 0.9 |
| SMB Signing → Relay | Service: smb, signing=false | RELAY_TARGET from compromised | 0.8 |
| MSSQL + Domain | Service: mssql on domain host | POTENTIAL_AUTH from domain creds | 0.7 |
| Credential Fanout | New credential node | POTENTIAL_AUTH to all compatible services | 0.6 |
| ADCS ESC1 | Certificate: enrollee_supplies_subject | ESC1 from enrollable users | 0.75 |
| Unconstrained Delegation | Host: unconstrained_delegation | DELEGATES_TO from domain users | 0.85 |

---

## Setup Instructions

### Prerequisites

- Node.js 20+
- Claude Code CLI (`claude` command)
- Security tools installed on the testing system (nmap, nxc/netexec, certipy, impacket, etc.)
- Authorized testing scope and written permission

### Install

```bash
tar xzf overwatch.tar.gz
cd overwatch
npm install
npm run build
```

### Configure Engagement

Edit `engagement.json` with your target scope, objectives, and OPSEC profile. See the included sample config for structure.

OPSEC profiles:
- `ctf` — max_noise: 1.0, no restrictions
- `pentest` — max_noise: 0.7, standard internal
- `redteam` — max_noise: 0.3, stealth engagement
- `assumed_breach` — max_noise: 0.5, start with access

### Connect to Claude Code

The `.claude/settings.json` in the project root is pre-configured:

```json
{
  "mcpServers": {
    "overwatch": {
      "command": "node",
      "args": ["dist/index.js"],
      "env": {
        "OVERWATCH_CONFIG": "./engagement.json",
        "OVERWATCH_SKILLS": "./skills"
      }
    }
  }
}
```

### Run

```bash
cd overwatch
claude
```

Claude Code connects to the MCP server automatically. The `CLAUDE.md` file in the project root provides the primary session instructions. Claude calls `get_state()` first to load the briefing, then enters the main loop.

---

## Project Structure

```
overwatch/
├── .claude/settings.json       # Claude Code MCP server config
├── AGENTS.md                   # Primary session system prompt
├── CLAUDE.md                   # Claude Code instructions
├── README.md                   # Project documentation
├── engagement.json             # Engagement config (edit this)
├── package.json
├── tsconfig.json
├── vitest.config.ts
├── src/
│   ├── index.ts                # MCP server entrypoint (~80 lines)
│   ├── types.ts                # Full type taxonomy + Zod schemas
│   ├── tools/                  # 12 tool modules + error boundary
│   │   ├── error-boundary.ts   # withErrorBoundary wrapper for all handlers
│   │   ├── state.ts            # get_state, get_history, export_graph
│   │   ├── findings.ts         # report_finding
│   │   ├── scoring.ts          # next_task
│   │   ├── exploration.ts      # query_graph, find_paths, validate_action
│   │   ├── agents.ts           # register_agent, get_agent_context, update_agent
│   │   ├── skills.ts           # get_skill
│   │   ├── bloodhound.ts       # ingest_bloodhound
│   │   ├── toolcheck.ts        # check_tools
│   │   ├── processes.ts        # track_process, check_processes
│   │   ├── inference.ts        # suggest_inference_rule
│   │   ├── parse-output.ts     # parse_output
│   │   └── retrospective.ts   # run_retrospective
│   ├── cli/
│   │   └── retrospective.ts    # npm run retrospective (CLI)
│   ├── dashboard/
│   │   └── index.html          # Live dashboard SPA (sigma.js + graphology)
│   └── services/
│       ├── graph-engine.ts     # Graph orchestrator (thin facade over modules)
│       ├── engine-context.ts   # Shared mutable state for all engine modules
│       ├── state-persistence.ts# Persist, snapshot rotation, load, recovery
│       ├── agent-manager.ts    # Agent task CRUD lifecycle
│       ├── inference-engine.ts # Rule matching, edge production, selectors
│       ├── path-analyzer.ts    # Shortest-path, objective resolution
│       ├── frontier.ts         # Frontier computation (incomplete nodes, untested edges)
│       ├── dashboard-server.ts # HTTP + WebSocket server for live dashboard
│       ├── retrospective.ts   # Post-engagement analysis (5 outputs)
│       ├── skill-index.ts      # TF-IDF RAG search over skills
│       ├── cidr.ts             # CIDR expansion and scope checking
│       ├── bloodhound-ingest.ts# BloodHound JSON parser
│       ├── output-parsers.ts   # nmap XML, nxc, certipy parsers
│       ├── tool-check.ts       # Tool availability health check
│       └── process-tracker.ts  # Long-running process tracker
├── skills/                     # 29 methodology files (markdown)
│   ├── network-recon.md        ├── smb-enumeration.md
│   ├── dns-enumeration.md      ├── snmp-enumeration.md
│   ├── ad-discovery.md         ├── kerberoasting.md
│   ├── adcs-exploitation.md    ├── smb-relay.md
│   ├── lateral-movement.md     ├── privilege-escalation.md
│   ├── credential-dumping.md   ├── password-spraying.md
│   ├── ad-persistence.md       ├── domain-trust-attacks.md
│   ├── pivoting.md             ├── web-discovery.md
│   ├── web-vuln-scanning.md    ├── sql-injection.md
│   ├── web-app-attacks.md      ├── cms-exploitation.md
│   ├── linux-enumeration.md    ├── linux-privesc.md
│   ├── aws-exploitation.md     ├── azure-exploitation.md
│   ├── gcp-exploitation.md     ├── data-exfiltration.md
│   ├── persistence.md          ├── sccm-attacks.md
│   └── exchange-attacks.md
└── dist/                       # Compiled JS (after npm run build)
```

---

## Extending the System

### Adding Skills

Create a markdown file in `skills/` with this structure:

```markdown
# Skill Name

tags: keyword1, keyword2, keyword3

## Objective
## Prerequisites
## Methodology
## Reporting
## OPSEC Notes
```

Tags improve RAG search ranking. Use specific terms the LLM would search for.

### Adding Inference Rules

In `graph-engine.ts`, add to the BUILTIN_RULES array:

```typescript
{
  id: 'rule-custom',
  name: 'Custom Rule Name',
  description: 'What this detects',
  trigger: {
    node_type: 'service',
    property_match: { service_name: 'winrm' }
  },
  produces: [{
    edge_type: 'CAN_PSREMOTE',
    source_selector: 'domain_credentials',
    target_selector: 'parent_host',
    confidence: 0.7
  }]
}
```

### Completed Additions (v0.2)

All items from the original v0.1 roadmap have been implemented except #7:

1. ~~**BloodHound JSON ingestion**~~ — ✅ `ingest_bloodhound` tool + `bloodhound-ingest.ts` parser. Handles computers, users, groups, domains, GPOs with ACE/session/delegation edge extraction.
2. ~~**Tool availability health check**~~ — ✅ `check_tools` tool + `tool-check.ts`. Verifies nmap, nxc, certipy, impacket, etc.
3. ~~**Process tracking**~~ — ✅ `track_process` + `check_processes` tools + `process-tracker.ts`.
4. ~~**Richer subgraph scoping**~~ — ✅ N-hop BFS, auto-compute from frontier, credential/service enrichment in `get_agent_context`.
5. ~~**`suggest_inference_rule` tool**~~ — ✅ With `backfillRule` for retroactive application to existing graph.
6. ~~**Output parsing helpers**~~ — ✅ `parse_output` tool with nmap XML, nxc, and certipy parsers. Nmap service names normalized to match inference rules.

Additional v0.2 work:
- **29 offensive security skills** — full methodology library with exact commands, OPSEC noise ratings, graph reporting, detection signatures, and sequencing dependencies. All commands reference nxc (NetExec).
- **Bug fixes** — scope guard edge leak, objective pathfinding to real nodes, snapshot rollback inference rule restoration, nmap service name normalization, BloodHound admincount boolean normalization.
- **147 tests** across 8 test files, all passing.

### Completed Additions (v0.3)

1. **Error boundaries** — All 20 async MCP tool handlers wrapped with `withErrorBoundary(toolName, handler)` in `src/tools/error-boundary.ts`. Catches thrown errors, logs tool name + stack trace, returns structured `{ error, tool, isError: true }` response. Prevents MCP server crashes from individual tool failures. Bootstrap/startup errors are NOT caught (intentional).

2. **GraphEngine modular split** — The monolithic 1500-line `graph-engine.ts` has been decomposed into 6 focused modules sharing a single `EngineContext` mutable state object. All modules hold a reference to `ctx` (not individual fields), so when `recoverFromSnapshot()` replaces `ctx.graph`, every module sees the new graph immediately. Public API unchanged — `GraphEngine` is now a thin facade:
   - `engine-context.ts` — shared mutable state (graph, config, rules, agents, activity log, callbacks)
   - `state-persistence.ts` — persist, snapshot rotation, load, recovery
   - `agent-manager.ts` — agent task CRUD
   - `inference-engine.ts` — rule matching, edge production, selector resolution
   - `path-analyzer.ts` — shortest-path, objective resolution, path confidence
   - `frontier.ts` — frontier computation (incomplete nodes, untested inferred edges)

3. **193 tests** across 9 test files, all passing.

### Roadmap (v0.4+)

Priority items for the next iteration:

1. ~~**Retrospective tool**~~ — ✅ `run_retrospective` MCP tool + `npm run retrospective` CLI. Produces 5 outputs: inference rule suggestions, skill gap analysis, context-improvement recommendations, attack path report (markdown), and heuristic RLVR trace telemetry. Core logic in `retrospective.ts` service, thin wrappers for MCP and CLI.

2. **Live engagement dry-run** — end-to-end test against a controlled lab (e.g., GOAD, Offshore) to validate the full loop: get_state → next_task → get_skill → validate_action → bash execution → parse_output/report_finding → inference → repeat. This will surface integration gaps that unit tests can't catch.

3. **Multi-engagement support** — ability to run multiple engagements simultaneously with isolated graph state. Currently single-engagement per server instance.

4. ~~**Web dashboard**~~ — ✅ Live real-time dashboard using sigma.js (WebGL) + graphology. Served from same MCP server process on port 8384 (configurable via `OVERWATCH_DASHBOARD_PORT`). Features: force-directed graph layout, node filtering by type, search, objective tracker, frontier panel, agent activity, WebSocket push updates with HTTP poll fallback. Read-only.

5. **Weight presets + tuning** — the scoring layer references weight presets (ctf/pentest/redteam/assumed_breach) in the config but doesn't use them yet. Implement configurable scoring weights that shift frontier priority based on engagement type.

6. **RLVR export** — structured engagement traces (state, action, outcome triplets) exportable for reinforcement learning from verifiable rewards. Each graph transition is a natural training signal.

7. ~~**Additional parsers**~~ — ✅ Added 4 parsers to `parse_output`: `secretsdump` (SAM/NTDS hash extraction → credential + user nodes), `kerbrute` (user enumeration + password spray → user + domain + credential nodes), `hashcat` (cracked NTLM/Kerberoast/AS-REP/NTLMv2 → credential nodes), `responder` (captured NTLMv2 hashes → credential + user + host nodes + session edges). BloodHound-python stdout and ldapdomaindump deferred (already covered by `ingest_bloodhound` JSON parser).

---

## Design Decisions Log

### Why TypeScript over Python?

MCP SDK is TS-native and first-class. Claude Code's ecosystem is Node/TS. graphology is a mature TS graph library. Single runtime, no polyglot. Python's NetworkX is nice but not worth the dependency when graphology covers all needed algorithms.

### Why not wrap tools as MCP functions (hexstrike approach)?

Claude Code already has bash execution. The LLM knows how to construct complex command lines with context-specific flags. Wrapping 150+ tools as MCP functions is maintenance burden with no intelligence gain. Our value is in the state/reasoning layer, not in tool abstraction.

### Why nxc (NetExec)?

NetExec (`nxc`) is the actively maintained tool for SMB/LDAP/WinRM enumeration and spraying. All skills and parsers reference `nxc`.

### Why hybrid scoring instead of pure deterministic?

Offensive security is too combinatorial for static rules. The interesting attack chains happen in the gaps between rules (e.g., "this ADCS misconfiguration combined with that enrollment agent permission is an ESC1 chain"). The LLM handles the creative pattern recognition. The deterministic layer handles hard constraints that don't benefit from reasoning (scope, dedup, OPSEC vetoes).

### Why graph over SQLite?

Engagements are fundamentally about relationships: credential X is valid on service Y which runs on host Z which is domain-joined to domain W. SQLite stores facts as rows. Graphs store relationships as edges. "What's the shortest path from my current access to domain admin?" is a graph traversal, not a SQL query.

### Why inference rules?

When an agent finds SMB signing disabled, a human operator immediately thinks "relay target." When a new credential is discovered, a human thinks "test it against every accessible service." Inference rules encode these reflexes as deterministic graph transformations, generating hypothesis edges the LLM then evaluates. This compounds the graph's value — every finding creates not just new nodes, but new relationships to explore.

### Why the deterministic layer is thin (guardrail, not brain)?

Early design had a weighted scoring formula in the deterministic layer. This was wrong — it would miss creative attack chains that a formula can't express. The deterministic layer now only hard-filters (scope, dedup, OPSEC ceiling). Everything else passes to the LLM with graph metrics attached as context. The LLM has full unrestricted graph access via `query_graph()` to explore any pattern it wants.

---

## Disclaimer

Overwatch is designed for authorized security testing only. Do not use against systems without explicit written permission. The system logs all actions to the engagement graph — this creates a detailed audit trail of every command executed during the engagement.
