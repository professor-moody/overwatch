# Overwatch

An offensive security engagement orchestrator built as an MCP server. Designed to be the persistent state layer and reasoning substrate for LLM-powered penetration testing with Claude Code.

## Architecture

Overwatch inverts the typical "LLM-as-orchestrator" pattern. Instead of stuffing engagement state into a prompt, the orchestrator is a **persistent MCP server** that the LLM calls into. The graph holds every discovery, relationship, and hypothesis. The LLM proposes actions. The server validates them.

```
┌──────────────┐
│   Operator    │  scope, objectives, OPSEC profile
└──────┬───────┘
       │
┌──────▼────────────────────────────────────────────────┐
│              MCP Orchestrator Server                   │
│                                                        │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Graph Engine │  │ Scoring /    │  │  OPSEC       │  │
│  │ (graphology) │  │ Frontier     │  │  Policy      │  │
│  └──────┬──────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                │                  │          │
│  ┌──────▼────────────────▼──────────────────▼───────┐  │
│  │              MCP Tool Interface                   │  │
│  │  get_state · next_task · validate_action ·        │  │
│  │  log_action_event · parse_output ·                │  │
│  │  report_finding · query_graph · find_paths · ...  │  │
│  └──────────────────────┬────────────────────────────┘  │
└─────────────────────────┼──────────────────────────────┘
                          │ stdio
       ┌──────────────────▼──────────────────┐
       │        Claude Code (Opus)            │
       │     Primary Session + Sub-Agents     │
       └──────────────────────────────────────┘
```

### Key Design Decisions

**Graph, not database.** Engagements are directed property graphs — hosts, services, credentials, and the relationships between them. The graph structure means "credential X is valid on service Y which runs on host Z" is a traversable path, not three rows in a table.

**MCP server, not a prompt.** The orchestrator survives context compaction by design — it's not in the context window. After compaction, `get_state()` reconstructs a complete briefing from the graph. Zero information loss.

**Hybrid scoring.** The deterministic layer handles hard constraints (scope, deduplication, OPSEC vetoes). The LLM handles nuanced reasoning (attack chain spotting, sequencing, risk assessment). Neither does the other's job.

**Inference rules.** When findings are reported, deterministic rules fire automatically to generate hypothesis edges (e.g., "SMB signing disabled → relay target", "new credential → test against all compatible services"). These become frontier items for the LLM to evaluate.

**Full graph access.** The LLM isn't restricted to scored frontier items. `query_graph()` gives unrestricted access to the entire graph for creative path discovery.

## Setup

### Prerequisites

- Node.js 20+
- Claude Code CLI (`claude` command)

### Install

```bash
git clone <repo-url>
cd overwatch
npm install
npm run build
```

### Configure Engagement

Create or edit `engagement.json`:

```json
{
  "id": "eng-001",
  "name": "Internal Pentest - Target Corp",
  "created_at": "2026-03-20T00:00:00Z",
  "scope": {
    "cidrs": ["10.10.10.0/24"],
    "domains": ["target.local"],
    "exclusions": ["10.10.10.254"],
    "hosts": []
  },
  "objectives": [
    {
      "id": "obj-da",
      "description": "Achieve Domain Admin on target.local",
      "target_node_type": "credential",
      "target_criteria": { "privileged": true, "cred_domain": "target.local" },
      "achieved": false
    }
  ],
  "opsec": {
    "name": "pentest",
    "max_noise": 0.7,
    "blacklisted_techniques": ["zerologon"],
    "notes": "Standard internal pentest."
  }
}
```

#### OPSEC Profiles

| Profile | max_noise | Description |
|---------|-----------|-------------|
| `ctf` | 1.0 | No restrictions. Speed over stealth. |
| `pentest` | 0.7 | Standard internal pentest. Some noise acceptable. |
| `redteam` | 0.3 | Stealth engagement. Quiet techniques preferred. |
| `assumed_breach` | 0.5 | Start with access. Focus on objectives. |

### Connect to Claude Code

Add Overwatch as an MCP server in your Claude Code config (`~/.claude/settings.json` or project-level `.claude/settings.json`):

```json
{
  "mcpServers": {
    "overwatch": {
      "command": "node",
      "args": ["<path-to-overwatch>/dist/index.js"],
      "env": {
        "OVERWATCH_CONFIG": "<path-to-engagement.json>",
        "OVERWATCH_SKILLS": "<path-to-overwatch>/skills"
      }
    }
  }
}
```

### Run

```bash
claude
```

Claude Code will connect to the Overwatch MCP server automatically. The `CLAUDE.md` file in the project root provides the primary session instructions. Claude will call `get_state()` first to load the engagement briefing, then enter the main scoring loop.

## First Lab Workflow

### GOAD / Proxmox AD Lab

Use this order for a first real lab run:

1. Start the MCP server and confirm Claude can call `get_state`.
2. Run `run_lab_preflight` with `profile: "goad_ad"` to check tool availability, graph health, persistence, and dashboard readiness.
3. Ingest BloodHound data with `ingest_bloodhound`.
4. Parse and ingest Nmap XML with `parse_output`.
5. Parse and ingest NXC output with `parse_output`.
6. Re-run `get_state` and `run_graph_health` to confirm the graph stayed healthy.
7. Inspect the dashboard for frontier, health, and readiness context.
8. Restart the server once and verify the engagement resumes cleanly from persisted state.

### HTB / Single-Host VM

For a smaller single-target workflow:

1. Run `run_lab_preflight` with `profile: "single_host"`.
2. Parse and ingest Nmap XML with `parse_output`.
3. Report at least one manual or parsed finding. Prefer `parse_output` for supported tools; use `report_finding` for manual observations or unsupported output.
4. Check `get_state`, `next_task`, and `run_graph_health`.
5. Verify a restart/load round-trip before relying on the workflow for longer sessions.

## MCP Tools

| Tool | Purpose | Read-only |
|------|---------|-----------|
| `get_state` | Full engagement briefing from graph | ✓ |
| `run_lab_preflight` | Aggregate lab-readiness checks for GOAD or single-host testing | ✓ |
| `next_task` | Filtered frontier candidates for scoring | ✓ |
| `validate_action` | Pre-execution sanity check and `action_id` issuance | ✗ |
| `log_action_event` | Record explicit action lifecycle around tool execution | ✗ |
| `parse_output` | Parse supported tool output into findings | ✗ |
| `report_finding` | Submit new nodes/edges to the graph | ✗ |
| `query_graph` | Open-ended graph exploration | ✓ |
| `find_paths` | Shortest paths to objectives | ✓ |
| `get_skill` | RAG search over skill library | ✓ |
| `register_agent` | Dispatch a sub-agent task | ✗ |
| `get_agent_context` | Scoped subgraph for an agent | ✓ |
| `update_agent` | Mark agent task complete/failed | ✗ |
| `get_history` | Full activity log | ✓ |
| `export_graph` | Complete graph dump | ✓ |
| `run_graph_health` | Full graph integrity report | ✓ |
| `ingest_bloodhound` | Import BloodHound JSON collections | ✗ |
| `check_tools` | Inspect installed offensive tooling | ✓ |
| `track_process` | Register a long-running scan or collection | ✗ |
| `check_processes` | Inspect tracked process state | ✓ |
| `suggest_inference_rule` | Add a custom inference rule | ✗ |
| `run_retrospective` | Generate retrospective and skill-gap analysis | ✓ |

### `parse_output` vs `report_finding`

Use `parse_output` when the raw output comes from a supported parser such as Nmap XML, NXC/NetExec, Certipy, Secretsdump, Kerbrute, Hashcat, or Responder. This keeps parsing deterministic and reduces LLM token cost.

Use `report_finding` when you are reporting manual observations, unsupported-tool output, analyst judgment, or already-structured nodes and edges.

## Graph Model

### Node Types

`host` · `service` · `domain` · `user` · `group` · `credential` · `share` · `certificate` · `gpo` · `ou` · `subnet` · `objective`

### Edge Types

**Network:** `REACHABLE` · `RUNS`

**Domain:** `MEMBER_OF` · `MEMBER_OF_DOMAIN` · `TRUSTS` · `SAME_DOMAIN`

**Access:** `ADMIN_TO` · `HAS_SESSION` · `CAN_RDPINTO` · `CAN_PSREMOTE`

**Credentials:** `VALID_ON` · `OWNS_CRED` · `POTENTIAL_AUTH`

**AD Attack Paths:** `CAN_DCSYNC` · `DELEGATES_TO` · `WRITEABLE_BY` · `GENERIC_ALL` · `GENERIC_WRITE` · `WRITE_OWNER` · `WRITE_DACL` · `ADD_MEMBER` · `FORCE_CHANGE_PASSWORD` · `ALLOWED_TO_ACT`

**ADCS:** `CAN_ENROLL` · `ESC1` · `ESC2` · `ESC3` · `ESC4` · `ESC6` · `ESC8`

**Lateral Movement:** `RELAY_TARGET` · `NULL_SESSION`

### Inference Rules (Built-in)

| Rule | Trigger | Produces |
|------|---------|----------|
| Kerberos → Domain | Service with `service_name: kerberos` | `MEMBER_OF_DOMAIN` edge to domain nodes |
| SMB Signing → Relay | Service with `smb_signing: false` | `RELAY_TARGET` edges from compromised hosts |
| MSSQL + Domain | MSSQL service on domain host | `POTENTIAL_AUTH` from domain credentials |
| Credential Fanout | New credential node | `POTENTIAL_AUTH` to all compatible services |
| ADCS ESC1 | Certificate with enrollee-supplied subject | `ESC1` from enrollable users |
| Unconstrained Delegation | Host with unconstrained delegation | `DELEGATES_TO` from domain users |

Custom rules can be added programmatically via `addInferenceRule()`.

## Skills

Skills are markdown files in the `skills/` directory. The skill index provides TF-IDF search via the `get_skill` tool.

### Included Skills

- `network-recon.md` — Host discovery, port scanning, service enumeration
- `ad-discovery.md` — AD enumeration, BloodHound, trusts, delegation, ADCS
- `smb-relay.md` — NTLM relay attacks, coercion methods
- `kerberoasting.md` — SPN enumeration, TGS cracking
- `web-discovery.md` — Web app fingerprinting, directory enumeration

### Writing Skills

```markdown
# Skill Name

tags: keyword1, keyword2, keyword3

## Objective
What this skill accomplishes.

## Prerequisites
What's needed before using this skill.

## Methodology
Step-by-step approach.

## Reporting
What to report via report_finding.

## OPSEC Notes
Noise considerations and stealth alternatives.
```

Tags improve search ranking — use specific terms the LLM might search for.

## Engagement Lifecycle

1. **Init** — Operator writes config. Server starts, seeds graph with scope nodes.
2. **Bootstrap** — Primary session discovers live hosts, enumerates services, inference rules fire.
3. **Main Loop** — Deterministic filter → LLM scoring → validation (`action_id` issued) → execution logging → operator approval/dispatch.
4. **Agent Execution** — Sub-agents work scoped tasks, log action start, execute, use `parse_output` for supported raw output, fall back to `report_finding` for manual findings, then log completion or failure.
5. **Recovery** — After compaction, `get_state()` rebuilds context from graph. Zero loss.
6. **Objective Tracking** — Graph path analysis detects when objectives are achieved.
7. **Retrospective** — Full history review produces skill updates, new inference rules, context-improvement recommendations, and heuristic trace telemetry.

## State Persistence

Graph state is persisted to `state-<engagement-id>.json` after every finding. An engagement can be:
- Resumed after compaction (automatic via `get_state`)
- Resumed after Claude Code restart
- Resumed days later from a fresh session
- Analyzed post-engagement for retrospectives

## Development

```bash
npm run build    # Compile TypeScript
npm run dev      # Watch mode
npm start        # Run server (stdio)
```

### Adding Inference Rules

```typescript
engine.addInferenceRule({
  id: 'rule-custom',
  name: 'Custom Rule Name',
  description: 'What this rule detects',
  trigger: {
    node_type: 'service',
    property_match: { service_name: 'tomcat', version_major: 9 }
  },
  produces: [{
    edge_type: 'RELATED',
    source_selector: 'trigger_node',
    target_selector: 'domain_nodes',
    confidence: 0.65
  }]
});
```

### Selector Reference

| Selector | Resolves to |
|----------|-------------|
| `trigger_node` | The node that triggered the rule |
| `trigger_service` | Same as trigger_node |
| `parent_host` | Host running the triggering service |
| `domain_nodes` | All domain nodes |
| `domain_users` | All domain user nodes |
| `domain_credentials` | All NTLM/Kerberos/AES credentials |
| `all_compromised` | Hosts with confirmed access |
| `compatible_services` | Services accepting the credential type |
| `enrollable_users` | All user nodes (for ADCS rules) |

## License

TBD

## Disclaimer

This tool is designed for authorized security testing only. Do not run against production systems without explicit written authorization.
