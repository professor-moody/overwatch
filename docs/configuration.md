# Configuration

## Runtime Prerequisites

Overwatch targets Node.js **>= 20** (matches `package.json#engines`). Older
runtimes will be rejected by the npm install step. A few capabilities are
"soft" optional and require system-level packages installed by the operator:

- **Interactive PTY sessions** (`open_session` / `send_to_session` with a
  pseudo-terminal): require `node-pty`, which compiles a native binding at
  install time and needs the platform's build toolchain (Xcode CLI tools on
  macOS, `build-essential` + `python3` on Debian/Ubuntu).
- **Password-based SSH sessions**: require `sshpass` on `$PATH` so the
  session-control layer can drive interactive password prompts non-interactively.

If `node-pty` is not built, Overwatch falls back to non-PTY pipes for shell
sessions; if `sshpass` is missing, password-based SSH sessions are reported
as a precheck failure rather than silently hanging.

## Engagement Config (`engagement.json`)

The engagement config defines scope, objectives, and OPSEC policy. It's loaded at server startup from the path specified by `OVERWATCH_CONFIG` (defaults to `./engagement.json`).

### Schema

```json
{
  "id": "string (required)",
  "name": "string (required)",
  "created_at": "ISO 8601 timestamp (required)",
  "profile": "goad_ad | single_host | cloud | web_app | hybrid | network (optional, inferred if omitted; network must be set explicitly)",
  "scope": {
    "cidrs": ["CIDR notation strings"],
    "domains": ["domain names"],
    "exclusions": ["IPs or hostnames to exclude"],
    "hosts": ["additional in-scope hostnames"],
    "aws_accounts": ["AWS account IDs"],
    "azure_subscriptions": ["Azure subscription IDs"],
    "gcp_projects": ["GCP project IDs"],
    "url_patterns": ["URL glob patterns"]
  },
  "objectives": [
    {
      "id": "string (required)",
      "description": "string (required)",
      "target_node_type": "host | service | credential | ...",
      "target_criteria": { "property": "value" },
      "achieved": false
    }
  ],
  "opsec": {
    "name": "string (required)",
    "max_noise": 0.7,
    "enabled": true,
    "approval_mode": "auto-approve | approve-critical | approve-all",
    "approval_timeout_ms": 300000,
    "time_window": {
      "start_hour": 8,
      "end_hour": 22
    },
    "blacklisted_techniques": ["zerologon"],
    "notes": "Free-form notes"
  },
  "phases": [
    {
      "id": "recon",
      "name": "Recon",
      "order": 1,
      "strategies": ["enumeration"],
      "entry_criteria": [{ "type": "always" }],
      "exit_criteria": [{ "type": "objective_achieved", "objective_id": "host-discovery-complete" }],
      "opsec_overrides": { "max_noise": 0.3 },
      "approval_overrides": { "mode": "auto-approve" }
    }
  ],
  "tape": {
    "enabled": false,
    "dir": "./tapes",
    "file": null
  },
  "hash_chain_enabled": true,
  "engagement_nonce": "64-char-hex-string (auto-generated for new engagements)",
  "engagement_signing_key_id": "optional-key-id-for-signed-checkpoints",
  "subagent_isolation": "in_process | process",
  "available_models": ["claude-opus-4-8", "claude-sonnet-5", "claude-haiku-4-5"],
  "default_agent_model": "claude-sonnet-5"
}
```

### Scope

| Field | Type | Description |
|-------|------|-------------|
| `cidrs` | `string[]` | CIDR ranges in scope (e.g., `10.10.10.0/24`) |
| `domains` | `string[]` | Domain names in scope (e.g., `target.local`) |
| `exclusions` | `string[]` | IPs or hostnames explicitly excluded |
| `hosts` | `string[]` | Additional in-scope hostnames not covered by CIDRs |
| `aws_accounts` | `string[]` | AWS account IDs in scope |
| `azure_subscriptions` | `string[]` | Azure subscription IDs in scope |
| `gcp_projects` | `string[]` | GCP project IDs in scope |
| `url_patterns` | `string[]` | URL glob patterns in scope (e.g., `https://app.target.com/**`) |

### Lab Profile

The optional `profile` field selects the lab preflight profile, which controls which checks run and what tools are required.

| Profile | Description |
|---------|-------------|
| `goad_ad` | Active Directory lab — requires BloodHound, NXC, nmap. Checks domain scope. |
| `single_host` | Single-target HTB machine — minimal scope, focused checks. |
| `network` | Network-only engagement — requires nmap. BH/NXC optional. Checks CIDR scope, not domains. |
| `web_app` | Web application assessment — checks URL patterns, recommends web scanners. |
| `cloud` | Cloud-only engagement — checks cloud account scope, recommends cloud tools (pacu, prowler). |
| `hybrid` | Combined infrastructure + cloud — checks all scope types. |

If omitted, the profile is **inferred** with the following precedence: `hybrid` when both domains and cloud accounts are present, `cloud` when cloud accounts are scoped (even if URL patterns also exist), `web_app` when URL patterns are scoped (takes precedence over domains), `goad_ad` when `scope.domains` is non-empty, `single_host` otherwise. Note: `network` is never inferred — it must be set explicitly.

### Objectives

Each objective describes a goal. The engine tracks progress by matching graph nodes against `target_criteria`.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Unique objective identifier |
| `description` | `string` | Human-readable goal |
| `target_node_type` | `NodeType` | Node type to match (optional) |
| `target_criteria` | `object` | Property key-value pairs to match against nodes |
| `achieved` | `boolean` | Automatically set when criteria are met |

### OPSEC Profiles

The `name` field is free-form text; common values include `ctf`, `pentest`, `assumed_breach`, `redteam`.

| Profile | `max_noise` | Description |
|---------|-------------|-------------|
| `ctf` | 1.0 | No restrictions. Speed over stealth. |
| `pentest` | 0.7 | Standard internal pentest. Some noise acceptable. |
| `assumed_breach` | 0.5 | Start with access. Focus on objectives. |
| `redteam` | 0.3 | Stealth engagement. Quiet techniques preferred. |

**`max_noise`** is a hard ceiling (0.0–1.0). Actions with `opsec_noise` above this value are filtered from the frontier and rejected by `validate_action`.

**`enabled`** (boolean, default `false` for legacy compatibility) gates the OPSEC ceiling enforcement on direct `run_bash`/`run_tool` actions. With `enabled: false` the noise pipeline is fully inert — no substitution, no recording, no rejection. Turn it on for engagements where the ceiling needs to bite.

**`time_window`** (optional) restricts action execution to specific hours (0–23). Useful for engagements with business-hours-only authorization.

**`blacklisted_techniques`** are rejected outright by `validate_action` regardless of noise level.

**`approval_mode`** controls the per-action approval gate:

- `auto-approve` (default) — actions run without operator review.
- `approve-critical` — actions whose noise would exceed half the ceiling, or whose technique is blacklisted, or under defensive pressure, are queued for operator approval.
- `approve-all` — every action is queued.

**`approval_timeout_ms`** (default 300000) bounds how long the queue waits for an operator response. On timeout, the action proceeds **but** is stamped `auto_approved: true` and `unattended_execute: true` so retros and OPSEC logs surface unattended decisions.

### Phase-Aware Policy

Engagement phases declared in `phases` can override OPSEC and approval policy while they're active. The active phase is the one whose `entry_criteria` are met but whose `exit_criteria` are not.

```json
"phases": [
  {
    "id": "exploit",
    "name": "Exploitation",
    "order": 2,
    "strategies": ["post_exploitation"],
    "entry_criteria": [{ "type": "objective_achieved", "objective_id": "initial-access" }],
    "exit_criteria": [{ "type": "objective_achieved", "objective_id": "domain-admin" }],
    "opsec_overrides": { "max_noise": 0.4 },
    "approval_overrides": {
      "mode": "approve-all",
      "blacklisted_techniques": ["zerologon"]
    }
  }
]
```

- `opsec_overrides` is `Partial<OpsecProfile>` — only the fields you specify get overridden; others fall through to the engagement-level OPSEC.
- `approval_overrides.blacklisted_techniques` **extends** the engagement-level list (cannot weaken operator-level safety).
- Phase transitions emit `phase_entered` / `phase_exited` events to the activity log. These are hash-chained.

### Deterministic ID and Replay

For engagements created after the foundations work shipped:

- **`engagement_nonce`** (64-char hex, auto-generated by `engagement-manager` on creation) flips action and event ID generation from `uuidv4` to `sha256(nonce | agent_id | timestamp | command_signature | sequence)`. Same inputs → same IDs across runs.
- **`hash_chain_enabled`** defaults to `true`. The activity-chain emits signed checkpoints every 500 events / 30 minutes; verifiers resume from the latest checkpoint instead of replaying genesis.
- **Mutation journal** (`<state-file>.journal.jsonl`) is a write-ahead log appended before each graph mutation. On load, the engine replays journal entries past the last snapshot. Snapshot rotation truncates the journal up to the snapshot's seq.
- **Golden-master replay**: tests can record a tape (in `src/__tests__/golden-master/fixtures/`), replay against a fresh engine, and assert byte-identical state. Two replays of the same tape produce the same `graph_hash` — see `src/services/golden-replay.ts`.

**Strict migration.** Engagements created before the foundations work (no `engagement_nonce` field) keep `uuidv4` IDs forever. We do not retroactively recompute IDs. If you need replay/audit guarantees on an existing engagement, create a fresh engagement and re-run.

### Sub-agent Isolation (Scaffolded)

`subagent_isolation` controls where sub-agents run:

- `'in_process'` (default) — sub-agents share memory with the engine and call MCP tools directly. Current production behavior.
- `'process'` — sub-agents run as child Node processes communicating with the engine over JSON-over-stdio per `src/services/subagent-ipc.ts`. **Scaffolded and proven on the recon-scoping role.** Other roles fall back to in-process even when this flag is set, until follow-up work fills out coverage.

#### Choosing a Profile

- **CTF / Lab** — Use `ctf` when speed matters and there's no defender. GOAD labs, HTB machines, practice ranges.
- **Internal pentest** — Use `pentest` for standard authorized testing. Allows port scanning, enumeration, and most exploitation techniques.
- **Assumed breach** — Use `assumed_breach` when you start with valid credentials. Skips noisy discovery and focuses on lateral movement and privilege escalation.
- **Red team** — Use `redteam` for stealth engagements with active defenders. Limits to quiet techniques: targeted queries, Kerberoasting, careful lateral movement. Blocks mass scanning and brute force.

#### Scope Violation Behavior

When an action targets something outside scope:

1. **Frontier filtering** — `next_task` never returns frontier items targeting out-of-scope hosts or services
2. **Validation rejection** — `validate_action` returns `invalid` with error: `"Target is out of scope"`
3. **No graph pollution** — `report_finding` accepts out-of-scope nodes (they may be discovered passively) but they won't generate frontier items
4. **URL fallback** — When `url_patterns` is not configured, `validate_action` falls back to checking the URL's hostname against `scope.domains`. URLs with hostnames not matching any scoped domain are rejected.

### Agent Models

Headless agents (and the free-form planner) run as `claude -p` sub-processes, so you can choose which Claude model each uses.

| Field | Type | Description |
|-------|------|-------------|
| `available_models` | `string[]` | The models the **Deploy** picker offers. When set and non-empty, a dispatch requesting a model outside this list is **rejected** — so an org that doesn't have a given model simply omits it here. Unset/empty → the picker offers a default set (`claude-opus-4-8`, `claude-sonnet-5`, `claude-haiku-4-5`) and any model is allowed. |
| `default_agent_model` | `string` | Model used for headless agents and the planner when the operator doesn't pick one. Unset → the `claude` CLI's own default. |

The chosen model is passed straight through as `claude -p --model <id>`. Pick a model per-deploy in the dashboard's Deploy modal, or set `default_agent_model` to apply one engagement-wide.

### Agent Resilience

A headless agent that ends **abnormally** — wall-clock timeout (30 min), heartbeat-reap, process death, or a boot reconcile after a crash — used to leave its unfinished frontier work **silently** stranded ("the log recovers but nothing continues"). It's now made **loud**: once the dead process is confirmed gone, a one-time activity alert (`work_reoffered`) notes that the item is stranded and **back on the frontier for pickup**. The frontier lease was already released on termination, so the item re-surfaces in `next_task` / `get_state` for the operator — or the persistent orchestrator (Phase 3.2) — to redo.

This is deliberately an **alert + re-offer**, not an autonomous re-spawn: re-dispatching correctly over a mutable, id-reusing frontier plus OPSEC / dispatch caps is the orchestrator's job. A **deliberate** stop (operator cancel/dismiss, stop directive, or a campaign abort) is marked `no_retry` and never surfaced as stranded. No configuration is required.

### Example: Multi-Domain Engagement

```json
{
  "id": "eng-multi",
  "name": "Multi-Domain Assessment",
  "created_at": "2026-03-20T00:00:00Z",
  "scope": {
    "cidrs": ["10.10.10.0/24", "10.10.20.0/24", "192.168.1.0/24"],
    "domains": ["corp.local", "dev.corp.local", "partner.org"],
    "exclusions": ["10.10.10.1", "10.10.20.1", "192.168.1.254"],
    "hosts": ["jumpbox.corp.local", "vpn.partner.org"]
  },
  "objectives": [
    {
      "id": "obj-da-corp",
      "description": "Domain Admin on corp.local",
      "target_node_type": "credential",
      "target_criteria": { "privileged": true, "cred_domain": "corp.local" },
      "achieved": false
    },
    {
      "id": "obj-da-partner",
      "description": "Domain Admin on partner.org",
      "target_node_type": "credential",
      "target_criteria": { "privileged": true, "cred_domain": "partner.org" },
      "achieved": false
    }
  ],
  "opsec": {
    "name": "pentest",
    "max_noise": 0.7,
    "blacklisted_techniques": ["zerologon", "printnightmare"],
    "notes": "Authorized internal pentest. No production disruption."
  }
}
```

### Example: Red Team with Time Window

```json
{
  "id": "eng-redteam",
  "name": "Red Team - Financial Corp",
  "created_at": "2026-03-20T00:00:00Z",
  "scope": {
    "cidrs": ["10.0.0.0/8"],
    "domains": ["fincorp.com"],
    "exclusions": ["10.0.0.1", "10.0.0.2"],
    "hosts": []
  },
  "objectives": [
    {
      "id": "obj-ceo-mail",
      "description": "Access CEO mailbox",
      "target_node_type": "service",
      "target_criteria": { "service_name": "exchange", "hostname": "mail.fincorp.com" },
      "achieved": false
    }
  ],
  "opsec": {
    "name": "redteam",
    "max_noise": 0.3,
    "time_window": {
      "start_hour": 8,
      "end_hour": 18
    },
    "blacklisted_techniques": ["zerologon", "printnightmare", "petitpotam", "mass_scan"],
    "notes": "Active SOC monitoring. Business hours only. Avoid triggering EDR alerts."
  }
}
```

!!! note "Time window enforcement"
    When `time_window` is set, `validate_action` will return a warning (not an error) if the current hour is outside the window. This is a soft constraint — the operator can choose to proceed.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OVERWATCH_CONFIG` | `./engagement.json` | Path to engagement configuration file |
| `OVERWATCH_SKILLS` | `./skills` | Path to skill library directory |
| `OVERWATCH_DASHBOARD_PORT` | `8384` | Port for live dashboard (set to `0` to disable) |
| `OVERWATCH_TRANSPORT` | `stdio` | Transport mode: `stdio` or `http` |
| `OVERWATCH_HTTP_PORT` | `3000` | Port for HTTP/SSE transport (when `OVERWATCH_TRANSPORT=http`) |
| `OVERWATCH_HTTP_HOST` | `127.0.0.1` | Bind address for HTTP/SSE transport |
| `OVERWATCH_TAPE` | unset | Force the in-process JSON-RPC tape recorder on (`1`/`true`/`on`) or off (`0`/`false`/`off`) for stdio and HTTP transports. Overrides `engagement.tape.enabled` and records `started_by: "env"` when it starts recording. See [Tape Recording](tape-recording.md). |
| `OVERWATCH_TAPE_DIR` | `./tapes` | Directory for auto-named tape files when the recorder is enabled |
| `OVERWATCH_TAPE_FILE` | unset | Explicit tape file path (overrides `OVERWATCH_TAPE_DIR`) |
