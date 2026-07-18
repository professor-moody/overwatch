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

The engagement config defines scope, objectives, and OPSEC policy. In the
recommended managed-daemon workflow, `npm run setup` selects its exact path and
records it in `.overwatch-runtime/profile.json`; normal lifecycle commands use
that persisted selection. A fresh setup defaults to `./engagement.json`.

After startup, use **Console → Add Targets**, **Settings**, or the
`update_scope`, `add_objective`, and `set_opsec` tools. Those revisioned
write-through edits keep the file, live engine, and durable state aligned.
`create_engagement` and the dashboard's **New Engagement** flow instead create
an inactive config under `engagements/`; they do not switch the running daemon.
Dashboard engagement switching is not currently supported.

### Schema

```json
{
  "id": "string (required)",
  "name": "string (required)",
  "created_at": "ISO 8601 timestamp (required)",
  "config_revision": "positive integer (managed by Overwatch)",
  "config_hash": "64-character SHA-256 (managed by Overwatch)",
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
  "default_agent_model": "claude-sonnet-5",
  "orchestrator": { "enabled": false }
}
```

### Active configuration ownership and recovery

Persisted engagement state is explicitly versioned. A missing `state_version`
is legacy V0; current writers use state V1 and transaction journal V2. Before a
V0 engagement can normalize configuration metadata or publish any V1
checkpoint, Overwatch must completely replay its WAL and create a verified
backup under `.migration-backups/`. Check readiness offline with:

```bash
overwatch state migrate --check \
  --config-file /path/to/engagement.json \
  --state-file /path/to/state-engagement-id.json
```

An unsupported newer format remains read-only and byte-preserved. Do not point
an older binary at migrated V1 files; restore the complete checksummed migration
backup into a clean engagement directory first.

For the active engagement, `engagement.json`, the live engine, and the config
embedded in durable state are one revisioned value. Overwatch adds two managed
fields:

| Field | Meaning |
|-------|---------|
| `config_revision` | Monotonic revision assigned after each completed active-config change |
| `config_hash` | SHA-256 of canonical JSON for the complete config, including the revision and excluding only `config_hash` itself |

A legacy file/state pair with neither field is normalized to revision 1 only
when both representations have identical semantics and persistence is writable.
If metadata exists on only one side, a declared hash is invalid, or semantics
differ, Overwatch does not guess.

Active mutations are write-through. Scope, objectives, OPSEC, phase/settings,
and automatic objective-achievement changes use the same config service:

1. Validate the proposed semantic change and calculate the next revision/hash.
2. Durably write a checksummed intent beside the active config as
   `<engagement.json>.write-intent.json`.
3. Atomically replace and fsync the config file.
4. Apply the same revision to the live engine and durable state.
5. Record the audited change, persist it, and remove the intent.

Success is returned only after all managed representations share the target
revision/hash. Inactive engagement edits remain validated atomic file updates;
they become managed by this sequence when that engagement is started.

If a crash interrupts a known write, startup resumes the checksummed intent.
While that completion is unavailable or fails, status is `write_incomplete` and
new durable mutations remain disabled. Do not delete or edit the intent file by
hand.

An unexplained file/state difference starts in degraded read-only mode with
status `diverged`. Inspect it through any of these equivalent read surfaces:

```bash
overwatch recovery
```

- MCP: [`get_recovery_status`](tools/get-recovery-status.md)
- HTTP: `GET /api/recovery`
- Dashboard: the global recovery banner and **Settings → Recovery**

Recovery reports separate the underlying WAL/state result from
`config_recovery`. If both are degraded, config reconciliation cannot bypass or
discard the WAL tail; repair the persistence recovery first.

When `allowed_resolutions` permits it, choose authority explicitly using the
exact observed hashes:

```bash
overwatch config reconcile use_file \
  --file-hash <observed-file-sha256> \
  --state-hash <durable-state-sha256>

overwatch config reconcile use_state \
  --file-hash <observed-file-sha256> \
  --state-hash <durable-state-sha256>
```

- `use_file` validates and applies the file's semantic diff. The engagement
  `id`, `created_at`, and `engagement_nonce` remain immutable.
- `use_state` atomically restores the file from durable-state authority.

Both modes assign a fresh revision, audit the resolution, and reject stale
hashes with a conflict. Refresh recovery status and review the new values before
retrying. See
[`resolve_config_divergence`](tools/resolve-config-divergence.md) for the exact
MCP and HTTP request shape.

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

### Durable Transactions, Deterministic IDs, and Replay

- **Transaction journal** (`<state-file>.journal.jsonl`) is enabled for every
  migrated engagement. Each `EngineTransaction` V2 is written as `tx_begin`,
  bounded operation chunks, and a checksum-protected `tx_commit`, then fsynced
  before the shared recovery applier changes memory. Only complete committed
  transactions replay.
- **Checkpointed bases** store only the highest contiguous successfully applied
  transaction. Recovery starts from the newest valid primary/snapshot base and
  replays newer commits. An unknown, malformed, skipped, or failed record stops
  replay, preserves the original WAL and remaining tail, and leaves the engine
  read-only instead of compacting past uncertainty.
- **`engagement_nonce`** (64-char hex, auto-generated at creation) changes action
  and event IDs from UUIDs to deterministic SHA-256-derived IDs. It is an audit
  and test-replay feature; WAL durability does not depend on the nonce.
- **`hash_chain_enabled`** defaults to `true` for new engagements. The activity
  chain checkpoints every 500 chained events or 30 minutes. Checkpoints are
  Ed25519-signed only when the signing environment is configured; otherwise the
  hash chain and checkpoints remain unsigned but verifiable for continuity.
- **Golden-master replay** tests can replay a controlled tape against a fresh
  engine and compare state hashes. A portable real-engagement restore uses
  `bundle_engagement`, which includes state, WAL, evidence, reports, and a
  versioned manifest; a graph export or tape alone is not a full backup.

An absent persisted-state version is legacy v0. `overwatch state migrate
--check` validates migration readiness without writing; an actual migration
creates and validates a checksummed backup before publishing state v1. Legacy
engagements without `engagement_nonce` retain UUID identities, but they still
receive the current journal/recovery behavior after migration.

### Managed Agent Isolation

Daemon-managed agents and the free-form planner run as supervised `claude -p`
processes over the same HTTP MCP engine. Each worker gets a temporary
task-specific MCP file, `--strict-mcp-config`, user-only Claude settings, a
restricted allowed-tool set, and `--no-session-persistence`. It does not inherit
the terminal Claude session, project MCP entries, project hooks/settings, or
resume history, so dashboard agents and an interactive terminal Claude can run
at the same time without becoming competing state owners.

`subagent_isolation` remains accepted for compatibility with the older Node IPC
scaffold in `subagent-ipc.ts`; it is not the selector for the current managed
Claude worker backend. Use daemon mode (`npm run setup`, then `npm run
daemon:start`) for dashboard deployment.

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

A headless agent that ends **abnormally** — wall-clock timeout (30 min), heartbeat-reap, process death, or a boot reconcile after a crash — used to leave its unfinished frontier work **silently** stranded ("the log recovers but nothing continues"). It's now made **loud**: once the dead process is confirmed gone, a one-time activity alert (`work_reoffered`) notes that the item is stranded and **back on the frontier for pickup**. The frontier lease was already released on termination, so the item re-surfaces in `next_task` / `get_state` for the operator or persistent orchestrator to redo.

This is deliberately an **alert + re-offer**, not an autonomous re-spawn: re-dispatching correctly over a mutable, id-reusing frontier plus OPSEC / dispatch caps is the orchestrator's job. A **deliberate** stop (operator cancel/dismiss, stop directive, or a campaign abort) is marked `no_retry` and never surfaced as stranded. No configuration is required.

### Persistent Orchestrator ("Primary")

By default the dashboard is the orchestrator: you drive it, and each command bar submission spawns a single-shot planner. Opt into a **persistent PRIMARY orchestrator** — a long-lived headless agent that runs the frontier→dispatch→synthesize loop on its own and consumes re-offered work — with:

```json
"orchestrator": { "enabled": true }
```

| Field | Type | Description |
|-------|------|-------------|
| `orchestrator.enabled` | `boolean` | Default **`false`** (opt-in — it drives autonomous dispatch). When `true`, one primary orchestrator is registered at engagement startup and kept alive with **restart-on-crash** (exponential backoff, 30 s → 10 min cap; a run ≥ 5 min resets it). Requires the HTTP/headless runtime + `claude` on PATH. |

The orchestrator's autonomous loop is **prompt-driven** (`get_system_prompt(role="primary")`), and its dispatched sub-agents' actions still pass through the normal OPSEC / approval / scope guards. Steer it live from the command bar's **"Primary"** scope (see [Operator Cockpit](operator-cockpit.md#command-scope)). It's exempt from the 30-min sub-agent wall-clock (it's meant to persist), but the heartbeat watchdog still reaps it if it goes silent — and then restarts it.

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

The table describes raw process inputs. In the recommended managed workflow,
run setup while stopped to persist the selected config/state/endpoints in
`.overwatch-runtime/profile.json`; later lifecycle commands use that profile and
reject conflicting transient ownership overrides. Use raw variables directly
only for an explicitly isolated developer process, fixture, or documented setup
selection.

| Variable | Default | Description |
|----------|---------|-------------|
| `OVERWATCH_CONFIG` | `./engagement.json` | Raw/setup-time engagement config selection; managed lifecycle uses the persisted profile |
| `OVERWATCH_SKILLS` | `./skills` | Path to skill library directory |
| `OVERWATCH_DASHBOARD_PORT` | `8384` | Port for live dashboard (set to `0` to disable) |
| `OVERWATCH_TRANSPORT` | `stdio` | Transport mode: `stdio` or `http` |
| `OVERWATCH_HTTP_PORT` | `3000` | Port for Streamable HTTP transport (when `OVERWATCH_TRANSPORT=http`) |
| `OVERWATCH_HTTP_HOST` | `127.0.0.1` | Bind address for Streamable HTTP transport |
| `OVERWATCH_TAPE` | unset | Force the in-process JSON-RPC tape recorder on (`1`/`true`/`on`) or off (`0`/`false`/`off`) for stdio and HTTP transports. Overrides `engagement.tape.enabled` and records `started_by: "env"` when it starts recording. See [Tape Recording](tape-recording.md). |
| `OVERWATCH_TAPE_DIR` | `./tapes` | Directory for auto-named tape files when the recorder is enabled |
| `OVERWATCH_TAPE_FILE` | unset | Explicit tape file path (overrides `OVERWATCH_TAPE_DIR`) |
