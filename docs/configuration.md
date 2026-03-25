# Configuration

## Engagement Config (`engagement.json`)

The engagement config defines scope, objectives, and OPSEC policy. It's loaded at server startup from the path specified by `OVERWATCH_CONFIG` (defaults to `./engagement.json`).

### Schema

```json
{
  "id": "string (required)",
  "name": "string (required)",
  "created_at": "ISO 8601 timestamp (required)",
  "profile": "goad_ad | single_host | network (optional, inferred if omitted)",
  "scope": {
    "cidrs": ["CIDR notation strings"],
    "domains": ["domain names"],
    "exclusions": ["IPs or hostnames to exclude"],
    "hosts": ["additional in-scope hostnames"]
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
    "time_window": {
      "start_hour": 8,
      "end_hour": 22
    },
    "blacklisted_techniques": ["zerologon"],
    "notes": "Free-form notes"
  }
}
```

### Scope

| Field | Type | Description |
|-------|------|-------------|
| `cidrs` | `string[]` | CIDR ranges in scope (e.g., `10.10.10.0/24`) |
| `domains` | `string[]` | Domain names in scope (e.g., `target.local`) |
| `exclusions` | `string[]` | IPs or hostnames explicitly excluded |
| `hosts` | `string[]` | Additional in-scope hostnames not covered by CIDRs |

### Lab Profile

The optional `profile` field selects the lab preflight profile, which controls which checks run and what tools are required.

| Profile | Description |
|---------|-------------|
| `goad_ad` | Active Directory lab — requires BloodHound, NXC, nmap. Checks domain scope. |
| `single_host` | Single-target HTB machine — minimal scope, focused checks. |
| `network` | Network-only engagement — requires nmap. BH/NXC optional. Checks CIDR scope, not domains. |

If omitted, the profile is **inferred**: `goad_ad` when `scope.domains` is non-empty, `single_host` otherwise.

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

| Profile | `max_noise` | Description |
|---------|-------------|-------------|
| `ctf` | 1.0 | No restrictions. Speed over stealth. |
| `pentest` | 0.7 | Standard internal pentest. Some noise acceptable. |
| `assumed_breach` | 0.5 | Start with access. Focus on objectives. |
| `redteam` | 0.3 | Stealth engagement. Quiet techniques preferred. |

**`max_noise`** is a hard ceiling (0.0–1.0). Actions with `opsec_noise` above this value are filtered from the frontier and rejected by `validate_action`.

**`time_window`** (optional) restricts action execution to specific hours (0–23). Useful for engagements with business-hours-only authorization.

**`blacklisted_techniques`** are rejected outright by `validate_action` regardless of noise level.

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
