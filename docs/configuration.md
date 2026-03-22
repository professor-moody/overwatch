# Configuration

## Engagement Config (`engagement.json`)

The engagement config defines scope, objectives, and OPSEC policy. It's loaded at server startup from the path specified by `OVERWATCH_CONFIG` (defaults to `./engagement.json`).

### Schema

```json
{
  "id": "string (required)",
  "name": "string (required)",
  "created_at": "ISO 8601 timestamp (required)",
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

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OVERWATCH_CONFIG` | `./engagement.json` | Path to engagement configuration file |
| `OVERWATCH_SKILLS` | `./skills` | Path to skill library directory |
| `OVERWATCH_DASHBOARD_PORT` | `8384` | Port for live dashboard (set to `0` to disable) |
