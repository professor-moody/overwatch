# update_scope

Expand or contract the engagement scope at runtime.

## When to use

- A pivot network is discovered outside the original scope CIDRs
- A new Active Directory domain appears that wasn't in the initial config
- A host needs to be explicitly excluded (e.g. production infrastructure)
- An exclusion needs to be lifted after confirming the target is safe

## Confirmation gate

The tool has a **two-phase** workflow:

1. **Preview** (`confirm: false`, the default) — returns a dry-run showing what would change, how many nodes would enter/leave scope, and which pending scope suggestions would be resolved. No state is mutated.
2. **Apply** (`confirm: true`) — mutates `config.scope` in-place, persists immediately, logs a `scope_updated` activity event with full before/after diff, and invalidates the frontier cache so new discovery items appear.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `add_cidrs` | `string[]` | No | CIDRs to add to scope (e.g. `["172.16.1.0/24"]`) |
| `remove_cidrs` | `string[]` | No | CIDRs to remove from scope |
| `add_domains` | `string[]` | No | Domains to add to scope (e.g. `["internal.corp"]`) |
| `remove_domains` | `string[]` | No | Domains to remove from scope |
| `add_exclusions` | `string[]` | No | IPs or CIDRs to add to exclusion list |
| `remove_exclusions` | `string[]` | No | IPs or CIDRs to remove from exclusion list |
| `reason` | `string` | **Yes** | Operator-provided reason for the scope change |
| `confirm` | `boolean` | No | `true` to apply; `false` (default) for dry-run preview |

## Scope suggestions

Out-of-scope host nodes are automatically detected and surfaced in `get_state()` as `scope_suggestions`. Each suggestion includes:

- **`suggested_cidr`** — the inferred /24 CIDR covering the out-of-scope IPs
- **`out_of_scope_ips`** — the specific IPs that are outside current scope
- **`node_ids`** — graph node IDs for the out-of-scope hosts
- **`first_seen_at`** — when the first out-of-scope host in this group was discovered
- **`source_descriptions`** — which agents/tools reported these hosts

## Examples

### Preview a scope expansion

```json
{
  "add_cidrs": ["172.16.1.0/24"],
  "reason": "Pivot network discovered via 10.10.110.100",
  "confirm": false
}
```

### Apply a scope expansion

```json
{
  "add_cidrs": ["172.16.1.0/24"],
  "reason": "Pivot network discovered via 10.10.110.100",
  "confirm": true
}
```

### Exclude a production host

```json
{
  "add_exclusions": ["172.16.1.1"],
  "reason": "Production gateway — do not touch",
  "confirm": true
}
```

### Add a new domain

```json
{
  "add_domains": ["child.corp.local"],
  "reason": "Discovered child AD domain during BloodHound ingest",
  "confirm": true
}
```

## Behavior notes

- CIDRs are validated before application; invalid formats are rejected with an error
- Duplicate entries are silently deduplicated (adding a CIDR already in scope is a no-op)
- The frontier cache is invalidated immediately so `next_task` reflects the new scope
- The persisted state file is written immediately so scope survives restarts
- Activity log entry includes the complete before/after scope diff for audit trail
