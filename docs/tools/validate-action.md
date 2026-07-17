# validate_action

Pre-execution sanity check against graph state, scope, and OPSEC policy (engagement-level + active phase).

**Read-only:** No (logs validation event)

## Description

Validate a proposed action before executing it. Checks:

- Do referenced nodes actually exist in the graph?
- Is the target in scope (not excluded)?
- Is the technique blacklisted by the **effective** OPSEC profile (engagement-level + active phase override)?
- Is the action within the approved time window?
- Would the action's noise estimate exceed `max_noise` (when OPSEC enforcement is enabled and a `noise_estimate` is provided)?

Call this before every significant action. Returns valid/invalid with specific errors and warnings, plus a stable `action_id` for correlating with subsequent execution and findings.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `description` | `string` | Yes | Human-readable description of the planned action |
| `target_node` | `string` | No | Node ID being targeted |
| `target_ip` / `target_ips` | `string` / `string[]` | No | Raw target IP(s) for pre-discovery scope validation |
| `target_url` | `string` | No | Target URL for url-pattern scope check |
| `cloud_resource` | `string` | No | Cloud resource ARN/identifier |
| `edge_source` | `string` | No | Source node of the edge being tested |
| `edge_target` | `string` | No | Target node of the edge being tested |
| `technique` | `string` | No | Technique name (e.g., `kerberoast`, `ntlmrelay`, `portscan`) |
| `action_id` | `string` | No | Stable action ID to reuse (auto-generated; deterministic for engagements with `engagement_nonce`, `uuidv4` for legacy) |
| `tool_name` | `string` | No | Tool expected to be used |
| `frontier_item_id` | `string` | No | Frontier item this action came from |
| `noise_estimate` | `number` | No | Predicted noise (0–1). When OPSEC is enabled, exceeding remaining budget rejects the action |
| `allow_unverified_scope` | `boolean` | No | Operator override: skip the fail-closed check for host/service/share targets that cannot be verified against engagement scope |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `action_id` | `string` | Stable ID for this action |
| `action` | `string` | The description provided |
| `validation_result` | `string` | `valid`, `warning_only`, or `invalid` |
| `valid` | `boolean` | Whether the action can proceed |
| `errors` | `string[]` | Blocking errors |
| `warnings` | `string[]` | Non-blocking warnings |
| `opsec_context` | `object` | Effective `max_noise`, remaining budget, defensive signals, recommended approach |
| `recent_outcomes` | `array?` | Recent prior outcomes for the same technique |
| `technique_success_rate` | `object?` | Per-engagement / per-KB success rate |
| `cooldown_suggestion` | `string?` | Hint when the technique has been failing recently |

## Phase-Aware Policy (P4.1)

When the engagement has phases declared and one is currently active, the validator reads the **effective** OPSEC + approval config:

- `opsec_overrides` on the active phase merges over engagement-level OPSEC (only specified fields override).
- `approval_overrides.blacklisted_techniques` **extends** the engagement-level blacklist — phases can tighten safety, never weaken it.

See [Configuration → Phase-Aware Policy](../configuration.md#phase-aware-policy).

## Implicit Target Extraction (P0.1)

For raw `run_bash`/`run_tool` calls where the caller forgot to populate `target_ip` / `target_node`, the validator sniffs the command for IPv4, IPv6, URL, or hostname tokens — but only when the technique OR the binary is in the target-facing allowlist (e.g. `nmap`, `nxc`, `kerbrute`, `ffuf`). This prevents `nmap 8.8.8.8` from slipping through scope when metadata is omitted, while keeping innocuous commands (e.g. `git clone https://...`) unchecked.

## Max-Noise Ceiling (P0.3)

When `engagement.opsec.enabled === true` and a `noise_estimate` is supplied (or a per-technique default applies), the validator rejects the action if `noise_estimate > opsec_context.noise_budget_remaining`. The error message includes spent / remaining / max.

When OPSEC is disabled, the noise pipeline is fully inert — no ceiling enforcement, no recording.

## Passive OSINT recon (Phase 2B)

Passive OSINT techniques (`crt_sh`, `whois`, `passive_dns`, `subfinder`,
`theharvester`, `amass_passive`, `shodan`, `github_dork`) query **public sources**
and never contact the target, so they carry **0 noise** and are **exempt from the
noise ceiling and the time window** — those constraints exist to limit what the
*target's* defenders observe. The technique **blacklist is still honored** (an
explicit operator veto wins). Light-active OSINT (`dnsx`/`httpx`) does contact
in-scope assets and goes through the normal scope + noise path.

A discovered **subdomain** node is scoped by its name: if its apex domain is in
`scope.domains` (e.g. `api.example.com` under a scoped `example.com`) it is
in-scope; otherwise it's flagged `scope unverified`. Actively probing the IP a
subdomain resolves to still requires that IP to be in a scope CIDR.

## Usage Notes

- Always validate before executing — this is a core safety gate.
- The returned `action_id` should be passed to `log_action_event`, `report_finding`, and `parse_output` to maintain causal linkage.
- An `invalid` result means the action should NOT be executed.
- A `warning_only` result means proceed with caution.
- The `action_id` is **deterministic** for engagements with `engagement_nonce` populated — same inputs (agent_id + timestamp + command + sequence) produce the same id. See [Configuration → Durable Transactions, Deterministic IDs, and Replay](../configuration.md#durable-transactions-deterministic-ids-and-replay).
