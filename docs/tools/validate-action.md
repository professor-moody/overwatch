# validate_action

Pre-execution sanity check against graph state and OPSEC policy.

**Read-only:** No (logs validation event)

## Description

Validate a proposed action before executing it. Checks:

- Do referenced nodes actually exist in the graph?
- Is the target in scope (not excluded)?
- Is the technique blacklisted by OPSEC profile?
- Is the action within the approved time window?

Call this before every significant action. Returns valid/invalid with specific errors and warnings, plus a stable `action_id` for correlating with subsequent execution and findings.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `description` | `string` | Yes | Human-readable description of the planned action |
| `target_node` | `string` | No | Node ID being targeted |
| `edge_source` | `string` | No | Source node of the edge being tested |
| `edge_target` | `string` | No | Target node of the edge being tested |
| `technique` | `string` | No | Technique name (e.g., `kerberoast`, `ntlmrelay`, `portscan`) |
| `action_id` | `string` | No | Stable action ID to reuse (auto-generated if omitted) |
| `tool_name` | `string` | No | Tool expected to be used |
| `frontier_item_id` | `string` | No | Frontier item this action came from |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `action_id` | `string` | Stable ID for this action |
| `action` | `string` | The description provided |
| `validation_result` | `string` | `valid`, `warning_only`, or `invalid` |
| `valid` | `boolean` | Whether the action can proceed |
| `errors` | `string[]` | Blocking errors |
| `warnings` | `string[]` | Non-blocking warnings |

## Usage Notes

- Always validate before executing — this is a core safety gate
- The returned `action_id` should be passed to `log_action_event`, `report_finding`, and `parse_output` to maintain causal linkage
- An `invalid` result means the action should NOT be executed
- A `warning_only` result means proceed with caution
