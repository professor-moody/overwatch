# report_finding

Submit discoveries to the engagement graph.

**Read-only:** No

## Description

This is how new information enters the graph. Submit nodes (hosts, services, credentials, users, etc.) and edges (relationships between them). The orchestrator will:

1. Add/update nodes and edges in the graph
2. Run inference rules to generate new hypothetical edges
3. Re-evaluate objectives
4. Persist state to disk

Always report findings as they occur — do not batch them. Interim reporting enables reactive re-planning by the primary session.

!!! tip "When to use `parse_output` instead"
    If your finding comes from a supported tool (nmap, nxc, certipy, etc.), use [`parse_output`](parse-output.md) instead. It handles structured parsing deterministically and reduces LLM token cost.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent_id` | `string` | Yes | ID of the reporting agent |
| `action_id` | `string` | No | Stable action ID linking to a validated action |
| `tool_name` | `string` | No | Tool that produced this finding |
| `target_node_ids` | `string[]` | No | Primary graph node IDs this finding came from |
| `frontier_item_id` | `string` | No | Frontier item this finding came from |
| `nodes` | `array` | No | Nodes to add/update |
| `edges` | `array` | No | Edges to add/update |
| `evidence` | `object` | No | Supporting evidence |
| `raw_output` | `string` | No | Raw command/tool output for logging |

### Node Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | `string` | Yes | Unique node ID (e.g., `host-10-10-10-5`) |
| `type` | `NodeType` | Yes | `host`, `service`, `credential`, etc. |
| `label` | `string` | Yes | Human-readable label |
| `properties` | `object` | No | Additional properties as key-value pairs |

### Edge Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source` | `string` | Yes | Source node ID |
| `target` | `string` | Yes | Target node ID |
| `type` | `EdgeType` | Yes | `RUNS`, `VALID_ON`, `ADMIN_TO`, etc. |
| `confidence` | `number` | No | 0.0–1.0 (default: 1.0) |
| `properties` | `object` | No | Additional properties |

### Evidence Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | `string` | Yes | `screenshot`, `log`, `file`, or `command_output` |
| `content` | `string` | Yes | Evidence content |
| `filename` | `string` | No | Associated filename |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `action_id` | `string` | Action ID |
| `finding_id` | `string` | Unique finding identifier |
| `new_nodes` | `string[]` | IDs of newly created nodes |
| `new_edges` | `string[]` | IDs of newly created edges |
| `inferred_edges` | `string[]` | IDs of edges created by inference rules |
| `message` | `string` | Summary |

## Usage Notes

- Node IDs should follow conventions: `host-<ip>`, `svc-<ip>-<port>`, `user-<domain>-<name>`, `cred-<type>-<user>`
- Duplicate node IDs update existing nodes (properties are merged)
- Inference rules fire automatically on new nodes — check the `inferred_edges` in the response
- Always include `action_id` from `validate_action` for traceability
