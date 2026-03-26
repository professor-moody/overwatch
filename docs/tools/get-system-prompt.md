# get_system_prompt

Generate a dynamic system prompt for an MCP consumer based on the current engagement state.

## Purpose

Returns a markdown system prompt tailored to the specified role, including engagement briefing, tool reference table, state snapshot, and OPSEC constraints. Use this instead of static `AGENTS.md` instructions for session initialization and agent dispatch.

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `role` | `'primary' \| 'sub_agent'` | Yes | — | Consumer role: primary orchestrator or scoped sub-agent |
| `agent_id` | `string` | No | — | For sub_agent role: the agent ID to scope the instructions |
| `include_state` | `boolean` | No | `true` | Include current state snapshot in the prompt |
| `include_tools` | `boolean` | No | `true` | Include tool reference table in the prompt |

## Roles

### `primary`

Full orchestrator instructions including:
- Engagement briefing (name, scope, objectives, OPSEC profile)
- Core loop workflow (get_state → next_task → validate → execute → report)
- Key principles
- Complete tool reference table
- Current state snapshot (graph summary, access level, frontier size)

### `sub_agent`

Scoped worker instructions including:
- Engagement name and agent context
- Scoped tool subset (get_agent_context, validate_action, report_finding, etc.)
- Step-by-step workflow
- Agent-specific context (frontier item, scoped nodes, skill)

## Example

```json
{
  "role": "primary",
  "include_state": true,
  "include_tools": true
}
```

## Returns

A single text content block containing the generated markdown system prompt.

## Annotations

- **Read-only:** Yes
- **Idempotent:** Yes
