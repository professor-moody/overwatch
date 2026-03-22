# update_agent

Update the status of a running agent task.

**Read-only:** No

## Description

Call when an agent completes or fails its task. This updates the agent's status in the engagement state and is visible in `get_state`.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `task_id` | `string` | Yes | Task ID to update |
| `status` | `string` | Yes | `completed` or `failed` |
| `summary` | `string` | No | Brief summary of results or failure reason |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `task_id` | `string` | Task identifier |
| `status` | `string` | Updated status |
| `summary` | `string` | Summary provided |
| `updated` | `boolean` | Confirmation |

## Usage Notes

- Always call this when an agent finishes — open tasks show as active in `get_state`
- Include a meaningful `summary` — it appears in the engagement history and retrospective analysis
- Failed tasks should include the failure reason in `summary`
