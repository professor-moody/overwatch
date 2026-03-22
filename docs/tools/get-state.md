# get_state

Full engagement state briefing from the graph. This is the primary recovery mechanism after context compaction.

**Read-only:** Yes

## Description

Returns the complete current state of the engagement, synthesized from the graph. Use this as your first call in any new or compacted session to understand:

- What targets are in scope
- What has been discovered (nodes and edges)
- What credentials and access you have
- What objectives remain
- What frontier items (next actions) are available
- What agents are currently running

The frontier items are pre-filtered by the deterministic layer (scope, dedup, hard OPSEC vetoes) but NOT scored — that is the LLM's job.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `include_full_frontier` | `boolean` | `true` | Include all frontier items. Set `false` for summary only (first 10). |
| `activity_count` | `integer` | `20` | Number of recent activity entries to include (1–100). |

## Returns

An `EngagementState` object containing:

| Field | Type | Description |
|-------|------|-------------|
| `config` | `EngagementConfig` | Scope, objectives, OPSEC profile |
| `graph_summary` | `object` | Node/edge counts by type, confirmed vs inferred |
| `objectives` | `EngagementObjective[]` | All objectives with achievement status |
| `frontier` | `FrontierItem[]` | Candidate next actions with graph metrics |
| `active_agents` | `AgentTask[]` | Currently running sub-agents |
| `recent_activity` | `array` | Recent events with timestamps and agent IDs |
| `access_summary` | `object` | Compromised hosts, valid credentials, access level |
| `warnings` | `HealthSummary` | Graph health warnings |
| `lab_readiness` | `LabReadinessSummary` | Lab readiness status |

## Example

```json
// Request
{ "include_full_frontier": true, "activity_count": 10 }
```

## Usage Notes

- Call this at the **start of every session** and after any context compaction
- The frontier items have graph metrics attached but are not scored — the LLM should score and prioritize them
- Use `activity_count` to control how much history is included in the briefing
