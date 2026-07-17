# get_state

Operational engagement briefing synthesized from durable state. This is the
primary context-recovery call after model compaction or handoff; it is not a
lossless state-file or artifact export.

**Read-only:** Yes

## Description

Returns a bounded, operator-oriented view of the current engagement. Use this as
your first call in any new or compacted model session to understand:

- What targets are in scope
- What has been discovered (nodes and edges)
- What credentials and access you have
- What objectives remain
- What frontier items (next actions) are available
- What agents are currently running

The frontier items are pre-filtered by the deterministic layer (scope, dedup, hard OPSEC vetoes) but NOT scored — that is the LLM's job.

The briefing deliberately does not embed the entire activity history, raw
evidence bytes, report/tape/bundle contents, every graph property, or ephemeral
runtime handles such as PTYs, sockets, process objects, database connections,
terminal buffers, and WebSocket clients. Durable process and session
descriptors are available through their dedicated inventory/recovery surfaces;
they are never presented as proof that a live handle survived restart.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `include_full_frontier` | `boolean` | `true` | Include all frontier items. Set `false` for summary only (first 10). |
| `activity_count` | `integer` | `20` | Number of recent activity entries to include (1–100). |
| `include_reasoning` | `boolean` | `false` | Include `event_type=thought` / `category=reasoning` entries in `recent_activity`. |
| `include_system` | `boolean` | `true` | Include `category=system` entries in `recent_activity`. |
| `snapshot` | `boolean` | `false` | Persist a copy of this returned briefing to the evidence store and emit a `system` event so a retrospective can recover exactly this view. **Defaults to `false`** so the tool is genuinely read-only. De-duplicated within a 5s window when the briefing body is unchanged. |
| `since` | `string` | — | ISO timestamp of your last `get_state` call. When set, the response adds a `changes_since` summary — new findings + which sub-agents completed since then + a recommendation — so a dispatching primary sees at a glance whether to re-synthesize without scanning `recent_activity`. Unparseable values are ignored. |
| `compact` | `boolean` | `false` | Return compact JSON (no indentation) to save tokens. Identical payload — only whitespace differs. The evidence snapshot stays pretty-printed. |

## Returns

An `EngagementState` briefing object containing:

| Field | Type | Description |
|-------|------|-------------|
| `config` | `EngagementConfig` | Scope, objectives, OPSEC profile |
| `graph_summary` | `object` | Node/edge counts by type, confirmed vs inferred, community stats, cold store census |
| `objectives` | `EngagementObjective[]` | All objectives with achievement status |
| `frontier` | `FrontierItem[]` | Candidate next actions with graph metrics |
| `active_agents` | `AgentTask[]` | Currently running sub-agents |
| `recent_activity` | `array` | Recent events with timestamps and agent IDs |
| `access_summary` | `object` | Compromised hosts (live sessions only), valid credentials, access level |
| `warnings` | `HealthSummary` | Graph health warnings |
| `lab_readiness` | `LabReadinessSummary` | Inline lab readiness summary (graph health severity, domain hints, stage). For full per-tool readiness, use [`run_lab_preflight`](run-lab-preflight.md). |
| `scope_suggestions` | `string[]` | Suggested scope expansions discovered during the engagement |
| `credential_coverage` | `CredentialCoverage` | Credential spray progress: tested/total pairs, coverage %, top untested combinations |
| `phases` | `array?` | Phase status when phases are declared (id, status, entry/exit met, strategies). Active phase contributes effective OPSEC + approval policy via [`opsec_overrides` / `approval_overrides`](../configuration.md#phase-aware-policy). |
| `current_phase` | `string?` | The currently-active phase id, if any |

### graph_summary community fields

| Field | Type | Description |
|-------|------|-------------|
| `community_count` | `number` | Number of communities detected via Louvain algorithm |
| `largest_community_size` | `number` | Node count in the biggest community |
| `unexplored_community_count` | `number` | Communities with at least one unexplored frontier item |

These are computed lazily from the graph topology and cached until the next topology change.

### graph_summary cold store fields

| Field | Type | Description |
|-------|------|-------------|
| `cold_node_count` | `number` | Number of hosts in the cold store census (alive, IP-only, no services) |
| `cold_nodes_by_subnet` | `Record<string, number>` | Top 5 subnets by cold node count (omitted when 0) |

See [Concepts — Graph Compaction](../concepts.md#graph-compaction-cold-store) for details on hot/cold classification.

## Example

```json
// Request
{ "include_full_frontier": true, "activity_count": 10 }
```

## Usage Notes

- Call this at the **start of every session** and after any context compaction.
- Pass `snapshot: true` at session bootstrap when you want the call to also persist evidence — the default is now read-only (`snapshot: false`) so casual reads do not duplicate engagement state across the evidence store.
- The frontier items have graph metrics attached but are not scored — the LLM should score and prioritize them.
- Use `activity_count` to control how much history is included in the briefing.
- Use [`get_history`](get-history.md) for paginated activity,
  [`get_evidence`](get-evidence.md) for full-fidelity blobs, `query_graph` or
  `export_graph` for graph detail, and `bundle_engagement` for a portable
  engagement archive.
- Use `get_recovery_status`, `list_sessions`, and `check_processes` when startup
  recovery or live runtime ownership matters. A clean briefing is not a
  substitute for those explicit status surfaces.
