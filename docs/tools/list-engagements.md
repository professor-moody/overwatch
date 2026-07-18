# list_engagements

List the persisted engagement configs and which one is currently active.

## When to use

- After [`create_engagement`](create-engagement.md), to confirm the inactive
  config landed while the daemon remains on its current engagement.
- To see what engagements exist on disk (`engagements/*.json`).

## Parameters

None.

## Returns

```json
{
  "active_id": "internal-pentest-abc123",
  "engagements": [
    { "id": "...", "name": "...", "scope_cidrs": [...], "scope_domains": [...],
      "objectives_count": 3, "config_path": "...", "is_active": true }
  ]
}
```

Read-only — lists summaries only. It does not switch the active engagement, and
the dashboard does not currently provide engagement switching.
