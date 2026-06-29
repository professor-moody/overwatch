# list_engagements

List the persisted engagement configs and which one is currently active.

## When to use

- After [`create_engagement`](create-engagement.md), to confirm the new config
  landed and to see whether it's active yet (it won't be until the server is
  restarted pointed at it — create-then-start).
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

Read-only — lists summaries only; it does not switch the active engagement
(activation is a server restart pointed at the chosen config).
