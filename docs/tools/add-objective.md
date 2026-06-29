# add_objective

Add an objective (goal) to the **active** engagement — no hand-edited config.

## When to use

- A new goal emerges mid-engagement ("also prove access to the backup server")
  and you want it tracked + factored into objective progress without editing
  `engagement.json`.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `description` | `string` | **Yes** | What achieving this objective means |
| `target_node_type` | `string` | No | Node type that satisfies it (e.g. `credential`, `host`) |
| `target_criteria` | `object` | No | Property match for the target node, e.g. `{"privileged": true}` |
| `achievement_edge_types` | `string[]` | No | Edge types that count as achieved (default: `HAS_SESSION` / `ADMIN_TO` / `OWNS_CRED`) |

## Returns

`{ added: true, objective }` — the created objective (with its generated id). The
change persists immediately.

## Behavior notes

- **Low-risk:** declares a goal; it authorizes no targets and changes neither
  scope nor OPSEC, so there is no confirmation gate.
- Mutates the active engagement (same path as the dashboard's add-objective
  endpoint). To create a brand-new engagement instead, use
  [`create_engagement`](create-engagement.md).
