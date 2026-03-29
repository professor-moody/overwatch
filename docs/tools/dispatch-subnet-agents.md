# dispatch_subnet_agents

Dispatch one sub-agent per scope CIDR for parallel network enumeration.

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `max_agents` | integer | No | `8` | Maximum number of agents to dispatch (1–20) |
| `skill` | string | No | `"subnet-enumeration"` | Skill/methodology to assign to each agent |
| `hops` | integer | No | `2` | Hops for subgraph scope computation (1–5) |

## Behavior

For each CIDR in the engagement scope:

1. Checks if a `network_discovery` frontier item exists for the CIDR
2. Skips fully-discovered CIDRs (no frontier item)
3. Skips CIDRs that already have a running agent
4. Registers a sub-agent with:
   - Agent ID: `agent-subnet-<cidr-slug>-<uuid>`
   - Frontier item: the `network_discovery` item for that CIDR
   - Subgraph: already-discovered host nodes in the CIDR
   - Skill: the specified methodology (default `subnet-enumeration`)

Dispatches up to `max_agents` agents total.

## Response

```json
{
  "requested": 8,
  "total_cidrs": 3,
  "dispatched": [
    {
      "task_id": "uuid",
      "agent_id": "agent-subnet-10-10-10-0-24-abc12345",
      "cidr": "10.10.10.0/24",
      "existing_nodes": 5,
      "skill": "subnet-enumeration"
    }
  ],
  "skipped": [
    { "cidr": "192.168.1.0/24", "reason": "fully_discovered" },
    { "cidr": "172.16.0.0/16", "reason": "running_agent: agent-subnet-172-16-0-0-16-def456" }
  ]
}
```

## Example

```
dispatch_subnet_agents({ max_agents: 4 })
```

Dispatches up to 4 sub-agents, one per scope CIDR, each running the `subnet-enumeration` skill.

## Integration with Cold Store

Hosts discovered by subnet agents that respond to ping but have no open services are stored in the **cold store** rather than the hot graph. This keeps the active graph focused on actionable targets. If a later scan reveals services on a cold host, it is automatically promoted to the hot graph.

## See Also

- [`register_agent`](register-agent.md) — manual single-agent dispatch
- [`get_agent_context`](get-agent-context.md) — agent subgraph retrieval
- [`update_agent`](update-agent.md) — mark agent complete/failed
- [Subnet Enumeration skill](../../skills/subnet-enumeration.md) — default methodology
