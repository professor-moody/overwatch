# suggest_inference_rule

Propose a new inference rule to add to the engagement's active rule set.

**Read-only:** No

## Description

Inference rules fire automatically when matching nodes are ingested or updated. They produce new edges (hypotheses) that expand the attack graph.

Example: "If a host has port 3389 open, create a `CAN_RDPINTO` edge from all users with valid credentials."

The rule will be validated for correct node/edge types and selectors. Optionally backfill against all existing matching nodes immediately.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | `string` | Yes | Human-readable name for the rule |
| `description` | `string` | Yes | What this rule detects and why it matters |
| `trigger_node_type` | `NodeType` | Yes | Node type that triggers this rule |
| `trigger_properties` | `object` | No | Property values the trigger node must match |
| `produces` | `array` | Yes | Edges this rule produces when triggered |
| `backfill` | `boolean` | No | Run against all existing matching nodes immediately (default: `false`) |

### Produces Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `edge_type` | `EdgeType` | Yes | Type of edge to create |
| `source_selector` | `string` | Yes | How to resolve the source node |
| `target_selector` | `string` | Yes | How to resolve the target node |
| `confidence` | `number` | No | Confidence of the inferred edge (default: 0.7) |

### Valid Selectors

| Selector | Resolves To |
|----------|-------------|
| `trigger_node` | The node that matched the trigger |
| `trigger_service` | Same as `trigger_node` |
| `parent_host` | Host running the triggering service |
| `domain_nodes` | All domain nodes |
| `domain_users` | All domain user nodes |
| `domain_credentials` | All credential nodes |
| `all_compromised` | Hosts with confirmed access |
| `compatible_services` | Services accepting the credential type |
| `enrollable_users` | All user nodes (for ADCS rules) |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | `string` | Auto-generated rule ID |
| `name` | `string` | Rule name |
| `added` | `boolean` | Confirmation |
| `backfill` | `object` | Number of inferred edges (if `backfill: true`) |
| `message` | `string` | Summary |

## Example

```json
{
  "name": "RDP Access from Domain Users",
  "description": "If a host has RDP open, domain users with valid credentials may RDP in",
  "trigger_node_type": "service",
  "trigger_properties": { "service_name": "rdp" },
  "produces": [{
    "edge_type": "CAN_RDPINTO",
    "source_selector": "domain_users",
    "target_selector": "parent_host",
    "confidence": 0.5
  }],
  "backfill": true
}
```

## Usage Notes

- Rules persist for the engagement session — they fire on all future findings
- Set `backfill: true` to immediately apply the rule to existing graph data
- Invalid selectors return an error with the list of valid selectors
- Use this when you notice a pattern the built-in rules don't cover
