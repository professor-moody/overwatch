# manage_campaign

Control campaign lifecycle: activate, pause, resume, abort, or get status.

**Read-only:** No

## Description

Campaigns are auto-generated groups of related frontier items that share a common strategy. Use `next_task(group_by="campaign")` to see available campaigns, then use this tool to manage their lifecycle.

Campaign strategies:

- **credential_spray** — one credential tested against multiple services
- **enumeration** — batch of incomplete nodes needing the same enrichment
- **post_exploitation** — follow-up actions on a compromised host
- **network_discovery** — host discovery in a scope CIDR

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `campaign_id` | `string` | Yes | Campaign ID to manage |
| `action` | `string` | Yes | Lifecycle action: `activate`, `pause`, `resume`, `abort`, `status`, or `check_abort` |

## Returns

| Field | Type | Description |
|-------|------|-------------|
| `campaign` | `object` | The campaign object with current state |
| `abort_conditions` | `object` | Present when `action` is `check_abort` — lists conditions that would trigger an abort |

## Usage Notes

- Use `status` to inspect a campaign before acting on it
- `activate` moves a draft campaign into the running state — required before dispatching agents with `dispatch_campaign_agents`
- `pause` temporarily halts a running campaign; `resume` continues it
- `abort` permanently cancels a campaign and all associated work
- `check_abort` evaluates whether the campaign should be aborted (e.g., all items failed, objective already achieved) without actually aborting it
- Campaigns transition through states: `draft` → `active` → `paused` | `completed` | `aborted`
