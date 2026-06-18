# get_opsec_status

Read-only view of the engagement's OPSEC posture. Backs the **opsec_sentinel**
archetype and is available to any operator/agent that needs to weigh noise
before acting.

## What it returns

- **enforcement** — `{ enabled, configured_fields, inert }` (whether OPSEC gating
  is on, what's configured, and whether it's configured-but-disabled).
- **global_noise_spent** — cumulative noise across the engagement.
- **context** — the scoped OPSEC context: noise spent, budget remaining, the
  `recommended_approach` (quiet / normal / loud), and *recent* defensive signals.
  Scope to a host or domain with the optional parameters.
- **all_defensive_signals** — the full history of observed defender reactions
  (lockouts, rate limits, honeypots, connection resets, blocks) with host/domain
  attribution. (`context.defensive_signals` is the recent + scoped subset.)

## Parameters

| Param | Type | Notes |
|-------|------|-------|
| `host_id` | string? | Scope the noise estimate + recommendation to a host node |
| `domain` | string? | Scope the noise estimate + recommendation to a domain |

## Notes

`readOnlyHint: true` — never mutates state. It reads the live `OpsecTracker`, so
the numbers reflect actions recorded so far this engagement.
