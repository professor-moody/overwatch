# create_engagement

Build and persist a new engagement config — conversationally, with no hand-edited
`engagement.json`.

## When to use

- Standing up a new engagement: "set up an engagement scoped to `10.10.10.0/24`,
  objective domain-admin, quiet OPSEC" — the model calls this and writes a
  validated `engagements/<id>.json`.
- Spinning a variant off a template (`ctf`, `internal-pentest`,
  `external-assessment`, `red-team`, `cloud-assessment`, `assumed-breach`).

## Inactive creation

The new engagement is **persisted but not live**. The running server keeps
serving the current engagement. This tool does not switch or reload the daemon,
and the dashboard does not currently provide engagement switching. It does
**not** touch the running engagement, so no confirmation gate is needed; use
`dry_run: true` to preview the built config without writing.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | `string` | **Yes** | Engagement name (also seeds the id) |
| `template` | `string` | No | Template id to base it on |
| `cidrs` | `string[]` | No | In-scope CIDRs, e.g. `["10.10.10.0/24"]` |
| `domains` | `string[]` | No | In-scope domains |
| `exclusions` | `string[]` | No | Out-of-scope CIDRs/IPs |
| `objectives` | `{ description }[]` | No | Engagement goals |
| `opsec_profile` | `quiet \| normal \| pentest \| loud` | No | Noise ceiling: 0.2 / 0.5 / 0.7 (default) / 1.0 |
| `dry_run` | `boolean` | No | Preview the built config without writing it |

## Returns

On write: the engagement summary (including `config_path`) and the existing
additive `activation` metadata, whose status is `not_active`. Treat that block
as status information, not as dashboard switching support. With `dry_run:
true`, the result is `{ dry_run: true, config }` and nothing is written.

## Behavior notes

- The config is built by the shared `buildEngagementConfig` and validated against
  the engagement schema; invalid CIDRs and unknown templates are rejected.
- A fresh `id` (slug + base36) and a 64-hex `engagement_nonce` are minted; the
  file is written to `engagements/<id>.json` and **never overwrites** an existing
  engagement.
- To edit the *active* engagement instead of creating a new one, use
  [`update_scope`](update-scope.md), [`add_objective`](add-objective.md), and
  [`set_opsec`](set-opsec.md).
