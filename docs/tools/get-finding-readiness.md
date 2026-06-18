# get_finding_readiness

Read-only proof-readiness audit over the engagement's findings. Backs the
**evidence_auditor** archetype: before anything is written into a client report,
it answers "which findings are actually backed by proof, and which still need
work?" The findings are derived from the same builder + classifier the report
itself uses, so the audit matches what would ship.

## What it returns

A `summary` rollup plus a per-finding `findings` array. Each finding is labelled
with one of three readiness states:

- **client_ready** — backed by captured evidence (an evidence chain citing
  evidence-store bytes / raw output) or a proof card. Safe to report as-is.
- **needs_validation** — a claim with an evidence chain or affected assets, but
  no *captured* evidence yet. Re-run/parse the proving action before reporting.
- **draft** — thin: no captured evidence, no chains, no affected assets.

Each finding also carries the raw signals (`evidence_chains`, `proof_cards`,
`captured_evidence`, `classified`, `affected_assets`) and a `gaps` list of the
concrete things to close (e.g. "no captured evidence — run/parse the action that
proves this finding", "unclassified — no CWE/OWASP/ATT&CK mapping").

## Parameters

| Param | Type | Notes |
|-------|------|-------|
| `finding_id` | string? | Audit a single finding by id (default: all findings) |

## Notes

`readOnlyHint: true` — never mutates state. The readiness label is a heuristic
over captured evidence + classification, not a verdict: it surfaces the signals
and gaps for the operator (or evidence_auditor) to judge, then drill in with
[`get_evidence`](get-evidence.md) / [`query_graph`](query-graph.md).
