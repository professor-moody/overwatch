# Evidence Auditing

tags: evidence, findings, readiness, proof, audit, client-ready, gaps, validation, get_finding_readiness, read-only

## Objective
Read-only audit: assess each finding's proof readiness and surface the gaps before
the engagement is reported. You confirm that confirmed findings actually have the
evidence to back them — you never execute against targets or mutate the graph.

## Tools
- `get_finding_readiness` — the per-finding readiness rollup
  (client_ready / needs_validation / draft) plus the concrete gaps.
- `get_evidence` — the proof chain behind a finding (command output, parsed artifacts).
- `query_graph` — the nodes/edges the finding asserts.
- `explain_action` — how the action that produced the finding was reached/validated.

## Readiness taxonomy
- **client_ready** — finding has reproducible evidence + a clear asset + severity; safe
  to put in a client report. Verify, don't assume.
- **needs_validation** — the claim is plausible but the proof is thin (inferred edge,
  no captured output, single weak signal). Name exactly what's missing.
- **draft** — asserted but largely unproven; treat as a lead, not a finding.

## Methodology

### 1. Pull the rollup
Start with `get_finding_readiness` — it buckets every finding by state and lists the
gaps. This is your worklist.

### 2. Drill into each non-ready finding
For `needs_validation` / `draft`, open `get_evidence` + `explain_action`:
- Is there captured output (not just a prose claim)?
- Does the evidence actually show what the finding asserts?
- Is the underlying edge confirmed or inferred?

### 3. Classify the gap precisely
For each gap, say what would close it: "no captured stdout — re-run with evidence
capture", "edge is inferred — needs a validate_action", "credential never replayed —
validate_token_credential". A precise gap is actionable; "needs more proof" is not.

### 4. Report the rollup
Produce: counts per state, the client_ready set (confirmed), and for each gap a
finding-id + the one concrete step to close it. Prioritize gaps on high-severity
findings (those gate the report's headline claims).

## Escalation / done
- **Flag for the operator** when a high-severity / objective-completing finding is only
  `draft` — that's a headline claim with no proof, the riskiest gap.
- **Done** when each finding's proof readiness is assessed and the gaps (with the
  concrete step to close each) are reported.

## Anti-patterns
- Marking a finding ready without opening its evidence.
- Vague gaps ("needs validation") instead of the specific missing artifact + step.
- Running tools to "generate" the missing evidence — you audit; the operator dispatches
  the validation.
