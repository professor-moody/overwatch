# research_cve

Record the outcome of operator-style CVE/exploit research for a versioned service.

**Read-only:** No (ingests candidate vulnerability nodes/edges and stamps the service)

## Description

The web search + judgment is the **agent's** job — a headless [`research`-role](../operator-cockpit.md#roles) sub-agent with `WebSearch`/`WebFetch` finds CVEs and public POCs for a service's product+version and judges which actually apply. `research_cve` **records** the structured outcome: applicable candidates become `vulnerability` nodes + `VULNERABLE_TO` edges (marked `tested: false` — candidates for the primary to verify/exploit), and the service is **always** stamped `cve_checked_at` so the `cve_research` frontier item stops regenerating (even when nothing was found).

Call it **once** per service with all credible candidates (or an empty list).

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `service_id` | `string` | yes | The service node id that was researched |
| `summary` | `string` | yes | One-line summary of what the research found |
| `candidates` | `CveCandidate[]` | yes (may be empty) | Researched candidates; only `applicable: true` ones become edges |
| `agent_id` | `string` | no | Your agent id (attribution) |

Each `CveCandidate`: `{ cve?, title, cvss?, vuln_type?, exploit_available?, poc_url?, applicable, confidence?, notes? }`.

## Returns

```json
{ "ok": true, "service_id": "svc-1", "cve_checked_at": "2026-05-15T...", "candidates_recorded": 1,
  "new_nodes": ["vuln-..."], "new_edges": ["..."] }
```

Returns `isError: true` if the service node isn't found or ingestion validation fails.

## Side Effects

- Ingests applicable candidates as `vulnerability` nodes + `VULNERABLE_TO(tested:false)` edges.
- Stamps `cve_checked_at` + `cve_check_summary` on the service and invalidates the frontier cache so the `cve_research` item retires.
- Emits an activity event recording the candidate counts.

## See Also

- [Operator Cockpit → roles](../operator-cockpit.md#roles) — the headless `research` role.
- [`report_finding`](report-finding.md) — the general discovery-ingestion path.
