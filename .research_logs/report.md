# Engagement Report: GOAD First Run

**Engagement ID:** goad-20260322
**Period:** 2026-03-22 17:47:11Z — 2026-03-22 18:16:37Z
**OPSEC Profile:** pentest (max noise: 0.7)

## Executive Summary

This engagement targeted 5 CIDR range(s) and 3 domain(s). 0 of 1 objective(s) were achieved. The engagement discovered 161 nodes and 236 edges, compromising 5 host(s) and obtaining 0 reusable credential(s).

## Scope

| Type | Values |
|------|--------|
| CIDRs | 10.3.10.10/32, 10.3.10.11/32, 10.3.10.12/32, 10.3.10.22/32, 10.3.10.23/32 |
| Domains | sevenkingdoms.local, north.sevenkingdoms.local, essos.local |
| Exclusions | 10.3.10.99, 10.3.10.254 |

## Objectives

| Objective | Status | Achieved At |
|-----------|--------|-------------|
| Obtain a privileged credential in any GOAD domain | ❌ Pending | — |

## Discovery Summary

### Nodes

| Type | Count |
|------|-------|
| group | 51 |
| service | 31 |
| user | 29 |
| ou | 23 |
| credential | 10 |
| host | 5 |
| share | 5 |
| domain | 3 |
| gpo | 3 |
| objective | 1 |
| **Total** | **161** |

### Edges

| Type | Count |
|------|-------|
| GENERIC_ALL | 39 |
| RUNS | 35 |
| MEMBER_OF_DOMAIN | 33 |
| GENERIC_WRITE | 27 |
| WRITE_OWNER | 27 |
| WRITE_DACL | 27 |
| VALID_ON | 18 |
| OWNS_CRED | 9 |
| ADMIN_TO | 7 |
| MEMBER_OF | 6 |
| RELATED | 5 |
| TRUSTS | 1 |
| DELEGATES_TO | 1 |
| PATH_TO_OBJECTIVE | 1 |
| **Total** | **236** (236 confirmed, 0 inferred) |

## Compromised Assets

### Hosts

- KINGSLANDING
- WINTERFELL
- MEEREEN
- CASTELBLACK
- BRAAVOS

## Retrospective Findings

### Context Improvements

- **incomplete_node:** Incomplete-node exploration produced strong yield and likely benefited from richer host/service context. (low confidence)
- **untested_edge:** untested_edge was underrepresented in the engagement, so conclusions about its yield are weak. (low confidence)
- **inferred_edge:** inferred_edge produced 81% apparent yield across 16 observed follow-ups. (low confidence)
- **parser improvement:** 2 service nodes lack banner, version, or protocol enrichment. Recommendation: Improve service parsing so Claude gets richer service context instead of making decisions from bare open ports. (medium confidence)
- **validation-warning improvement:** 1 history entries indicate failures or access denial, which may mean validation warnings were too weak or too generic. Recommendation: Strengthen validate_action guidance for recurring failure patterns so Claude gets clearer pre-execution context. (low confidence)
- **logging/instrumentation improvement:** Structured activity logging is not strong enough to support high-confidence iterative improvements. Recommendation: Prioritize instrumentation: record action_id, event_type, frontier_type, and explicit result linkage for key actions before relying heavily on retrospective guidance. (high confidence)
- **Logging quality:** weak. Prioritize instrumentation: record action_id, event_type, frontier_type, and explicit result linkage for key actions before relying heavily on retrospective guidance.

### Inference Opportunities

- Auto-infer RUNS from host to service: host→RUNS→service appeared 30 times with no covering inference rule
- Auto-infer RUNS from host to share: host→RUNS→share appeared 5 times with no covering inference rule
- Auto-infer OWNS_CRED from user to credential: user→OWNS_CRED→credential appeared 9 times with no covering inference rule

### Skill Gaps

- Failed techniques observed: password

### Trace Quality

- Trace quality is **good**.
- History contains no explicit frontier_type fields, which weakens causal analysis.

## Activity Timeline

| Time | Event |
|------|-------|
| 2026-03-22 17:32:36Z | New edge: bh-group-northsevenkingdomslocal-s-1-5-32-544 --[GENERIC_WRITE]--> bh-group-s-1-5-21-3097139407-3967030816-712095522-513 [bloodhound-ingest] |
| 2026-03-22 17:32:36Z | New edge: bh-group-northsevenkingdomslocal-s-1-5-32-544 --[WRITE_OWNER]--> bh-group-s-1-5-21-3097139407-3967030816-712095522-513 [bloodhound-ingest] |
| 2026-03-22 17:32:36Z | New edge: bh-group-northsevenkingdomslocal-s-1-5-32-544 --[WRITE_DACL]--> bh-group-s-1-5-21-3097139407-3967030816-712095522-513 [bloodhound-ingest] |
| 2026-03-22 17:32:36Z | New ou discovered: DOMAIN CONTROLLERS@NORTH.SEVENKINGDOMS.LOCAL [bloodhound-ingest] |
| 2026-03-22 17:32:36Z | New edge: bh-group-s-1-5-21-3097139407-3967030816-712095522-512 --[GENERIC_ALL]--> bh-ou-a2b1f5a7-479f-40ff-8592-1098a4dd8420 [bloodhound-ingest] |
| 2026-03-22 17:32:36Z | New edge: bh-group-s-1-5-21-3097139407-3967030816-712095522-512 --[GENERIC_WRITE]--> bh-ou-a2b1f5a7-479f-40ff-8592-1098a4dd8420 [bloodhound-ingest] |
| 2026-03-22 17:32:36Z | New edge: bh-group-s-1-5-21-3097139407-3967030816-712095522-512 --[WRITE_OWNER]--> bh-ou-a2b1f5a7-479f-40ff-8592-1098a4dd8420 [bloodhound-ingest] |
| 2026-03-22 17:32:36Z | New edge: bh-group-s-1-5-21-3097139407-3967030816-712095522-512 --[WRITE_DACL]--> bh-ou-a2b1f5a7-479f-40ff-8592-1098a4dd8420 [bloodhound-ingest] |
| 2026-03-22 17:32:36Z | New edge: bh-group-northsevenkingdomslocal-s-1-5-32-544 --[GENERIC_WRITE]--> bh-ou-a2b1f5a7-479f-40ff-8592-1098a4dd8420 [bloodhound-ingest] |
| 2026-03-22 17:32:36Z | New edge: bh-group-northsevenkingdomslocal-s-1-5-32-544 --[WRITE_OWNER]--> bh-ou-a2b1f5a7-479f-40ff-8592-1098a4dd8420 [bloodhound-ingest] |
| 2026-03-22 17:32:36Z | New edge: bh-group-northsevenkingdomslocal-s-1-5-32-544 --[WRITE_DACL]--> bh-ou-a2b1f5a7-479f-40ff-8592-1098a4dd8420 [bloodhound-ingest] |
| 2026-03-22 17:32:36Z | Finding ingested: 1 new nodes, 7 new edges, 0 inferred edges [bloodhound-ingest] |
| 2026-03-22 17:34:52Z | Finding reported: 1 nodes, 4 edges [primary] |
| 2026-03-22 17:34:52Z | New credential discovered: essos\administrator NTLM [primary] |
| 2026-03-22 17:34:52Z | New edge: user-essos-administrator --[OWNS_CRED]--> cred-essos-admin-hash [primary] |
| 2026-03-22 17:34:52Z | New edge: cred-essos-admin-hash --[VALID_ON]--> domain-essos-local [primary] |
| 2026-03-22 17:34:52Z | New edge: cred-essos-admin-hash --[ADMIN_TO]--> host-10-3-10-12 [primary] |
| 2026-03-22 17:34:52Z | New edge: cred-essos-admin-hash --[ADMIN_TO]--> host-10-3-10-23 [primary] |
| 2026-03-22 17:34:52Z | Finding ingested: 1 new nodes, 4 new edges, 0 inferred edges [primary] |
| 2026-03-22 17:35:33Z | ESC8 NTLM relay: coerce KINGSLANDING auth via PetitPotam, relay to ADCS web enrollment on KINGSLANDING to get a cert as KINGSLANDING$ machine account, then use for DCSync |
| 2026-03-22 17:51:13Z | ESC8 relay from WINTERFELL to SEVENKINGDOMS-CA succeeded in obtaining WINTERFELL$ DC cert. Cross-forest relay to ESSOS-CA blocked by template permissions. Same-host relay to KINGSLANDING blocked. Forest root escalation blocked by PAC validation (golden ticket), same-host relay, and cross-CA trust boundaries. [primary] |
| 2026-03-22 18:03:08Z | Finding reported: 3 nodes, 6 edges [primary] |
| 2026-03-22 18:03:08Z | New credential discovered: sevenkingdoms\administrator NTLM [primary] |
| 2026-03-22 18:03:08Z | New credential discovered: localuser:password (hash reuse) [primary] |
| 2026-03-22 18:03:08Z | New user discovered: localuser@sevenkingdoms.local [primary] |
| 2026-03-22 18:03:08Z | New edge: user-sk-localuser --[OWNS_CRED]--> cred-sk-localuser [primary] |
| 2026-03-22 18:03:08Z | New edge: cred-sk-localuser --[VALID_ON]--> domain-sevenkingdoms-local [primary] |
| 2026-03-22 18:03:08Z | New edge: cred-sk-localuser --[ADMIN_TO]--> host-10-3-10-10 [primary] |
| 2026-03-22 18:03:08Z | New edge: user-sk-administrator --[OWNS_CRED]--> cred-sk-admin-hash [primary] |
| 2026-03-22 18:03:08Z | New edge: cred-sk-admin-hash --[VALID_ON]--> domain-sevenkingdoms-local [primary] |
| 2026-03-22 18:03:08Z | New edge: cred-sk-admin-hash --[ADMIN_TO]--> host-10-3-10-10 [primary] |
| 2026-03-22 18:03:08Z | Finding ingested: 3 new nodes, 6 new edges, 0 inferred edges [primary] |
| 2026-03-22 18:06:55Z | Finding reported: 0 nodes, 14 edges [primary] |
| 2026-03-22 18:06:55Z | New edge: svc-10-3-10-22-445 --[RELATED]--> share-castelblack-all [primary] |
| 2026-03-22 18:06:55Z | New edge: svc-10-3-10-22-445 --[RELATED]--> share-castelblack-public [primary] |
| 2026-03-22 18:06:55Z | New edge: svc-10-3-10-23-445 --[RELATED]--> share-braavos-all [primary] |
| 2026-03-22 18:06:55Z | New edge: svc-10-3-10-23-445 --[RELATED]--> share-braavos-public [primary] |
| 2026-03-22 18:06:55Z | New edge: svc-10-3-10-23-445 --[RELATED]--> share-braavos-certenroll [primary] |
| 2026-03-22 18:06:55Z | New edge: cred-north-arya.stark --[VALID_ON]--> host-10-3-10-11 [primary] |
| 2026-03-22 18:06:55Z | New edge: cred-north-hodor --[VALID_ON]--> host-10-3-10-11 [primary] |
| 2026-03-22 18:06:55Z | New edge: cred-north-brandon.stark --[VALID_ON]--> host-10-3-10-11 [primary] |
| 2026-03-22 18:06:55Z | New edge: cred-north-jon.snow --[VALID_ON]--> host-10-3-10-11 [primary] |
| 2026-03-22 18:06:55Z | New edge: cred-north-admin-hash --[VALID_ON]--> host-10-3-10-11 [primary] |
| 2026-03-22 18:06:55Z | New edge: cred-essos-missandei --[VALID_ON]--> host-10-3-10-12 [primary] |
| 2026-03-22 18:06:55Z | New edge: cred-essos-admin-hash --[VALID_ON]--> host-10-3-10-12 [primary] |
| 2026-03-22 18:06:55Z | New edge: cred-sk-localuser --[VALID_ON]--> host-10-3-10-10 [primary] |
| 2026-03-22 18:06:55Z | New edge: cred-sk-admin-hash --[VALID_ON]--> host-10-3-10-10 [primary] |
| 2026-03-22 18:06:55Z | Finding ingested: 0 new nodes, 14 new edges, 0 inferred edges [primary] |
| 2026-03-22 18:07:40Z | Resumed engagement from persisted state |
| 2026-03-22 18:16:37Z | Resumed engagement from persisted state |

## Recommendations

- **1 objective(s) not achieved** — Obtain a privileged credential in any GOAD domain.
- **Remediate access on 5 compromised host(s)** — reset credentials, revoke sessions, review logs.

---
*Generated by Overwatch at 2026-03-22T18:21:28.551Z*
