# Engagement Report: GOAD First Run

**Engagement ID:** goad-20260323
**Period:** 2026-03-24 12:57:55Z — 2026-03-24 14:59:22Z
**OPSEC Profile:** pentest (max noise: 0.7)

## Executive Summary

This engagement targeted 5 CIDR range(s) and 3 domain(s). 1 of 1 objective(s) were achieved. The engagement discovered 151 nodes and 1590 edges, compromising 2 host(s) and obtaining 39 reusable credential(s).

## Scope

| Type | Values |
|------|--------|
| CIDRs | 10.3.10.10/32, 10.3.10.11/32, 10.3.10.12/32, 10.3.10.22/32, 10.3.10.23/32 |
| Domains | sevenkingdoms.local, north.sevenkingdoms.local, essos.local |
| Exclusions | 10.3.10.99, 10.3.10.254 |

## Objectives

| Objective | Status | Achieved At |
|-----------|--------|-------------|
| Obtain a privileged credential in any GOAD domain | ✅ Achieved | 2026-03-24 12:38:11Z |

## Discovery Summary

### Nodes

| Type | Count |
|------|-------|
| service | 59 |
| user | 43 |
| credential | 40 |
| host | 5 |
| domain | 3 |
| objective | 1 |
| **Total** | **151** |

### Edges

| Type | Count |
|------|-------|
| POTENTIAL_AUTH | 1470 |
| RUNS | 59 |
| OWNS_CRED | 40 |
| MEMBER_OF_DOMAIN | 18 |
| ADMIN_TO | 2 |
| CAN_DELEGATE_TO | 1 |
| **Total** | **1590** (116 confirmed, 1474 inferred) |

## Compromised Assets

### Hosts

- 10.3.10.11
- castelblack.north.sevenkingdoms.local

### Credentials

- plaintext_password: jon.snow
- ntlm_hash: Administrator
- ntlm_hash: Guest
- ntlm_hash: krbtgt
- ntlm_hash: localuser
- ntlm_hash: arya.stark
- ntlm_hash: eddard.stark
- ntlm_hash: catelyn.stark
- ntlm_hash: robb.stark
- ntlm_hash: sansa.stark
- ntlm_hash: brandon.stark
- ntlm_hash: rickon.stark
- ntlm_hash: hodor
- ntlm_hash: jon.snow
- ntlm_hash: samwell.tarly
- ntlm_hash: jeor.mormont
- ntlm_hash: sql_svc
- ntlm_hash: Administrator
- ntlm_hash: krbtgt
- ntlm_hash: tywin.lannister
- ntlm_hash: jaime.lannister
- ntlm_hash: cersei.lannister
- ntlm_hash: tyron.lannister
- ntlm_hash: robert.baratheon
- ntlm_hash: joffrey.baratheon
- ntlm_hash: renly.baratheon
- ntlm_hash: stannis.baratheon
- ntlm_hash: petyer.baelish
- ntlm_hash: lord.varys
- ntlm_hash: maester.pycelle
- ntlm_hash: Administrator
- ntlm_hash: krbtgt
- ntlm_hash: DefaultAccount
- ntlm_hash: daenerys.targaryen
- ntlm_hash: viserys.targaryen
- ntlm_hash: khal.drogo
- ntlm_hash: jorah.mormont
- ntlm_hash: missandei
- ntlm_hash: drogon

## Retrospective Findings

### Context Improvements

- **incomplete_node:** Incomplete-node exploration produced strong yield and likely benefited from richer host/service context. (low confidence)
- **untested_edge:** untested_edge produced 100% apparent yield across 1469 observed follow-ups. (low confidence)
- **inferred_edge:** inferred_edge produced 95% apparent yield across 19 observed follow-ups. (low confidence)
- **parser improvement:** 5 live host nodes still lack operating-system enrichment. Recommendation: Improve parser or manual enrichment coverage so hosts carry OS context before follow-on reasoning. (medium confidence)
- **skill-library improvement:** Techniques were attempted without matching skill coverage: netexec. Recommendation: Add or improve skills for the techniques repeatedly attempted during the engagement. (medium confidence)
- **validation-warning improvement:** 6 history entries indicate failures or access denial, which may mean validation warnings were too weak or too generic. Recommendation: Strengthen validate_action guidance for recurring failure patterns so Claude gets clearer pre-execution context. (low confidence)
- **Logging quality:** weak. Prioritize instrumentation: record action_id, event_type, frontier_type, and explicit result linkage for key actions before relying heavily on retrospective guidance.

### Inference Opportunities

- Auto-infer RUNS from host to service: host→RUNS→service appeared 59 times with no covering inference rule
- Auto-infer OWNS_CRED from user to credential: user→OWNS_CRED→credential appeared 40 times with no covering inference rule
- Review low-performing rule: rule-kerberos-domain: 0/9 inferred edges confirmed for rule rule-kerberos-domain

### Skill Gaps

- Missing coverage: netexec
- Failed techniques observed: bloodhound, users, password, spray, ntlm

### Trace Quality

- Trace quality is **mixed**.
- 1/1766 traces rely mostly on text heuristics rather than structured action/result linkage.
- History contains no explicit frontier_type fields, which weakens causal analysis.

## Activity Timeline

| Time | Event |
|------|-------|
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-missandei-fd2c9404b6b8 --[POTENTIAL_AUTH]--> svc-10-3-10-22-445 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-missandei-fd2c9404b6b8 --[POTENTIAL_AUTH]--> svc-10-3-10-22-1433 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-missandei-fd2c9404b6b8 --[POTENTIAL_AUTH]--> svc-10-3-10-22-3389 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-missandei-fd2c9404b6b8 --[POTENTIAL_AUTH]--> svc-10-3-10-22-5985 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-missandei-fd2c9404b6b8 --[POTENTIAL_AUTH]--> svc-10-3-10-23-80 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-missandei-fd2c9404b6b8 --[POTENTIAL_AUTH]--> svc-10-3-10-23-139 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-missandei-fd2c9404b6b8 --[POTENTIAL_AUTH]--> svc-10-3-10-23-445 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-missandei-fd2c9404b6b8 --[POTENTIAL_AUTH]--> svc-10-3-10-23-1433 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-missandei-fd2c9404b6b8 --[POTENTIAL_AUTH]--> svc-10-3-10-23-3389 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-missandei-fd2c9404b6b8 --[POTENTIAL_AUTH]--> svc-10-3-10-23-5985 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-10-80 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-10-139 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-10-389 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-10-445 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-10-636 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-10-3268 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-10-3269 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-10-3389 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-10-5985 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-11-139 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-11-389 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-11-445 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-11-636 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-11-3268 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-11-3269 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-11-3389 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-11-5985 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-12-139 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-12-389 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-12-445 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-12-636 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-12-3268 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-12-3269 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-12-3389 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-12-5985 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-22-80 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-22-139 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-22-445 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-22-1433 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-22-3389 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-22-5985 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-23-80 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-23-139 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-23-445 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-23-1433 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-23-3389 |
| 2026-03-24 14:59:21Z | Inferred edge [New credential tests against compatible services]: cred-ntlm-hash-drogon-40bc60467425 --[POTENTIAL_AUTH]--> svc-10-3-10-23-5985 |
| 2026-03-24 14:59:21Z | Finding ingested: 16 new nodes, 9 new edges, 333 inferred edges [secretsdump-parser] |
| 2026-03-24 14:59:21Z | Output parsed and ingested for secretsdump [secretsdump-parser] |
| 2026-03-24 14:59:22Z | essos.local NTDS dumped via localuser PTH on MEEREEN. All 3 GOAD domains fully compromised. |

## Recommendations

- **1474 inferred edge(s) remain untested** — these represent potential attack paths that were not validated during the engagement.
- **Remediate access on 2 compromised host(s)** — reset credentials, revoke sessions, review logs.
- **Rotate 39 discovered credential(s)** immediately.

---
*Generated by Overwatch at 2026-03-24T15:00:33.200Z*
