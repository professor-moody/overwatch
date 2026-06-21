# generate_report

Generate a comprehensive penetration test report from the engagement graph and activity history.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `format` | `"markdown"` \| `"html"` | `"markdown"` | Output format |
| `include_evidence` | boolean | `true` | Include evidence chains for each finding |
| `include_narrative` | boolean | `true` | Include attack narrative section |
| `include_retrospective` | boolean | `false` | Include retrospective analysis (inference gaps, skill gaps) |
| `write_to_disk` | boolean | `false` | Save report file(s) to `output_dir` |
| `output_dir` | string | `"./reports/"` | Directory for output files |
| `theme` | `"light"` \| `"dark"` | `"light"` | Theme for HTML output |
| `client_safe` | boolean | `false` | **Phase I**: produce a client-deliverable variant. Strips `cred_value`, `raw_output`, stdout/stderr previews, and operator-machine paths. Disk artifacts get a `.client-safe.<ext>` suffix. See [Client-safe exports](#client-safe-exports). |
| `profile` | `"operator"` \| `"client"` | inferred | Report profile. `operator` keeps full internal proof metadata; `client` produces a polished client-safe deliverable. `client_safe: true` maps to `client`. |
| `evidence_style` | `"proof_cards"` \| `"appendix"` \| `"full_inline"` | `"proof_cards"` | Evidence presentation style. Proof cards are the default; appendix mode keeps findings concise; full inline is intended for operator binders. |

## Output

Returns a JSON summary with:

- `format` — the format used
- `findings_count` — total findings generated
- `severity_summary` — breakdown by severity (critical, high, medium, low, info)
- `report_preview` — first 800 characters of the report
- `report_length` — total character count
- `output_dir` — path where files were written (when `write_to_disk` is true)

When `write_to_disk` is true, writes:
- `{output_dir}/{engagement_id}/report.md` — markdown report (always)
- `{output_dir}/{engagement_id}/report.html` — HTML report (when format is html)

## Report Structure

### Markdown Report

1. **Title & Metadata** — engagement name, ID, period, OPSEC profile
2. **Table of Contents**
3. **Executive Summary** — severity distribution, node/edge counts, objective status
4. **Scope** — CIDRs, domains, exclusions, cloud accounts
5. **Findings Summary** — table of all findings with severity and risk score
6. **Detailed Findings** — per-finding sections:
   - Description
   - Affected Assets
   - Evidence proof cards (claim, proof, command/tool, action/evidence IDs, hash, raw preview link)
   - Auto-generated Remediation
7. **Evidence Appendix** — deduplicated evidence/action/hash references for cited proof
8. **Attack Narrative** — chronological prose by phase:
   - Reconnaissance
   - Initial Access & Credential Acquisition
   - Lateral Movement
   - Privilege Escalation
   - Objective Achievement
9. **Credential Chains** — derivation paths
10. **Objectives** — status table
11. **Discovery Summary** — nodes/edges by type
12. **Agent Activity** — dispatch/completion stats
13. **Retrospective Findings** (optional) — inference gaps, skill gaps
14. **Activity Timeline** — last N events
15. **Recommendations** — auto-generated from critical/high findings

### HTML Report

Self-contained single-file HTML with:
- Light/dark theme support
- Severity cards with color coding
- Visible proof cards and native collapsible raw previews
- Evidence appendix anchors for stable cross-reference
- Table of contents with anchor links
- Print CSS for paper output
- XSS-safe HTML escaping

## Finding Categories

| Category | Source | Severity Heuristic |
|----------|--------|--------------------|
| `compromised_host` | Hosts with HAS_SESSION/ADMIN_TO edges (confidence ≥ 0.9) | Critical if ADMIN_TO, High if session only |
| `credential` | Credential nodes with confidence ≥ 0.9 and usable for auth | Critical if privileged, High otherwise |
| `vulnerability` | Vulnerability nodes | Mapped from CVSS score |
| `cloud_exposure` | Cloud identities with policies/trust and public cloud resources | Critical if admin policy, High if public resource |
| `webapp` | Webapp nodes with vulnerabilities or authenticated access | High if vulnerable, Medium if auth-only |

## Risk Scoring

- Host: base 5.0 + 3.0 (ADMIN_TO) + 1.5 (HAS_SESSION) + 1.0 (≤2 hops to objective), capped at 10
- Credential: 9.5 if privileged, 7.0 otherwise
- Vulnerability: CVSS score directly, or 8.0 if exploitable without CVSS, 5.0 fallback
- Cloud identity: 9.0 if admin policy, 6.5 otherwise
- Cloud resource: 7.5 if public, 5.0 otherwise
- Webapp: 7.0 if vulnerable, 4.0 otherwise

## Auto-Remediation

Generated per finding type:
- **Hosts** — revoke sessions, reset admin creds, check persistence (OS-specific)
- **Credentials** — rotate credential, check lateral movement, credential guard mitigations
- **Vulnerabilities** — patch CVE, update component, vuln-type-specific advice (SSRF → IMDSv2, SQLi → parameterized queries, XSS → CSP)
- **Cloud identities** — review/reduce permissions, remove admin policies, enable MFA, rotate access keys
- **Cloud resources** — restrict public access, enable logging, resource-type-specific advice (S3 Block Public Access, IMDSv2, security groups)
- **Webapps** — fix identified vulns, harden auth (MFA, rate limiting), deploy WAF, code review

## Evidence

When operators supply `evidence` or `raw_output` via `report_finding`, or when terminal execution stores stdout/stderr evidence IDs, the report renders proof cards:

- **Proof cards** — concise claim, why it proves the finding, tool/command, timestamp, action ID, evidence ID, and hash when available.
- **Raw previews** — collapsed by default; redacted in client profile and available in operator profile.
- **Evidence appendix** — deduplicated index of cited action/evidence artifacts with integrity metadata.

## Client-safe exports

The default report is operator-internal: it includes captured stdout, credential values, NTLM/LM hashes, and absolute filesystem paths so the operator can reason about the engagement and debug findings. None of those are appropriate in a client-deliverable.

`client_safe: true` produces a redacted variant in the same call. For the full
field-by-field reference, see [Report Redaction](../reference/report-redaction.md).
The redaction pipeline:

| Field | Operator default | Client-safe |
|-------|------------------|-------------|
| `cred_value` (passwords, tokens, hashes) | full plaintext | `<redacted: <type>, sha256:<12hex>…>` so duplicate references can still be cross-correlated without leaking the secret |
| `raw_output` / `evidence_content` / `stdout_preview` / `stderr_preview` | full body | size-only summary plus `sha256:<16hex>…` for verifiability |
| operator paths (`/Users/...`, `/home/...`, `C:\Users\...`) | rendered verbatim | replaced with `<operator-path>` |
| markdown evidence fences (`Output:` / `Raw Output:` / `Evidence Content:`) | full content | replaced with `<redacted for client delivery — full evidence available in operator report>` |
| every other field | unchanged | unchanged |

Disk artifacts get a `.client-safe.<ext>` suffix so the two variants are visually distinct on disk:

```
./reports/<engagement-id>/report.md             ← operator default
./reports/<engagement-id>/report.client-safe.md ← client deliverable
```

The default operator path is byte-identical to the previous behavior. Operators opt in per call; there is no engagement-level setting.

## Example

```
generate_report({ format: "html", include_narrative: true, write_to_disk: true })

// Same engagement, client-safe markdown:
generate_report({ format: "markdown", write_to_disk: true, client_safe: true })
```
