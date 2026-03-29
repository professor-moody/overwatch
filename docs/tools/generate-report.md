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
   - Evidence (command → tool → graph mutation linkage)
   - Auto-generated Remediation
7. **Attack Narrative** — chronological prose by phase:
   - Reconnaissance
   - Initial Access & Credential Acquisition
   - Lateral Movement
   - Privilege Escalation
   - Objective Achievement
8. **Credential Chains** — derivation paths
9. **Objectives** — status table
10. **Discovery Summary** — nodes/edges by type
11. **Agent Activity** — dispatch/completion stats
12. **Retrospective Findings** (optional) — inference gaps, skill gaps
13. **Activity Timeline** — last N events
14. **Recommendations** — auto-generated from critical/high findings

### HTML Report

Self-contained single-file HTML with:
- Light/dark theme support
- Severity cards with color coding
- Collapsible evidence sections
- Table of contents with anchor links
- Print CSS for paper output
- XSS-safe HTML escaping

## Finding Categories

| Category | Source | Severity Heuristic |
|----------|--------|--------------------|
| `compromised_host` | Hosts with HAS_SESSION/ADMIN_TO edges (confidence ≥ 0.9) | Critical if ADMIN_TO, High if session only |
| `credential` | Credential nodes with confidence ≥ 0.9 and usable for auth | Critical if privileged, High otherwise |
| `vulnerability` | Vulnerability nodes | Mapped from CVSS score |

## Risk Scoring

- Host: base 5.0 + 3.0 (ADMIN_TO) + 1.5 (HAS_SESSION) + 1.0 (≤2 hops to objective), capped at 10
- Credential: 9.5 if privileged, 7.0 otherwise
- Vulnerability: CVSS score directly, or 8.0 if exploitable without CVSS, 5.0 fallback

## Auto-Remediation

Generated per finding type:
- **Hosts** — revoke sessions, reset admin creds, check persistence (OS-specific)
- **Credentials** — rotate credential, check lateral movement, credential guard mitigations
- **Vulnerabilities** — patch CVE, update component, vuln-type-specific advice (SSRF → IMDSv2, SQLi → parameterized queries, XSS → CSP)

## Example

```
generate_report({ format: "html", include_narrative: true, write_to_disk: true })
```
