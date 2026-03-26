# get_skill

Search the skill library for methodology guidance.

**Read-only:** Yes

## Description

RAG-based skill retrieval using TF-IDF search. Use when you encounter a service, vulnerability, or attack scenario and want structured guidance on how to approach it.

Examples:
- `"smb relay signing disabled"` → returns SMB relay methodology
- `"kerberos service accounts"` → returns Kerberoasting methodology
- `"web application tomcat"` → returns web discovery methodology

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | `string` | — | Search query to find relevant skills |
| `skill_id` | `string` | — | Retrieve a specific skill by ID |
| `list_all` | `boolean` | `false` | List all available skills |
| `max_results` | `integer` | `3` | Maximum results to return (1–10) |

## Behavior

- If `list_all: true` — returns all skill names and IDs
- If `skill_id` is provided — returns the full content of that specific skill
- If `query` is provided — searches and returns the top match (full content) plus summaries of other matches

## Returns

For search queries:

| Field | Type | Description |
|-------|------|-------------|
| `top_match.id` | `string` | Skill ID |
| `top_match.name` | `string` | Skill name |
| `top_match.score` | `number` | TF-IDF relevance score |
| `top_match.content` | `string` | Full skill markdown content |
| `other_matches` | `array` | Other relevant skills with excerpts |

## Available Skills

The library includes 32 offensive methodology guides covering:

- **Network** — reconnaissance, DNS, SNMP, SMB enumeration
- **Active Directory** — discovery, Kerberoasting, ADCS, domain trusts, persistence
- **Credentials** — password spraying, credential dumping, SMB relay
- **Lateral Movement** — pivoting, lateral movement techniques
- **Web** — discovery, app attacks, vulnerability scanning, CMS exploitation, SQL injection
- **Cloud** — AWS, Azure, GCP exploitation
- **Linux** — enumeration, privilege escalation
- **Windows** — privilege escalation, SCCM attacks, Exchange attacks
- **Post-exploitation** — persistence, data exfiltration

## Usage Notes

- Tags in skill files improve search ranking — search for specific terms
- Each skill includes exact commands, OPSEC noise ratings, and graph reporting guidance
- Skills reference `report_finding` format for consistent graph updates
