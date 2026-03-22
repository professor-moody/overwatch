# Skills Library

Overwatch includes 29 offensive methodology guides searchable via TF-IDF through the [`get_skill`](../tools/get-skill.md) tool.

## Available Skills

### Network & Infrastructure

| Skill | File | Description |
|-------|------|-------------|
| Network Recon | `network-recon.md` | Host discovery, port scanning, service enumeration |
| DNS Enumeration | `dns-enumeration.md` | DNS zone transfers, subdomain enumeration |
| SNMP Enumeration | `snmp-enumeration.md` | SNMP community string brute-force, MIB walking |
| SMB Enumeration | `smb-enumeration.md` | Share enumeration, null sessions, user listing |

### Active Directory

| Skill | File | Description |
|-------|------|-------------|
| AD Discovery | `ad-discovery.md` | AD enumeration, BloodHound, trusts, delegation, ADCS |
| Kerberoasting | `kerberoasting.md` | SPN enumeration, TGS cracking |
| ADCS Exploitation | `adcs-exploitation.md` | Certificate abuse (ESC1–ESC8) |
| Domain Trust Attacks | `domain-trust-attacks.md` | Cross-domain and forest trust abuse |
| AD Persistence | `ad-persistence.md` | Golden/Silver tickets, skeleton key, DCShadow |
| SCCM Attacks | `sccm-attacks.md` | SCCM/MECM credential harvesting and lateral movement |
| Exchange Attacks | `exchange-attacks.md` | ProxyLogon, ProxyShell, mailbox access |

### Credentials

| Skill | File | Description |
|-------|------|-------------|
| Password Spraying | `password-spraying.md` | Domain and local password spraying |
| Credential Dumping | `credential-dumping.md` | LSASS, SAM, NTDS.dit, DCSync |
| SMB Relay | `smb-relay.md` | NTLM relay attacks, coercion methods |

### Lateral Movement & Pivoting

| Skill | File | Description |
|-------|------|-------------|
| Lateral Movement | `lateral-movement.md` | WMI, PSExec, WinRM, DCOM, RDP |
| Pivoting | `pivoting.md` | SSH tunnels, SOCKS proxies, port forwarding |

### Web Application

| Skill | File | Description |
|-------|------|-------------|
| Web Discovery | `web-discovery.md` | Web app fingerprinting, directory enumeration |
| Web App Attacks | `web-app-attacks.md` | Authentication bypass, file upload, SSRF |
| Web Vuln Scanning | `web-vuln-scanning.md` | Automated vulnerability scanning |
| CMS Exploitation | `cms-exploitation.md` | WordPress, Joomla, Drupal |
| SQL Injection | `sql-injection.md` | SQL injection detection and exploitation |

### Privilege Escalation

| Skill | File | Description |
|-------|------|-------------|
| Windows Privilege Escalation | `privilege-escalation.md` | Service misconfigs, token abuse, UAC bypass |
| Linux Enumeration | `linux-enumeration.md` | System info, SUID, cron, capabilities |
| Linux Privilege Escalation | `linux-privesc.md` | Kernel exploits, sudo abuse, Docker escape |

### Cloud

| Skill | File | Description |
|-------|------|-------------|
| AWS Exploitation | `aws-exploitation.md` | IAM abuse, metadata service, S3 misconfiguration |
| Azure Exploitation | `azure-exploitation.md` | Azure AD, managed identities, storage |
| GCP Exploitation | `gcp-exploitation.md` | Service accounts, metadata, storage buckets |

### Post-Exploitation

| Skill | File | Description |
|-------|------|-------------|
| Persistence | `persistence.md` | Startup scripts, scheduled tasks, services |
| Data Exfiltration | `data-exfiltration.md` | File staging, transfer, and exfil techniques |

## Searching Skills

The `get_skill` tool uses TF-IDF search. Tips for effective queries:

- Use specific technique names: `"kerberoast"`, `"ntlm relay"`, `"adcs esc1"`
- Use service names: `"smb"`, `"ldap"`, `"mssql"`, `"http"`
- Use attack patterns: `"privilege escalation"`, `"lateral movement"`, `"credential dumping"`

## Writing Custom Skills

Skills are markdown files in the `skills/` directory following this template:

```markdown
# Skill Name

tags: keyword1, keyword2, keyword3

## Objective
What this skill accomplishes.

## Prerequisites
What's needed before using this skill.

## Methodology
Step-by-step approach with exact commands.

## Reporting
What to report via report_finding — node types, edge types, properties.

## OPSEC Notes
Noise considerations and stealth alternatives.
```

### Best Practices

- **Tags** improve search ranking — use specific terms the LLM might search for
- **Commands** should be exact and copy-pasteable
- **OPSEC Notes** should include noise ratings (0.0–1.0 scale)
- **Reporting** sections should reference `report_finding` format with specific node/edge types
- **Detection signatures** help the LLM understand risk before executing
