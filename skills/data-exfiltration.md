# Data Discovery and Exfiltration

tags: data, exfiltration, snaffler, seatbelt, shares, sensitive-files, passwords, ssh-keys, keepass

## Objective
Discover and collect sensitive data: passwords in scripts/configs, SSH keys, KeePass databases, certificates, connection strings.

## Prerequisites
- Authenticated access to file shares or compromised host
- Domain credentials for share enumeration

## Methodology

### Snaffler — Automated Share Enumeration (OPSEC: 0.5)
```bash
# Enumerate all accessible shares for sensitive files
Snaffler.exe -s -o snaffler.log

# Domain-wide share enumeration
Snaffler.exe -s -d domain.local -o snaffler.log -v data
```
Finds: passwords in scripts/configs, SSH keys, KeePass DBs, certificates, connection strings, database backups.

### Seatbelt — Local Host Enumeration (OPSEC: 0.2)
```bash
# Comprehensive local host data collection
Seatbelt.exe -group=all

# Targeted checks
Seatbelt.exe -group=user    # User-context info
Seatbelt.exe -group=system  # System-context info
```

### Manual Share Enumeration
```bash
# List accessible shares
nxc smb TARGETS -u user -p pass --shares

# Spider shares for interesting files
nxc smb TARGET -u user -p pass --spider C$ --regex "password|credential|secret" \
  --depth 3

# Recursive file listing
smbclient //TARGET/share -U 'domain/user%pass' -c 'recurse;ls'
```

### Sensitive File Targets
- `*.kdbx` — KeePass databases
- `*.pfx`, `*.p12`, `*.pem` — Certificates and private keys
- `*.config`, `web.config`, `appsettings.json` — App configs with connection strings
- `*.ps1`, `*.bat`, `*.vbs` — Scripts with hardcoded credentials
- `unattend.xml`, `sysprep.xml` — Windows deployment files with passwords
- `.ssh/id_rsa`, `.ssh/id_ed25519` — SSH private keys
- `.git-credentials`, `.netrc` — Stored credentials

## Graph Reporting
- **Credential nodes**: from discovered passwords, SSH keys, certificates
- **Share nodes**: with sensitive file indicators
- **VALID_ON edges**: discovered credentials → user/service accounts
- Link credentials to users and services for attack path expansion

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| Snaffler | 0.5 |
| Seatbelt | 0.2 |
| nxc share spider | 0.4 |
| Manual file access | 0.2 |

**Detection**: File access auditing (Event 5145), unusual SMB share access patterns, large file transfers.

## Sequencing
- **After**: Lateral Movement (access to hosts/shares), SMB Enumeration
- **Feeds →**: Credential validation → further Lateral Movement, objective completion
