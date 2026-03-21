# SMB Enumeration

tags: smb, enumeration, shares, rid-brute, null-session, gpp, signing, nxc, smbclient, enum4linux

## Objective
Enumerate SMB shares, users via RID cycling, GPP passwords, and SMB signing status for relay attacks.

## Prerequisites
- Target with port 445 open
- Optional: valid domain credentials for authenticated enumeration

## Methodology

### Null Session Testing (OPSEC: 0.3)
```bash
# Test null session
nxc smb TARGET -u '' -p ''
nxc smb TARGET -u 'guest' -p ''

# smbclient null session
smbclient -N -L //TARGET
```

### Share Enumeration (OPSEC: 0.3)
```bash
# Authenticated share listing
nxc smb TARGET -u user -p pass --shares

# smbclient
smbclient -U 'domain/user%pass' -L //TARGET

# Recursive file listing on accessible shares
smbclient //TARGET/share -U 'domain/user%pass' -c 'recurse;ls'
```

### User Enumeration via RID Cycling
```bash
# RID brute force — enumerate users without LDAP (OPSEC: 0.3)
nxc smb TARGET -u user -p pass --users --rid-brute

# enum4linux-ng comprehensive enumeration
enum4linux-ng -u user -p pass -A TARGET
```

### SMB Signing Check (critical for relay attacks)
```bash
# Generate list of relay targets — signing disabled hosts (OPSEC: 0.3)
nxc smb 10.10.10.0/24 --gen-relay-list relay_targets.txt
```
DCs have signing required by default; workstations typically do **not**.

### GPP Passwords (MS14-025)
```bash
# Check for Group Policy Preferences passwords (OPSEC: 0.3)
nxc smb TARGET -u user -p pass -M gpp_autologin
nxc smb TARGET -u user -p pass -M gpp_password

# Manual check
findstr /S /I cpassword \\DC\SYSVOL\domain\Policies\*.xml
```

## Graph Reporting
- **Share nodes**: with permissions (read/write), sensitive file indicators
- **User nodes**: from RID cycling enumeration
- **Credential nodes**: from GPP passwords with `VALID_ON` edges
- **RELAY_TARGET edges**: for signing-disabled hosts
- **RUNS edges**: host → SMB service

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| Null session test | 0.3 |
| Authenticated share enum | 0.3 |
| RID brute force | 0.3 |
| SMB signing check | 0.3 |
| GPP password check | 0.3 |

**Detection**: Event 4625 for failed null sessions, 5145 for share access, high-volume RID lookups.

## Sequencing
- **After**: Network Recon (identifies port 445)
- **Feeds →**: NTLM Relay (signing check), Credential Attacks, AD Discovery, Data Exfiltration
