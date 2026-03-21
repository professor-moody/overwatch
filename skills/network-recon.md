# Network Reconnaissance

tags: nmap, masscan, portscan, discovery, enumeration, network, recon, hosts, services, arp, udp

## Objective
Discover live hosts and enumerate services on target network segments. This is the foundational skill — everything downstream depends on its output quality.

## Prerequisites
- Network access to target ranges
- Root/sudo for SYN scans (`-sS`)
- Scope definition (IP ranges, excluded hosts)

## Methodology

### Host Discovery
```bash
# ARP scan — LAN only (OPSEC: 0.2)
nmap -sn -PR 10.10.10.0/24 -oA arp_sweep

# ICMP + TCP SYN/ACK + UDP — default ping sweep (OPSEC: 0.3)
nmap -sn 10.10.10.0/24 -oG - | grep "Up" | awk '{print $2}'

# TCP-only discovery when ICMP blocked (OPSEC: 0.3)
nmap -sn -PA80,443,445 TARGET_RANGE

# Masscan host discovery — fast, high packet rate (OPSEC: 0.5)
masscan 10.10.10.0/24 -p 80,443,445,22 --rate=1000 -oL alive.txt
```

### Port Scanning
```bash
# SYN scan with service detection (OPSEC: 0.5)
nmap -sS -sV -sC -O -p- --min-rate=1000 -oA full_scan TARGET
# Flags: -sS (SYN/stealth), -sV (version detection), -sC (default scripts),
#        -O (OS fingerprint), -p- (all 65535 ports)

# Top ports quick scan (OPSEC: 0.4)
nmap -sS -sV --top-ports 1000 -oA quick TARGET

# UDP scan — slow but finds SNMP, DNS, NTP (OPSEC: 0.6)
nmap -sU --top-ports 50 -sV TARGET

# Masscan full port then nmap service scan — optimized workflow
masscan TARGET -p 1-65535 --rate=1000 -oL ports.txt
grep "open" ports.txt | awk '{print $3}' | sort -un | paste -sd, > portlist
nmap -sV -sC -p $(cat portlist) TARGET -oA detailed

# IDS evasion scan (OPSEC: 0.3)
nmap -sS -f --data-length 24 -D RND:5 --source-port 53 -T2 TARGET
# -f (fragment packets), --data-length (pad), -D (decoys),
# --source-port (spoof src port), -T2 (slow timing)
```

### Key Services to Flag
- **Port 88 (Kerberos)**: Domain controller. High-priority target.
- **Port 445 (SMB)**: Check signing: `nmap --script smb-security-mode -p445 TARGET`. Signing disabled = relay target.
- **Port 389/636 (LDAP/LDAPS)**: Domain controller or domain-joined server.
- **Port 80/443 (HTTP/HTTPS)**: Web services — needs separate web discovery skill.
- **Port 1433 (MSSQL)**: Often has service accounts with domain privileges.
- **Port 3389 (RDP)**: Lateral movement target.
- **Port 5985/5986 (WinRM)**: PowerShell remoting, lateral movement vector.
- **Port 161 (SNMP/UDP)**: Information disclosure via community strings.

## Graph Reporting
For each host, `report_finding` with:
- **Host node**: `type: host`, IP, hostname, OS (from nmap fingerprint), `alive: true`
- **Service nodes**: one per open port — `type: service`, port, protocol, service_name, version, banner
- **RUNS edges**: from host → each service, `confidence: 1.0`
- **REACHABLE edges**: between hosts on same subnet
- **Subnet nodes**: enrich from discovered ranges
- If Kerberos found: triggers `rule-kerberos-domain` inference → MEMBER_OF_DOMAIN edge

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| ARP scan | 0.2 |
| ICMP ping sweep | 0.3 |
| SYN scan | 0.5 |
| Connect scan (-sT) | 0.6 |
| Version scan (-sV) | 0.5 |
| UDP scan | 0.6 |
| Masscan default rate | 0.7 |
| Masscan rate-limited | 0.4 |
| IDS evasion scan | 0.3 |

**Detection signatures**: Firewall logs for SYN-only packets (no ACK follow-up), IDS signatures for sequential port scanning, Snort/Suricata rules for nmap fingerprinting, threshold alerts for connection attempts per second.

## Sequencing
- **FIRST skill** in any engagement
- Feeds → DNS Enumeration, SMB Enumeration, Web Recon, AD Discovery
- Run before all other skills
