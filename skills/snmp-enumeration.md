# SNMP Enumeration

tags: snmp, enumeration, community-string, mib, onesixtyone, snmpwalk, udp, information-disclosure

## Objective
Extract host information, user accounts, running processes, and installed software via SNMP when UDP/161 is open.

## Prerequisites
- SNMP service identified on target (UDP port 161)
- Community string (try `public`, `private` first)

## Methodology

### Community String Guessing (OPSEC: 0.4)
```bash
# Brute force community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt TARGET
```

### MIB Walking
```bash
# System info
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.1

# User accounts (Windows)
snmpwalk -v2c -c public TARGET 1.3.6.1.4.1.77.1.2.25

# Running processes
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.4.2.1.2

# TCP connections
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.6.13.1.3

# Installed software
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.6.3.1.2
```

### Automated Enumeration (OPSEC: 0.3)
```bash
snmp-check TARGET -c public
```

## Graph Reporting
- **Enrich host nodes**: OS details, installed software, network config
- **User nodes**: from SNMP user enumeration
- **Service nodes**: from running processes
- **Credential nodes**: if community string is non-default (it's a shared secret)

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| Community string guessing | 0.4 |
| MIB walking | 0.3 |
| Automated enumeration | 0.3 |

**Detection**: SNMP authentication failure traps, high-volume SNMP GET requests.

## Sequencing
- **After**: Network Recon (identifies UDP/161 open)
- **Feeds →**: AD Discovery (user info), Lateral Movement (process info)
