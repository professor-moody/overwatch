# Web Vulnerability Scanning

tags: web, vulnerability, scanning, nuclei, nikto, cve, misconfig, exposure

## Objective
Identify known vulnerabilities, misconfigurations, and exposures on web applications using automated scanners.

## Prerequisites
- Web service identified and fingerprinted (from Web Reconnaissance)
- Network access to target web application

## Methodology

### Nuclei (OPSEC: 0.5–0.7)
```bash
# Quick scan — critical and high severity CVEs
nuclei -u http://target -t cves/ -severity critical,high -o output.txt

# Bulk URL scanning with multiple template categories
nuclei -l urls.txt -tags cve,misconfig,exposure \
  -severity critical,high,medium -c 50 -rate-limit 100

# Technology detection templates
nuclei -u http://target -t http/technologies/

# Specific CVE check
nuclei -u http://target -t cves/2021/CVE-2021-44228.yaml
```

### Nikto (OPSEC: 0.8 — very noisy)
```bash
# Comprehensive web server scan
nikto -h http://target -o output.txt

# With specific tuning
nikto -h http://target -Tuning 1234 -o output.txt
# Tuning: 1=interesting files, 2=misconfig, 3=info disclosure, 4=injection
```

### Scanning Methodology Order
1. **Fingerprint** (whatweb) — identify technology stack
2. **Directory enum** — find hidden paths and files
3. **Nuclei quick wins** — check for known CVEs against identified tech
4. **Manual testing** — follow up on interesting findings

## Graph Reporting
- **Enrich service nodes**: with vulnerability findings, CVE IDs
- **Credential nodes**: if default credentials found
- **HAS_SESSION edges**: if vulnerability leads to access
- Tag vulnerable services for follow-up exploitation

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| Nuclei (rate-limited) | 0.5 |
| Nuclei (full speed) | 0.7 |
| Nikto | 0.8 |

**Detection**: WAF alerts, distinctive user-agent strings (Nikto), high request volume, known vulnerability probe patterns in web logs.

## Sequencing
- **After**: Web Reconnaissance (need URLs and technology fingerprints)
- **Feeds →**: SQL Injection, Web Application Attacks, CMS Exploitation
