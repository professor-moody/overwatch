# Web Reconnaissance

tags: web, http, https, directory, vhost, application, webapp, reconnaissance, gobuster, feroxbuster, ffuf, whatweb, api

## Objective
Enumerate web applications, virtual hosts, directories, technologies, and API endpoints on HTTP/HTTPS services.

## Prerequisites
- HTTP or HTTPS service identified on target (port 80, 443, 8080, 8443, etc.)
- Network access to the service

## Methodology

### Technology Fingerprinting (OPSEC: 0.3)
```bash
# Quick technology fingerprint
whatweb http://target -a 3

# Header inspection
curl -sI http://target | grep -i 'server\|x-powered-by\|x-aspnet'
```
Check default error pages, `/robots.txt`, `/sitemap.xml`, `/.well-known/`.

### Directory and File Enumeration (OPSEC: 0.7)
```bash
# Gobuster — directory bruteforce
gobuster dir -u http://target \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,aspx,html,txt,bak -t 50 -o out.txt

# Feroxbuster — recursive with link extraction
feroxbuster -u http://target -w wordlist -x php,aspx \
  -t 50 --depth 3 --extract-links -o out.txt

# ffuf — fast fuzzing with filtering
ffuf -u http://target/FUZZ -w wordlist \
  -mc 200,301,302,403 -fc 404 -t 50 -o out.json -of json
```

### Virtual Host Discovery
```bash
# Discover vhosts via Host header fuzzing
ffuf -u http://target -H "Host: FUZZ.target.com" \
  -w subs.txt -fs <default_response_size>

# Gobuster vhost mode
gobuster vhost -u http://target -w wordlist --domain target.com
```
Each unique vhost is a separate attack surface.

### API Endpoint Discovery
Priority endpoints to check:
```bash
# Common API documentation paths
curl -s http://target/swagger.json
curl -s http://target/openapi.json
curl -s http://target/api-docs
curl -s http://target/graphql
curl -s http://target/api/v1/
```

### Sensitive File Checks
```bash
# Check for exposed source control, configs, backups
curl -s http://target/.git/HEAD
curl -s http://target/.env
curl -s http://target/web.config
curl -s http://target/wp-config.php.bak
```
Targets: `.git/`, `.svn/`, `.env`, `web.config`, backup files (`.bak`, `.old`, `.swp`), database dumps.

### Authentication Testing
- **Tomcat Manager**: `tomcat/tomcat`, `admin/admin`
- **Jenkins**: check for unauthenticated access at `/script`
- **WordPress**: enumerate users at `/wp-json/wp/v2/users`

## Graph Reporting
- **Enrich service nodes**: technology stack, framework, version, server software
- **New service nodes**: for each vhost discovered
- **Credential nodes**: for default/leaked credentials found
- **HAS_SESSION edges**: if admin access obtained via default creds

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| Technology fingerprinting | 0.3 |
| Directory bruteforcing | 0.7 |
| vhost discovery | 0.5 |
| API endpoint probing | 0.3 |
| Sensitive file checks | 0.3 |

**Detection**: WAF alerts for 404 spikes, web server access logs showing sequential requests, rate-limiting triggers.

## Sequencing
- **After**: Network Recon (identifies HTTP/HTTPS services)
- **Feeds →**: Web Vulnerability Scanning, SQL Injection, Web Application Attacks, CMS Exploitation
- **Scanning methodology order**: Fingerprint → Directory enum → API discovery → Manual testing
