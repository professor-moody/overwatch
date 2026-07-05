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

**Analyze the response headers** — don't just eyeball them: `curl -sI https://target` →
`parse_output as \`security-headers\`` (`context.source_host = https://target`) surfaces
`cors_misconfig` (permissive `Access-Control-Allow-Origin`) and `missing_security_header`
(HSTS / CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy) as `vulnerability` nodes
on the webapp.

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
Don't just eyeball the schema — **ingest it** so each operation becomes an `api_endpoint` node
(`method`, `response_type`, plus `auth_required` on the OpenAPI/Swagger path). Probe the
unauthenticated (`auth_required: false`) operations first:
```bash
# OpenAPI/Swagger JSON  →  parse_output as `openapi` (or `swagger`), context.source_host = http://target
curl -s http://target/openapi.json
# GraphQL introspection  →  parse_output as `graphql`, context.source_host = http://target
curl -s http://target/graphql -X POST -H 'Content-Type: application/json' \
  -d '{"query":"query{__schema{queryType{name} mutationType{name} types{name fields{name}}}}"}'
```

### Client-side JS: secrets + endpoints
Mine the app's JavaScript — leaked secrets become **credential** nodes (verified ones feed the spray
loop and `credential_test` frontier), extracted URLs become `api_endpoint` nodes:
```bash
wget -r -l2 -A js http://target -P js_bundles/          # grab the bundles (trufflehog scans files, not URLs)
trufflehog filesystem js_bundles/ --json                # →  parse_output as `trufflehog`, context.source_host = http://target
linkfinder -i 'http://target/app.js' -o cli             # →  parse_output as `linkfinder`, context.source_host = http://target
```

### Visual Triage (Screenshots)
Screenshot the web estate to prioritize by eye — leftover admin panels, default installs, error pages:
```bash
gowitness scan single -u https://target --write-jsonl   # writes ./gowitness.jsonl; or `aquatone` over a host list
```
`parse_output as \`gowitness\`` (or `aquatone`) enriches each webapp with its title, HTTP status,
technology, and a `screenshot_path` reference (the image bytes stay on disk). To make the captures
**viewable in the dashboard**, run the `ingest_screenshots` tool on the report dir — it stores the PNG
bytes as evidence and stamps `screenshot_evidence_id` on the webapp (rendered in the node drawer).

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
- **Test a credential against the app**: use the `test_webapp_credential` tool (method `form` /
  `basic` / `bearer` / `cookie`) with an explicit `success` criterion (a status code, a redirect
  target, or a body marker). On success it records `AUTHENTICATED_AS` + `VALID_ON` and retires the
  `credential_test` frontier item; on failure it records `TESTED_CRED` so the pair isn't retried.

### Authenticated Crawl
The **post-login** surface is where the interesting endpoints live — unauthenticated dir-enum can't see
it. Log in once, keep the session, and crawl with it:
1. `test_webapp_credential` with a `session_jar_id` (e.g. `acme`) — the login's `Set-Cookie` is saved to
   a cookie jar and the tool's response prints the jar path (the jar holds the authenticated session
   only if the login actually succeeded — check the result).
2. Crawl **with that session** through `run_tool` (`wget --load-cookies` reads the jar natively):
   ```bash
   wget --load-cookies '<jar-path-from-step-1>' --recursive --level=2 --spider --no-verbose https://target 2>&1 \
     | grep -oE 'https?://[^ ]+' | sort -u          # or `katana -u https://target -H "Cookie: …" -jsonl`
   ```
3. `parse_output as \`katana\`` (or `hakrawler`) → an `api_endpoint` per discovered URL under the webapp
   (`context.source_host = https://target`; kept to the same registrable domain — sibling subdomains
   like `api.target` stay, off-site links like CDNs/trackers are dropped).

## Graph Reporting
- **Enrich service nodes**: technology stack, framework, version, server software
- **New service nodes**: for each vhost discovered
- **Credential nodes**: for default/leaked credentials found (JS secrets included)
- **api_endpoint nodes**: for each ingested API operation / crawled URL (`HAS_ENDPOINT` from the webapp)
- **vulnerability nodes**: `cors_misconfig` / `missing_security_header` from response-header analysis
- **Webapp enrichment**: `screenshot_path` from visual triage
- **AUTHENTICATED_AS / VALID_ON edges**: when a credential validates against the app
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
