# OSINT & External-Recon

tags: osint, external-recon, subdomain-enumeration, dns, asn, netblock, whois, certificate-transparency, passive-recon, attack-surface, subfinder, amass, crt.sh

## Objective
Map the target's **external attack surface** — subdomains, DNS records, netblocks/ASNs, owning organizations, and emails — from **public sources only**, never actively scanning or exploiting, and land every discovery in the graph.

## Prerequisites
- An in-scope `domain` (or `organization`/`asn`/`email`) node — typically a `domain_enumeration` frontier item.
- `run_tool` for the passive binaries + `WebSearch`/`WebFetch` for web OSINT.
- **No** interactive sessions, **no** credential tools, **no** raw shell. Passive sources only.

## Methodology

### 1. Enumerate subdomains (passive sources, broadest first)
| Source | Gives | How (`run_tool`, argv) |
|--------|-------|------------------------|
| Certificate Transparency | Subdomains from issued certs | `curl -s "https://crt.sh/?q=<domain>&output=json"` → `parse_output(tool='crtsh')` |
| subfinder | Aggregated passive subdomains | `subfinder -d <domain> -oJ` → `parse_output(tool='subfinder')` |
| amass (passive) | Subdomains + resolved IPs + ASN | `amass enum -passive -d <domain> -json …` → `parse_output(tool='amass')` |

### 2. Resolve + map ownership (light-active is OK, still low-noise)
- `dnsx -json` over discovered names → A/AAAA records (`parse_output(tool='dnsx')`).
- `whois <domain>` and `whois <ip>` → owning **organization** + **ASN**/CIDR (`parse_output(tool='whois')`).
- `httpx -json` to fingerprint live web origins (`parse_output(tool='httpx')`).

### 3. Harvest people / web surface
- `theHarvester -d <domain> -b all -f out.json` → emails + hosts (`parse_output(tool='theharvester')`).
- `WebSearch`/`WebFetch` for GitHub dorks, public docs, and org info; record with `report_finding`.

### 4. Validate before each run, then retire the item
- Call `validate_action` first. Passive techniques (`crt_sh`, `whois`, `subfinder`, `amass_passive`, `theharvester`, …) are **0 noise** and exempt from the time-window/ceiling warnings; light-active (`dnsx`/`httpx`) carries a small rating.
- After enumerating a domain, stamp `subdomains_enumerated_at` on it (via `report_finding`/node update) so the `domain_enumeration` frontier item **retires even if nothing new was found** — mirrors `cve_checked_at`.

## Graph Reporting
- Parsers emit the surface: `subdomain` + `domain` (`SUBDOMAIN_OF`), `host` (`RESOLVES_TO`), `asn` (`IN_NETBLOCK`), `organization` (`OWNS_ASSET`), and `email` nodes.
- A discovered subdomain is scoped by domain-suffix match against `scope.domains`; an out-of-scope find is a candidate for a scope suggestion, not silent acceptance.
- Leave nothing only in stdout — every useful name/record becomes a node via `parse_output`/`report_finding`.

## OPSEC Notes
- **Passive = zero target noise.** crt.sh/whois/subfinder/amass-passive/theHarvester hit public datasets, not the target. OPSEC rating 0.0.
- **Light-active** (dnsx/httpx) touches the target's DNS/HTTP — small noise, still validate first; do not escalate to port scans or brute force (those belong to recon_scanner/web_tester).
- Never authenticate, spray, or exploit — this archetype reads public sources and records surface only.

## Sequencing
- **After**: a domain is in scope (an in-scope `domain` node → `domain_enumeration` frontier item).
- **Feeds →**: recon_scanner (resolved hosts/netblocks to scan), web_tester (live web origins), attack-path analysis (the external surface as entry points), reporting.
