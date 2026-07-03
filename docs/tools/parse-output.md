# parse_output

Parse raw output from common offensive tools into structured graph data.

**Read-only:** No

## Description

Deterministically parses tool output into structured findings and (optionally) ingests them into the graph. This reduces LLM token cost by handling structured parsing without LLM involvement.

### Supported Parsers

| Parser | Aliases | Input Format | Produces |
|--------|---------|--------------|----------|
| **Nmap** | `nmap`, `nmap-xml` | Nmap XML output | Host + service nodes, `RUNS` edges, OS detection |
| **NXC/NetExec** | `nxc`, `netexec` | NXC text output | Host + SMB service nodes, share nodes, user nodes, access edges, `NULL_SESSION` edges, SAM hashes (`--sam`), LSA secrets (`--lsa`), file listings (`spider_plus`) |
| **Certipy** | `certipy` | Certipy JSON output | CA + cert_template nodes, enrollment edges, ESC edges |
| **Secretsdump** | `secretsdump`, `impacket-secretsdump` | SAM/NTDS hashes | Credential + user nodes, `OWNS_CRED` + `DUMPED_FROM` + `MEMBER_OF_DOMAIN` edges |
| **Kerbrute** | `kerbrute` | User enum + spray output | User + domain + credential nodes |
| **Hashcat** | `hashcat` | Cracked hashes (NTLM, Kerberoast, AS-REP, NTLMv2) | Credential nodes |
| **Responder** | `responder` | Captured NTLMv2 hashes | Credential + user + host nodes |
| **Ldapsearch** | `ldapsearch`, `ldapdomaindump`, `ldap` | LDIF or ldapdomaindump JSON | User + group + host + domain nodes, UAC flags, group memberships |
| **Enum4linux** | `enum4linux`, `enum4linux-ng` | JSON (`-oJ`) or text | Host + SMB service + user + group + share nodes, null session detection |
| **Rubeus** | `rubeus` | Kerberoast/AS-REP/monitor output | User + credential nodes, `OWNS_CRED` edges (TGT/TGS detection) |
| **Web Dir Enum** | `gobuster`, `feroxbuster`, `ffuf`, `dirbuster` | Text or JSON | Service node enrichment with `discovered_paths`, login form detection |
| **Linpeas** | `linpeas`, `linenum`, `linpeas.sh` | Text output | Host enrichment: kernel version, SUID binaries, docker socket, capabilities, cron jobs |
| **Nuclei** | `nuclei` | JSON, JSONL, or text output | Vulnerability + webapp nodes, `VULNERABLE_TO` edges. A `takeover`-tagged result → `subdomain_takeover` vuln + `takeover_candidate` on the affected subdomain. Text format: `[template-id] [protocol] [severity] url` |
| **Nikto** | `nikto` | Text or JSON output | Per-path web vulnerability findings with `affected_path` metadata |
| **TestSSL** | `testssl`, `testssl.sh`, `sslscan` | Text or JSON output | TLS enrichment: version, cipher suites, certificate details |
| **Pacu** | `pacu` | JSON output | Cloud identity + resource + policy nodes, `HAS_POLICY` / `ASSUMES_ROLE` edges |
| **Prowler** | `prowler` | OCSF JSON-lines output | Cloud resource nodes, all FAIL findings as vulnerability nodes (any severity) |
| **Impacket GetNPUsers** | `getnpusers`, `impacket-getnpusers` | GetNPUsers text output | User + credential nodes (AS-REP hashes), `AS_REP_ROASTABLE` edges |
| **Impacket GetUserSPNs** | `getuserspns`, `impacket-getuserspns` | GetUserSPNs text output | User + credential nodes (TGS hashes), `KERBEROASTABLE` edges |
| **Impacket GetTGT** | `gettgt`, `impacket-gettgt` | GetTGT text output | Credential nodes (TGT `.ccache` files), domain membership |
| **Impacket GetST** | `getst`, `impacket-getst` | GetST text output | Credential nodes (service ticket `.ccache` files), `CAN_DELEGATE_TO` edges |
| **Impacket smbclient** | `smbclient`, `impacket-smbclient` | smbclient.py text output | Host + share nodes, file listings, `readable`/`writable` share properties |
| **Impacket wmiexec** | `wmiexec`, `impacket-wmiexec` | wmiexec.py text output | Host nodes with `ADMIN_TO`/`HAS_SESSION` edges (confirmed execution) |
| **Impacket psexec** | `psexec`, `impacket-psexec` | psexec.py text output | Host nodes with `ADMIN_TO`/`HAS_SESSION` edges (confirmed execution) |
| **crt.sh** | `crtsh`, `crt.sh`, `crt-sh` | crt.sh JSON (CT logs) | Subdomain + domain nodes, `SUBDOMAIN_OF` edges (passive OSINT) |
| **subfinder** | `subfinder` | Text or JSON-lines hosts | Subdomain + domain nodes, `SUBDOMAIN_OF` edges (passive OSINT) |
| **whois** | `whois` | whois text (domain or IP) | Organization + domain + asn nodes, `OWNS_ASSET` edges (passive OSINT) |
| **amass** | `amass` | `amass enum -json` JSON-lines | Subdomain + domain + host + asn nodes, `SUBDOMAIN_OF` / `RESOLVES_TO` / `IN_NETBLOCK` edges |
| **dnsx** | `dnsx` | `dnsx -json` JSON-lines | Subdomain + domain + resolved host nodes, `SUBDOMAIN_OF` / `RESOLVES_TO` edges (light-active). Captures `CNAME` → `dns_records`; a dangling CNAME (no A/AAAA) to a claimable provider flags `takeover_candidate` |
| **httpx** | `httpx` | `httpx -json` JSON-lines | Webapp nodes with detected technology + HTTP status (light-active) |
| **theHarvester** | `theharvester` | theHarvester JSON (`-f`) | Email nodes + harvested subdomain/domain nodes (passive OSINT) |
| **trufflehog** | `trufflehog` | `trufflehog filesystem … --json` JSON-lines (v3) | `credential` nodes for leaked secrets (`cred_evidence_kind: dump`; verified ⇒ usable), attached to the source webapp via a `hardcoded_secret` vuln + `EXPLOITS`. trufflehog scans files/git — download the JS first, then pass the app URL as `source_host` |
| **secretfinder** | `secretfinder` | Normalized secrets JSON `{url, results:[{name, matches}]}` | Same node/edge shape as trufflehog, keyed off the per-record `url`. SecretFinder has no native JSON — map its output to this shape (or use `ingest_json`) |
| **LinkFinder** | `linkfinder` | `-o cli` plaintext (one endpoint per line); also a JSON array / `{endpoints:[…]}` | `api_endpoint` nodes (`path`, query/fragment stripped) + `HAS_ENDPOINT` from the source webapp (sets `has_api`); off-origin links are dropped. Pass the scanned URL as `source_host` |
| **OpenAPI / Swagger** | `openapi`, `swagger` | OpenAPI 3 / Swagger 2 JSON | One `api_endpoint` per path × method (`method`, `auth_required` from `security`, `response_type`) + `HAS_ENDPOINT` from the server webapp (`has_api`). Origin from the schema's `servers`/`host`, else `source_host` |
| **GraphQL introspection** | `graphql`, `graphql_introspection` | `{data:{__schema:…}}` introspection JSON | One `api_endpoint` per query/mutation field (POST to the GraphQL path) + `HAS_ENDPOINT` (subscriptions are WebSocket, not modeled). Pass the endpoint URL as `source_host` |

(Plus cloud/identity parsers — `pacu`, `scoutsuite`, `cloudfox`, `roadrecon`, `okta`, the `msgraph-*` / `gh-api-*` / `token_replay_*` families, and more. Use `list_parsers: true` for the authoritative live list.)

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tool_name` | `string` | Yes | Name of the tool (e.g., `nmap`, `nxc`, `certipy`) |
| `output` | `string` | Yes | Raw tool output to parse |
| `agent_id` | `string` | No | Agent ID to attribute findings to |
| `action_id` | `string` | No | Stable action ID for linkage |
| `frontier_item_id` | `string` | No | Frontier item this parse came from |
| `context` | `object` | No | Parser context: `{ domain?: string, source_host?: string }` |
| `ingest` | `boolean` | No | Auto-ingest into graph (default: `true`) |
| `list_parsers` | `boolean` | No | List all supported parser names (default: `false`) |

### Parser Context

The `context` parameter provides ambient information that parsers use as fallback when the raw output doesn't contain it:

- **`domain`** — Used by `secretsdump` and `hashcat` to set `cred_domain` when the output doesn't include domain prefixes. Only used as a soft hint for `cred_domain`; not used to construct user IDs (prevents false merges).
- **`source_host`** — Used by `secretsdump` to create `DUMPED_FROM` edges linking credentials back to the host they were extracted from.

## Returns

Successful responses share a stable schema when the parser extracts at least one graph artifact:

| Field | Type | Description |
|-------|------|-------------|
| `parsed` | `boolean` | Whether parsing succeeded |
| `parse_status` | `string` | `"ok"` for successful extraction |
| `tool` | `string` | Tool name |
| `action_id` | `string` | Action ID |
| `finding_id` | `string` | Finding identifier |
| `parsed_from` | `string` | `"output"` or `"file_path"` |
| `nodes_parsed` | `number` | Nodes extracted |
| `edges_parsed` | `number` | Edges extracted |
| `ingested` | `object?` | Ingestion results (present only when `ingest: true` and nodes > 0) |
| `warnings` | `string[]?` | Instrumentation warnings (e.g. missing action context) |
| `message` | `string` | Summary |

If a parser runs but extracts zero nodes and zero edges, `parse_output` now returns an MCP error because silent success is worse than an explicit "nothing was recognized" signal during an engagement. The response uses:

| Field | Value |
|-------|-------|
| `isError` | `true` |
| `parsed` | `false` |
| `ingested` | `false` |
| `parse_status` | `"no_data"` |

## Usage Notes

- Prefer this over `report_finding` when you have raw output from a supported tool
- Treat `parse_status: "no_data"` as an operator-visible parser failure or empty-output condition; verify the command output before reporting "nothing found"
- Set `ingest: false` to preview what would be parsed without modifying the graph
- Set `list_parsers: true` to get the current, authoritative list of supported parser names (the count grows as parsers are added)
- Pass `context` with `domain` and `source_host` when available — improves credential domain attribution and provenance
- See [parse_output vs report_finding](../playbook/parse-vs-report.md) for detailed guidance
