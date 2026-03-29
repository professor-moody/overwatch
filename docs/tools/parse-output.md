# parse_output

Parse raw output from common offensive tools into structured graph data.

**Read-only:** No

## Description

Deterministically parses tool output into structured findings and (optionally) ingests them into the graph. This reduces LLM token cost by handling structured parsing without LLM involvement.

### Supported Parsers

| Parser | Aliases | Input Format | Produces |
|--------|---------|--------------|----------|
| **Nmap** | `nmap`, `nmap-xml` | Nmap XML output | Host + service nodes, `RUNS` edges, OS detection |
| **NXC/NetExec** | `nxc`, `netexec` | NXC text output | Host + SMB service nodes, share nodes, user nodes, access edges, `NULL_SESSION` edges |
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
| **Nuclei** | `nuclei` | JSON or text output | Vulnerability nodes, `VULNERABLE_TO` edges |
| **Nikto** | `nikto` | Text output | Web vulnerability findings |
| **TestSSL** | `testssl`, `testssl.sh`, `sslscan` | Text or JSON output | TLS enrichment: version, cipher suites, certificate details |
| **Pacu** | `pacu` | JSON output | Cloud identity + resource + policy nodes, `HAS_POLICY` / `ASSUMES_ROLE` edges |
| **Prowler** | `prowler`, `scoutsuite` | JSON output | Cloud resource + policy nodes, security findings |

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

| Field | Type | Description |
|-------|------|-------------|
| `parsed` | `boolean` | Whether parsing succeeded |
| `tool` | `string` | Tool name |
| `action_id` | `string` | Action ID |
| `finding_id` | `string` | Finding identifier |
| `nodes_parsed` | `number` | Nodes extracted |
| `edges_parsed` | `number` | Edges extracted |
| `ingested` | `object` | Ingestion results (if `ingest: true`) |
| `message` | `string` | Summary |

## Usage Notes

- Prefer this over `report_finding` when you have raw output from a supported tool
- Set `ingest: false` to preview what would be parsed without modifying the graph
- Set `list_parsers: true` to get the current list of supported parser names (31 aliases across 17 parsers)
- Pass `context` with `domain` and `source_host` when available — improves credential domain attribution and provenance
- See [parse_output vs report_finding](../playbook/parse-vs-report.md) for detailed guidance
