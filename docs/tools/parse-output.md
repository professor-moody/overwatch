# parse_output

Parse raw output from common offensive tools into structured graph data.

**Read-only:** No

## Description

Deterministically parses tool output into structured findings and (optionally) ingests them into the graph. This reduces LLM token cost by handling structured parsing without LLM involvement.

### Supported Parsers

| Parser | Aliases | Input Format | Produces |
|--------|---------|--------------|----------|
| **Nmap** | `nmap`, `nmap-xml` | Nmap XML output | Host + service nodes, `RUNS` edges |
| **NXC/NetExec** | `nxc`, `netexec` | NXC text output | Host + SMB service nodes, share nodes, access edges |
| **Certipy** | `certipy` | Certipy JSON output | Certificate nodes, enrollment edges, ESC edges |
| **Secretsdump** | `secretsdump`, `impacket-secretsdump` | SAM/NTDS hashes | Credential + user nodes, `OWNS_CRED` edges |
| **Kerbrute** | `kerbrute` | User enum + spray output | User + domain + credential nodes |
| **Hashcat** | `hashcat` | Cracked hashes (NTLM, Kerberoast, AS-REP, NTLMv2) | Credential nodes |
| **Responder** | `responder` | Captured NTLMv2 hashes | Credential + user + host nodes |

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tool_name` | `string` | Yes | Name of the tool (e.g., `nmap`, `nxc`, `certipy`) |
| `output` | `string` | Yes | Raw tool output to parse |
| `agent_id` | `string` | No | Agent ID to attribute findings to |
| `action_id` | `string` | No | Stable action ID for linkage |
| `frontier_item_id` | `string` | No | Frontier item this parse came from |
| `ingest` | `boolean` | No | Auto-ingest into graph (default: `true`) |
| `list_parsers` | `boolean` | No | List all supported parser names (default: `false`) |

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
- Set `list_parsers: true` to get the current list of supported parser names
- See [parse_output vs report_finding](../playbook/parse-vs-report.md) for detailed guidance
