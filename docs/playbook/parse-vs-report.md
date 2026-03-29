# parse_output vs report_finding

When to use each tool for getting data into the graph.

## Decision Rule

```
Is the output from a supported parser?
  ├── Yes → use parse_output
  └── No  → use report_finding
```

## Use `parse_output` When

The raw output comes from one of these supported tools:

| Tool | Parser Names |
|------|-------------|
| Nmap | `nmap`, `nmap-xml` |
| NXC/NetExec | `nxc`, `netexec` |
| Certipy | `certipy` |
| Secretsdump | `secretsdump`, `impacket-secretsdump` |
| Kerbrute | `kerbrute` |
| Hashcat | `hashcat` |
| Responder | `responder` |
| Ldapsearch | `ldapsearch`, `ldapdomaindump`, `ldap` |
| Enum4linux | `enum4linux`, `enum4linux-ng` |
| Rubeus | `rubeus` |
| Web Dir Enum | `gobuster`, `feroxbuster`, `ffuf`, `dirbuster` |

### Why

- **Deterministic** — parsing is consistent and accurate
- **Token-efficient** — the LLM doesn't need to interpret raw output
- **Structured** — produces correctly typed nodes and edges
- **Auditable** — the raw output is preserved in the finding

### How

```json
{
  "tool_name": "nmap",
  "output": "<?xml version=\"1.0\"?>...",
  "agent_id": "agent-recon-01",
  "action_id": "act-abc123"
}
```

### With Context

For parsers that benefit from ambient context (secretsdump, hashcat), pass the `context` parameter:

```json
{
  "tool_name": "secretsdump",
  "output": "Administrator:500:aad3b...",
  "action_id": "act-dump-01",
  "context": { "domain": "corp.local", "source_host": "10.10.10.5" }
}
```

- **`domain`** — soft hint for `cred_domain` when output lacks domain prefixes
- **`source_host`** — creates `DUMPED_FROM` edges linking credentials to source

## Use `report_finding` When

- **Manual observations** — something you noticed that isn't tool output
- **Unsupported tools** — output from tools without a parser
- **Analyst judgment** — conclusions drawn from multiple data points
- **Already-structured data** — you already have nodes and edges to report

### How

```json
{
  "agent_id": "agent-manual",
  "action_id": "act-xyz789",
  "nodes": [
    {
      "id": "host-10-10-10-5",
      "type": "host",
      "label": "10.10.10.5",
      "properties": { "ip": "10.10.10.5", "os": "Windows Server 2019", "alive": true }
    }
  ],
  "edges": [
    {
      "source": "host-10-10-10-5",
      "target": "domain-target-local",
      "type": "MEMBER_OF_DOMAIN",
      "confidence": 1.0
    }
  ]
}
```

## Common Patterns

| Scenario | Tool |
|----------|------|
| Nmap scan completed | `parse_output` with `tool_name: "nmap"` |
| NXC SMB enumeration | `parse_output` with `tool_name: "nxc"` |
| Manual web app discovery | `report_finding` with host + service nodes |
| Certipy find results | `parse_output` with `tool_name: "certipy"` |
| Observed a login prompt | `report_finding` with service node |
| Secretsdump output | `parse_output` with `tool_name: "secretsdump"` + `context` |
| Custom script output | `report_finding` with structured nodes/edges |
| Hashcat cracked hashes | `parse_output` with `tool_name: "hashcat"` |
| Responder captured hash | `parse_output` with `tool_name: "responder"` |
| LDAP domain dump | `parse_output` with `tool_name: "ldapsearch"` |
| Enum4linux-ng JSON | `parse_output` with `tool_name: "enum4linux"` |
| Rubeus Kerberoast | `parse_output` with `tool_name: "rubeus"` |
| Gobuster/Feroxbuster scan | `parse_output` with `tool_name: "gobuster"` or `"feroxbuster"` |
| ffuf fuzzing results | `parse_output` with `tool_name: "ffuf"` |

## Tips

- Use `parse_output` with `list_parsers: true` to see the current list of supported parsers (32 aliases across 16 parsers)
- Use `parse_output` with `ingest: false` to preview what would be parsed without modifying the graph
- Always include `action_id` from `validate_action` for traceability
- Pass `context` with `domain` and `source_host` when available for better credential attribution
- Node IDs should follow conventions: `host-<ip>`, `svc-<ip>-<port>`, `user-<domain>-<name>`
