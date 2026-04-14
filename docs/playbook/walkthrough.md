# End-to-End Walkthrough

A narrated example taking an engagement from empty graph to Domain Admin on a GOAD-like Active Directory lab.

## Phase 0 — Configuration

Create `engagement.json`:

```json
{
  "id": "eng-goad-001",
  "name": "GOAD Lab Assessment",
  "created_at": "2026-03-20T10:00:00Z",
  "scope": {
    "cidrs": ["192.168.56.0/24"],
    "domains": ["north.sevenkingdoms.local", "sevenkingdoms.local"],
    "exclusions": [],
    "hosts": []
  },
  "objectives": [
    {
      "id": "obj-da",
      "description": "Achieve Domain Admin on sevenkingdoms.local",
      "target_node_type": "credential",
      "target_criteria": { "privileged": true, "cred_domain": "sevenkingdoms.local" },
      "achieved": false
    }
  ],
  "opsec": {
    "name": "ctf",
    "max_noise": 1.0,
    "blacklisted_techniques": [],
    "notes": "Lab environment. No restrictions."
  }
}
```

Start the server and connect Claude Code:

```bash
claude
```

## Phase 1 — Bootstrap

### Get State

The primary session starts by loading the engagement briefing:

```
→ Call get_state
```

Response includes the scope, empty graph, and zero frontier items. The graph has been seeded with CIDR scope nodes.

### Lab Preflight

```
→ Call run_lab_preflight with profile: "goad_ad"
```

Verifies:

- Engagement config is valid
- Tools installed: nmap, nxc, impacket-*, bloodhound-python, certipy, hashcat
- Graph is healthy (0 nodes, 0 edges — expected for a fresh start)
- Dashboard is running on `http://localhost:8384`

### Check Tools

```
→ Call check_tools
```

Returns a list of offensive tools found on `$PATH` with version info. Missing tools get warnings but don't block the engagement.

**Graph state:** 0 nodes, 0 edges, 0 frontier items.

## Phase 2 — Discovery

### Nmap Scan

The LLM validates and executes a port scan:

```
→ Call validate_action with:
  description: "Full TCP port scan of 192.168.56.0/24"
  technique: "portscan"
```

Returns `action_id: "act-001"`, `valid: true`.

```
→ Call log_action_event with:
  action_id: "act-001"
  event_type: "action_started"
```

The LLM runs nmap and parses the results:

```
→ Call parse_output with:
  tool_name: "nmap"
  output: "<?xml version='1.0'?>
    <nmaprun>
      <host><address addr='192.168.56.10'/><ports>
        <port portid='88'><state state='open'/><service name='kerberos-sec'/></port>
        <port portid='389'><state state='open'/><service name='ldap'/></port>
        <port portid='445'><state state='open'/><service name='microsoft-ds'/></port>
      </ports></host>
      <host><address addr='192.168.56.11'/><ports>
        <port portid='445'><state state='open'/><service name='microsoft-ds'/></port>
        <port portid='1433'><state state='open'/><service name='ms-sql-s'/></port>
      </ports></host>
      <host><address addr='192.168.56.12'/><ports>
        <port portid='80'><state state='open'/><service name='http'/></port>
        <port portid='445'><state state='open'/><service name='microsoft-ds'/></port>
      </ports></host>
    </nmaprun>"
  agent_id: "primary"
  action_id: "act-001"
```

**Parser output:**

```json
{
  "parsed": true,
  "nodes_parsed": 9,
  "edges_parsed": 6,
  "ingested": {
    "new_nodes": ["host-192-168-56-10", "svc-192-168-56-10-88", "svc-192-168-56-10-389",
                  "svc-192-168-56-10-445", "host-192-168-56-11", "svc-192-168-56-11-445",
                  "svc-192-168-56-11-1433", "host-192-168-56-12", "svc-192-168-56-12-80"],
    "new_edges": 6,
    "inferred_edges": 3
  }
}
```

Inference rules fired automatically:

- **Kerberos → Domain**: `svc-192-168-56-10-88` → `MEMBER_OF_DOMAIN` edge created
- **MSSQL + Domain**: `svc-192-168-56-11-1433` → `POTENTIAL_AUTH` edges from future domain creds

```
→ Call log_action_event with:
  action_id: "act-001"
  event_type: "action_completed"
```

**Graph state:** 9 nodes, 9 edges (6 RUNS + 3 inferred), 12+ frontier items.

**Dashboard:** Three host nodes appear with service clusters. Inferred edges shown as dashed lines.

## Phase 3 — SMB Enumeration

### Check Frontier

```
→ Call next_task with max_items: 10
```

Returns candidates including:

- "Enumerate SMB on 192.168.56.10:445" (`incomplete_node`)
- "Enumerate SMB on 192.168.56.11:445" (`incomplete_node`)
- "Enumerate HTTP on 192.168.56.12:80" (`incomplete_node`)

The LLM scores them — SMB on the DC (56.10) is highest priority because Kerberos indicates it's a domain controller.

### NXC SMB Enumeration

```
→ Call validate_action with:
  description: "SMB enumeration with null session on 192.168.56.10"
  target_node: "svc-192-168-56-10-445"
  technique: "smb_enum"

→ Call log_action_event with action_id: "act-002", event_type: "action_started"
```

The LLM runs `nxc smb 192.168.56.10 --shares -u '' -p ''` and parses:

```
→ Call parse_output with:
  tool_name: "nxc"
  output: "SMB  192.168.56.10  445  WINTERFELL  [*] Windows Server 2019 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB  192.168.56.10  445  WINTERFELL  [+] Enumerated shares
SMB  192.168.56.10  445  WINTERFELL  Share    Permissions  Remark
SMB  192.168.56.10  445  WINTERFELL  -----   -----------  ------
SMB  192.168.56.10  445  WINTERFELL  SYSVOL  READ         Logon server share
SMB  192.168.56.10  445  WINTERFELL  NETLOGON READ        Logon server share"
  agent_id: "primary"
  action_id: "act-002"
```

New nodes: host updated with hostname `WINTERFELL`, domain `north.sevenkingdoms.local`, share nodes created.

**Graph state:** 13 nodes, 15 edges, frontier growing.

## Phase 4 — BloodHound Ingestion

If bloodhound-python data is available, bulk import it:

```
→ Call ingest_bloodhound with:
  path: "/tmp/bloodhound-output/"
```

This ingests users, groups, computers, ACLs, sessions, and local admin relationships. A typical GOAD lab produces ~50-100 nodes and ~200-500 edges.

**Graph state:** ~80 nodes, ~300 edges. Frontier explodes with inferred edges.

**Dashboard:** The graph now shows clear AD structure — domain controllers as large central nodes, users clustered around groups, credential edges fanning out.

## Phase 5 — Kerberoasting

### Frontier Shows the Path

```
→ Call next_task
```

The LLM spots a Kerberoastable service account in the BloodHound data. Frontier item: "Test Kerberoast against user-north-sql_svc" (`inferred_edge`, confidence: 0.5).

### Execute Kerberoast

```
→ Call validate_action with:
  description: "Kerberoast sql_svc on north.sevenkingdoms.local"
  target_node: "user-north-sql_svc"
  technique: "kerberoast"

→ Call log_action_event with action_id: "act-005", event_type: "action_started"
```

The LLM runs `impacket-GetUserSPNs` and gets a TGS hash. Then cracks it:

```
→ Call parse_output with:
  tool_name: "hashcat"
  output: "$krb5tgs$23$*sql_svc$NORTH.SEVENKINGDOMS.LOCAL$...:Password123!"
  agent_id: "primary"
  action_id: "act-005"
```

**New nodes created:**

- `cred-plaintext-sql_svc` (type: credential, cred_type: plaintext, cred_value: Password123!)

**Inference rules fire:**

- **Credential Fanout** → `POTENTIAL_AUTH` edges to every compatible service (SMB, MSSQL, WinRM)

```
→ Call log_action_event with action_id: "act-005", event_type: "action_completed"
```

**Graph state:** ~85 nodes, ~320 edges. New credential node with fan-out to all services.

**Dashboard:** Credential node pulses briefly (new node animation). Amber `POTENTIAL_AUTH` edges fan out to multiple services.

## Phase 6 — Lateral Movement

### Agent Dispatch

The frontier now shows `POTENTIAL_AUTH` edges to multiple services. The LLM dispatches sub-agents for parallel testing:

```
→ Call register_agent with:
  agent_id: "agent-lateral-smb"
  frontier_item_id: "fi-potential-auth-sql-svc-445"
  skill: "lateral-movement"
```

```
→ Call register_agent with:
  agent_id: "agent-lateral-mssql"
  frontier_item_id: "fi-potential-auth-sql-svc-1433"
  skill: "lateral-movement"
```

Each sub-agent:

1. Calls `get_agent_context` → scoped subgraph with the credential and target service
2. Calls `get_skill` with `query: "lateral movement"` → methodology
3. Validates and executes authentication test
4. Reports findings

**Agent A finds:** `sql_svc` has admin on `192.168.56.11` via SMB → reports `ADMIN_TO` edge (confidence: 1.0)

**Agent B finds:** `sql_svc` authenticates to MSSQL → reports `VALID_ON` edge (confidence: 1.0)

### Primary Monitors

```
→ Call get_state
```

The primary session sees new frontier items from agent findings:

- "DCSync via sql_svc on WINTERFELL" (if sql_svc has replication rights)
- "Dump credentials on 192.168.56.11" (has ADMIN_TO)
- "MSSQL command execution on 192.168.56.11" (has VALID_ON to MSSQL)

## Phase 7 — Privilege Escalation

### Secretsdump

```
→ Call validate_action with:
  description: "Secretsdump on 192.168.56.11 with sql_svc creds"
  target_node: "host-192-168-56-11"
  technique: "credential_dumping"

→ Call log_action_event with action_id: "act-010", event_type: "action_started"
```

The LLM runs `impacket-secretsdump` and parses:

```
→ Call parse_output with:
  tool_name: "secretsdump"
  output: "Administrator:500:aad3b435...:8846f7eaee8fb117...:::
Guest:501:aad3b435...:31d6cfe0d16ae931...:::
sql_svc:1001:aad3b435...:a87f3a337d73085...:::"
  agent_id: "primary"
  action_id: "act-010"
```

**New credentials created:** Local admin NTLM hashes. Credential Fanout fires again → more `POTENTIAL_AUTH` edges.

### DCSync

With the right privileges (or after finding a path to Domain Admin):

```
→ Call parse_output with:
  tool_name: "secretsdump"
  output: "north.sevenkingdoms.local\\Administrator:500:aad3b435...:b8a3f328b...:::
north.sevenkingdoms.local\\krbtgt:502:aad3b435...:9d765b48...:::"
  agent_id: "primary"
  action_id: "act-012"
```

**Objective achieved!** The engine matches `cred-ntlm-administrator` against the objective criteria (`privileged: true`, `cred_domain: sevenkingdoms.local`) and marks `obj-da` as achieved.

**Graph state:** ~100 nodes, ~400 edges. Objective node turns green in the dashboard.

## Phase 8 — Retrospective

```
→ Call run_retrospective with write_to_disk: true
```

Generates:

| File | Contents |
|------|----------|
| `report.md` | Timeline of the attack path: discovery → Kerberoast → lateral → DCSync |
| `inference-suggestions.json` | "MSSQL service on domain host often has xp_cmdshell enabled" |
| `skill-gaps.json` | ADCS skills unused (no certificates found), web skills unused |
| `context-improvements.json` | "Consider running BloodHound earlier for faster path discovery" |
| `training-traces.json` | 12 state→action→outcome traces for RLVR |

## Key Takeaways

- **Report early, report often** — each `report_finding` triggered inference rules that surfaced the next step
- **Parsers save tokens** — `parse_output` handled nmap, nxc, hashcat, and secretsdump without LLM interpretation
- **Inference chains compound** — SMB scan → credential fanout → lateral movement path appeared automatically
- **Sub-agents parallelize** — two services tested simultaneously instead of sequentially
- **The graph tells the story** — the retrospective reconstructed the full attack path from graph state
