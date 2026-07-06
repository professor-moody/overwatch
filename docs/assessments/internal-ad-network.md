# Internal AD / Network Assessment

**Scenario:** you're on the internal network (or have a foothold) with one or more **CIDR ranges**, maybe a **domain**, and a **test domain account** in scope. This guide takes you from that hand-off to a credential-driven internal assessment.

!!! tip "New to Overwatch?"
    Do the [Quick Start](../getting-started.md#quick-start-5-minutes) first. This guide assumes `claude` is connected and the dashboard is open. For lab-specific walkthroughs, see [HTB / Network](../playbook/htb-network.md) and the [GOAD AD Lab](../playbook/goad-lab.md).

!!! note "Tools you'll want"
    `nmap`, `nxc` (NetExec / CrackMapExec), `bloodhound-python`, `impacket` (secretsdump, GetUserSPNs), `ldapsearch`, `certipy`. Install the AD/network group from [Prerequisites](../prerequisites.md); confirm with `check_tools`.

---

## 1. Scope it

Scope by CIDR (and domain, if you know it). Use the `internal-pentest` template (`goad_ad` profile, Domain Admin objectives) when AD is the focus, or set `profile: network` when AD may or may not be present:

```bash
npm run setup -- --template internal-pentest --name "Acme Internal" --cidr 10.10.0.0/16 --domain corp.acme.local
```

```jsonc
{
  "profile": "network",          // or "goad_ad" if you already know the domain
  "scope": {
    "cidrs": ["10.10.0.0/16"],
    "domains": ["acme.local"],   // leave [] to let AD be discovered
    "exclusions": []
  }
}
```

!!! important "Pick the right profile"
    `network` is the middle ground — multi-host, AD-optional (domain warnings suppressed until AD is discovered). `goad_ad` expects a domain and blocks preflight if it's missing. `single_host` is for one box. See [HTB / Network](../playbook/htb-network.md#why-network-matters) for the trade-offs.

## 2. Seed the network

Sweep the scope and ingest, so hosts/services/domains land in the graph:

> **"Run preflight for the network profile, sweep the scope with nmap, ingest it, then work the frontier."**

As DCs, Kerberos, and LDAP show up, `domain` nodes appear automatically and inference rules start firing.

## 3. Add your test domain account

Add the provided credential as a `credential` node — `ingest_json` for a batch, or describe it and let Claude call `report_finding`:

> **"Add a test credential: domain user `acme.local\svc_test` / `Winter2025!`."**

Key fields for an AD credential:

| Field | Meaning |
|-------|---------|
| `cred_user` | the account (`svc_test`) |
| `cred_domain` | the domain (`acme.local` / `ACME`) — drives the same-domain match |
| `cred_value` | the password / hash (redacted in client reports) |
| `cred_type` / `cred_material_kind` | `plaintext` / `plaintext_password`, `ntlm` / `ntlm_hash`, `kerberos_tgt`, … |
| `cred_evidence_kind` | `manual` for operator-provided |

## 4. Enumerate WITH the account

With the credential and the swept hosts in the graph, the **credential-coverage frontier** surfaces the pairings to test — `get_state` / `next_task` list `credential_test` items like *"Test svc_test against DC01 (ldap)"*, prioritized by service value, hops-to-objective, and a same-domain boost.

> **"What credential tests are on the frontier? Run the highest-priority ones with the test account."**

Claude runs the credential-consuming tools (scope-checked, secret auto-redacted from the activity log) and ingests results:

- `nxc smb/ldap/winrm <host> -u svc_test -p '...'` → `VALID_ON` / access edges, shares, sessions, LSA/SAM dumps
- `ldapsearch` / `nxc --users` → domain users, groups, descriptions
- `GetUserSPNs` / Kerberoast, AS-REP roast → hashes (feed back as new credentials — spray loop)

The `goad_ad` profile guidance sequences this: enumerate → Kerberoast/ASREP → spray → lateral → DCSync, re-evaluating auth after every new credential.

## 5. Map the graph, then paths

Run BloodHound from a foothold with the account and ingest it:

> **"Run BloodHound collection as svc_test and ingest it."**

`ingest_bloodhound` populates users/groups/ACLs/sessions/local-admins; inference rules flag Kerberoastable, AS-REP-roastable, GenericAll, DCSync rights, and ADCS ESC1–13. High-value targets get tagged, and cross-tier enrichment links captured creds to what they can reach. Then:

> **"Show me a path from svc_test to Domain Admin — what's the missing step?"**

`find_paths` returns the chain and the AI explains the gap.

## 6. Report

> **"Generate a client-safe report."**

`generate_report` renders findings + attack paths with credential material redacted (sha256 fingerprints retained for cross-referencing).

## See also

- [HTB / Network](../playbook/htb-network.md) and [GOAD AD Lab](../playbook/goad-lab.md) — lab-specific walkthroughs and AD tactics
- [Web Assessment](web-assessment.md) — for the web tier of a hybrid engagement
- [Operator Infrastructure](../playbook/operator-infra.md) — Responder / relay during the sweep
- [End-to-End Walkthrough](../playbook/walkthrough.md) — a fully narrated engagement
