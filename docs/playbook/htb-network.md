# HTB / Network Lab Workflow

Step-by-step guide for a multi-host CIDR-scoped engagement like an HTB ProLab (Dante, Offshore, RastaLabs, etc.) or any network range where AD domains may be discovered organically.

## Prerequisites

- Target network accessible (VPN connected)
- Overwatch server configured with the target CIDR(s) in scope
- `"profile": "network"` set explicitly in `engagement.json` (required — unprofiled configs default to `single_host`)
- Claude Code connected to Overwatch

## Profile Semantics

The `network` profile is the middle ground between `single_host` and `goad_ad`:

- **CIDR-scoped**: One or more network ranges to sweep
- **Multi-host**: Expects multiple targets discovered via scanning
- **Domains not required**: AD may or may not be present; domains are discovered organically
- **BloodHound optional**: Not required upfront; useful once AD is confirmed
- **Credential warnings suppressed**: Domain-qualification warnings are hidden until AD context is actually discovered in the graph

## Step-by-Step

### 1. Run Lab Preflight

```
→ Call run_lab_preflight with profile: "network"
```

The network profile checks for nmap (required) and optional credential tools. It will not block on missing domains or BloodHound.

### 2. Sweep the Network

Run an initial Nmap sweep of the CIDR scope and parse results:

```
→ Call parse_output with tool_name: "nmap", output: "<nmap XML content>"
```

This creates host and service nodes across the range. The frontier will emit `network_discovery` items for partially explored CIDRs.

### 3. Enumerate Discovered Hosts

For each discovered host, use the frontier to guide enumeration:

```
→ Call next_task
→ Call validate_action
→ Execute the tool
→ Call parse_output or report_finding
```

Common early tools: nmap service scans, NXC/NetExec SMB enumeration, web directory scanning.

### 4. When AD Is Discovered

If SMB enumeration or service scanning reveals AD (domain controllers, Kerberos, LDAP):

- Domain nodes will be created automatically from parser output
- Credential domain-qualification warnings will **re-escalate** once AD context is detected
- Consider running BloodHound at this point for richer AD graph data:

```
→ Call ingest_bloodhound with path: "/path/to/bloodhound/output/"
```

### 5. Check State and Health

```
→ Call get_state
→ Call run_graph_health
```

Verify:

- Hosts and services are populating across the range
- Frontier items suggest reasonable next steps (service enumeration, credential testing)
- Health issues are relevant (not just domain-qualification noise)

### 6. Work the Engagement

Follow the main loop:

1. `next_task` — see frontier candidates
2. Score and prioritize them
3. `validate_action` — check before executing
4. Execute and report findings
5. Dispatch sub-agents for parallel work on independent hosts

## Tips

- **Network discovery frontier items** track how much of each CIDR has been explored; `fan_out_estimate` decreases as hosts are found
- **Credential warnings are context-aware**: unqualified credentials are expected early in network engagements and won't clutter the health report until AD is confirmed
- **Use `get_skill`** to look up methodology for discovered services
- **Pivot tracking**: As you compromise hosts and find credentials, the graph builds attack paths across the network automatically
- **Track long-running scans** with `track_process` and check with `check_processes`

## Example Config

The `engagement.json` at the repo root is a network-profile config for an HTB ProLab (Dante). See also `examples/` for cloud, web app, and hybrid engagement configs.
