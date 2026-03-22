# GOAD AD Lab Workflow

Step-by-step guide for a first run against a GOAD (Game of Active Directory) or Proxmox AD lab.

## Prerequisites

- GOAD lab running and network-accessible
- Overwatch server configured with the lab's scope (CIDRs, domains)
- Claude Code connected to Overwatch

## Step-by-Step

### 1. Verify Environment

Start the MCP server and confirm Claude can connect:

```
→ Call get_state
```

Verify the scope shows your lab's CIDR and domain.

### 2. Run Lab Preflight

```
→ Call run_lab_preflight with profile: "goad_ad"
```

This checks:

- Engagement config is valid
- Required tools are installed (nmap, nxc, impacket, bloodhound-python, certipy, etc.)
- Graph health is clean
- Dashboard is accessible
- Persistence is working

!!! warning "Blocked status"
    If the preflight returns `blocked`, resolve the missing tools or config issues before continuing.

### 3. Ingest BloodHound Data

If you have SharpHound or bloodhound-python output:

```
→ Call ingest_bloodhound with path: "/path/to/bloodhound/output/"
```

This populates the graph with AD structure — users, groups, computers, ACLs, sessions, and local admins. Inference rules fire automatically.

### 4. Parse Nmap Results

If you have Nmap XML output:

```
→ Call parse_output with tool_name: "nmap", output: "<nmap XML content>"
```

This creates host and service nodes with `RUNS` edges.

### 5. Parse NXC Results

If you have NXC/NetExec output:

```
→ Call parse_output with tool_name: "nxc", output: "<nxc output>"
```

This creates host, service, and share nodes with access edges.

### 6. Verify Graph Health

```
→ Call get_state
→ Call run_graph_health
```

Confirm:

- Nodes and edges were created as expected
- No critical health issues
- Frontier items are populated

### 7. Check the Dashboard

Open `http://localhost:8384` to visually inspect:

- Graph structure and node layout
- Frontier items in the side panel
- Objectives and progress

### 8. Test Persistence

Restart the server once and verify the engagement resumes cleanly:

```
→ Call get_state
```

The graph should match pre-restart state exactly.

### 9. Enter the Main Loop

Now start the main engagement loop:

1. Call `next_task` to see frontier candidates
2. Score and prioritize them
3. Validate with `validate_action`
4. Execute and report findings
5. Dispatch sub-agents for parallel work

## Tips

- **Report early, report often** — every `report_finding` triggers inference rules that may surface new attack paths
- **Use `parse_output`** for supported tools to keep parsing deterministic
- **Monitor the dashboard** for visual context on graph growth
- **Run `run_graph_health`** periodically, especially after large ingestions
- **Dispatch sub-agents** for independent tasks to parallelize work
