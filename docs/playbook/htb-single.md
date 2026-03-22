# HTB / Single Host Workflow

Step-by-step guide for a single-target workflow like a Hack The Box machine or standalone VM.

## Prerequisites

- Target host accessible
- Overwatch server configured with the target's IP in scope
- Claude Code connected to Overwatch

## Step-by-Step

### 1. Run Lab Preflight

```
→ Call run_lab_preflight with profile: "single_host"
```

The single-host profile checks for basic reconnaissance tools (nmap, gobuster/feroxbuster, etc.) and validates the engagement config.

### 2. Parse Nmap Results

Run your initial port scan and parse the results:

```
→ Call parse_output with tool_name: "nmap", output: "<nmap XML content>"
```

This creates the host node and service nodes with `RUNS` edges.

### 3. Report Initial Findings

For any manual observations or unsupported tool output, use `report_finding`:

```
→ Call report_finding with nodes and edges describing what you found
```

Prefer `parse_output` for supported tools; use `report_finding` for manual observations.

### 4. Check State and Health

```
→ Call get_state
→ Call next_task
→ Call run_graph_health
```

Verify:

- Host and services are in the graph
- Frontier items suggest reasonable next steps
- No health issues

### 5. Test Persistence

Verify a restart/load round-trip before relying on the workflow for longer sessions:

```
→ Restart server
→ Call get_state
```

### 6. Work the Target

Follow the main loop:

1. `next_task` — see what to enumerate/exploit next
2. `validate_action` — check before executing
3. Execute the tool
4. `parse_output` or `report_finding` — ingest results
5. Repeat

## Tips

- For single hosts, the graph will be smaller but the same patterns apply
- Use `get_skill` to look up methodology for discovered services
- The frontier will suggest service-specific enumeration based on discovered ports
- Track long-running scans with `track_process` and check with `check_processes`
