# Subnet Enumeration

Methodology for sub-agents assigned to enumerate a specific CIDR subnet.

## Prerequisites

- Assigned via `dispatch_subnet_agents` or `register_agent` with a `network_discovery` frontier item
- Target CIDR available in agent context

## Workflow

1. **Get context**: Call `get_agent_context` with your task ID to receive the target CIDR and any already-discovered nodes in the subnet.

2. **Validate sweep**: Call `validate_action` with:
   - `action_type`: `network_scan`
   - `target_ip`: representative IP or CIDR from context
   - `technique`: `nmap-sweep`

3. **Execute nmap sweep**: Run a host-discovery scan of the assigned CIDR:
   ```
   nmap -sn <CIDR> -oX -
   ```
   For service enumeration on discovered hosts:
   ```
   nmap -sV -sC -T4 --top-ports 1000 <CIDR> -oX -
   ```

4. **Parse results**: Use `parse_output` with tool `nmap` and the raw XML output. This will:
   - Create host nodes for alive hosts
   - Create service nodes for open ports
   - Create RUNS edges between hosts and services
   - Hosts with no services will be stored in the cold census (graph compaction)

5. **Enumerate interesting services**: For each host with interesting services:
   - **SMB (445)**: `nmap --script smb-enum-shares,smb-os-discovery -p445 <IP>`
   - **HTTP (80/443)**: `nmap --script http-title,http-methods -p80,443 <IP>`
   - **SSH (22)**: Note version for vuln checks
   - **MSSQL (1433)**: `nmap --script ms-sql-info -p1433 <IP>`
   - Parse each result with `parse_output`

6. **Report findings**: Use `report_finding` for any observations that parsers don't cover:
   - Unusual services or banners
   - Potential vulnerabilities spotted manually
   - Network segmentation observations

7. **Complete task**: Call `update_agent` with `status: completed` and a brief summary of:
   - Hosts discovered (alive count)
   - Services found
   - Notable findings

## OPSEC Notes

- Use `-T3` or lower if stealth is required (check engagement OPSEC profile)
- Avoid aggressive scripts (`--script vuln`) unless explicitly authorized
- Stay within your assigned CIDR — do not scan adjacent subnets

## Cold Store Interaction

Hosts that respond to ping but have no open ports will be stored in the cold census
rather than the hot graph. This keeps the active graph focused on actionable targets.
If a later scan reveals services on a cold host, it will be automatically promoted
to the hot graph.
