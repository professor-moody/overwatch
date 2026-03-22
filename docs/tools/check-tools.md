# check_tools

Check which offensive security tools are installed on the system.

**Read-only:** Yes

## Description

Returns a list of common pentest tools with their installation status, version, and path. Useful for planning what techniques are available without trial-and-error.

Tools checked include: nmap, nxc/netexec, certipy, impacket suite, bloodhound-python, gobuster/feroxbuster, ldapsearch, smbclient, rpcclient, john, hashcat, responder, enum4linux-ng, kerbrute.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tool_name` | `string` | — | Check a specific tool by name. Omit to check all tools. |

## Returns

When checking all tools:

| Field | Type | Description |
|-------|------|-------------|
| `installed_count` | `number` | Number of installed tools |
| `missing_count` | `number` | Number of missing tools |
| `installed` | `array` | Installed tools with name, version, and path |
| `missing` | `string[]` | Names of tools not found |

When checking a specific tool:

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Tool name |
| `installed` | `boolean` | Whether it's installed |
| `version` | `string` | Version string (if installed) |
| `path` | `string` | Binary path (if installed) |

## Usage Notes

- Run at the start of an engagement to know what's available
- Used by `run_lab_preflight` to validate tool availability for lab profiles
- If a critical tool is missing, install it before proceeding with dependent techniques
