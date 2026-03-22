# Getting Started

## Prerequisites

- **Node.js 20+**
- **Claude Code CLI** (`claude` command)

## Install

```bash
git clone https://github.com/keys/overwatch.git
cd overwatch
npm install
npm run build
```

## Configure an Engagement

Create or edit `engagement.json` in the project root:

```json
{
  "id": "eng-001",
  "name": "Internal Pentest - Target Corp",
  "created_at": "2026-03-20T00:00:00Z",
  "scope": {
    "cidrs": ["10.10.10.0/24"],
    "domains": ["target.local"],
    "exclusions": ["10.10.10.254"],
    "hosts": []
  },
  "objectives": [
    {
      "id": "obj-da",
      "description": "Achieve Domain Admin on target.local",
      "target_node_type": "credential",
      "target_criteria": { "privileged": true, "cred_domain": "target.local" },
      "achieved": false
    }
  ],
  "opsec": {
    "name": "pentest",
    "max_noise": 0.7,
    "blacklisted_techniques": ["zerologon"],
    "notes": "Standard internal pentest."
  }
}
```

See [Configuration](configuration.md) for the full schema reference.

## Connect to Claude Code

Add Overwatch as an MCP server in your Claude Code config (`~/.claude/settings.json` or project-level `.claude/settings.json`):

```json
{
  "mcpServers": {
    "overwatch": {
      "command": "node",
      "args": ["<path-to-overwatch>/dist/index.js"],
      "env": {
        "OVERWATCH_CONFIG": "<path-to-engagement.json>",
        "OVERWATCH_SKILLS": "<path-to-overwatch>/skills"
      }
    }
  }
}
```

## Run

```bash
claude
```

Claude Code will connect to the Overwatch MCP server automatically. The `AGENTS.md` file in the project root provides the primary session instructions. Claude will call `get_state()` first to load the engagement briefing, then enter the main scoring loop.

## Verify Setup

Once connected, ask Claude to:

1. Call `get_state` — confirms the server is running and the engagement is loaded
2. Call `run_lab_preflight` — validates tool availability, graph health, and dashboard readiness
3. Call `check_tools` — shows which offensive tools are installed

If all three succeed, you're ready to start. See the [Operator Playbook](playbook/index.md) for step-by-step lab workflows.
