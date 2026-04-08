# Overwatch

An offensive security engagement orchestrator built as an MCP server. The persistent state layer and reasoning substrate for LLM-powered penetration testing.

## Quick Start

```bash
git clone https://github.com/keys/overwatch.git
cd overwatch
npm install
npm run build
```

Add to your Claude Code MCP config:

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

Then run `claude` — see the full [Getting Started](https://keys.github.io/overwatch/getting-started/) guide.

## Documentation

**[keys.github.io/overwatch](https://keys.github.io/overwatch/)** — architecture, configuration, 40 MCP tools, graph model, inference rules, skills library, operator playbook, and development guide.

## Disclaimer

This tool is designed for authorized security testing only. Do not run against production systems without explicit written authorization.
