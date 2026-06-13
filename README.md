# Overwatch

An offensive security engagement orchestrator built as an MCP server. The persistent state layer and reasoning substrate for LLM-powered penetration testing.

## Quick Start

```bash
git clone https://github.com/professor-moody/overwatch.git
cd overwatch
npm install
npm run setup -- --template ctf --name "My Lab" --cidr 10.10.10.0/24
npm run build
npm run doctor
```

> **Note:** `node-pty` is an optional native dependency used for local PTY sessions. It requires native build tools (Python 3, C++ compiler). If it fails to install, the rest of Overwatch works normally — only `local_pty` sessions will be unavailable.

`npm run setup` creates local-only `.mcp.json`, `.claude/settings.json`, and
`engagement.json` files with absolute paths and a fresh engagement nonce. The
live graph state persists separately to `state-<engagement-id>.json` beside the
config unless `OVERWATCH_STATE_FILE` is set.

If you create config files manually, `.mcp.json` should use absolute paths:

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

Then run `claude`. `.mcp.json` starts Overwatch; `.claude/settings.json` enables hooks that keep Claude using Overwatch instead of drifting into raw target-facing Bash. See the full [Getting Started](https://professor-moody.github.io/overwatch/getting-started/) guide.

## Documentation

**[professor-moody.github.io/overwatch](https://professor-moody.github.io/overwatch/)** — architecture, configuration, 60+ MCP tools, graph model, inference rules, skills library, operator playbook, and development guide.

## Disclaimer

This tool is designed for authorized security testing only. Do not run against production systems without explicit written authorization.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
