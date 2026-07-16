# Overwatch

An offensive security engagement orchestrator built as an MCP server. The persistent state layer and reasoning substrate for LLM-powered penetration testing.

It runs as a **multi-agent operator cockpit**: a human operator drives a primary reasoning model, dispatches headless sub-agents, steers and talks to them in natural language, watches everything live, and answers questions agents escalate — all from the dashboard's Operator console. Every operator action routes through the same validated engine path, so OPSEC/scope/approval guards always apply. See [Operator Cockpit](docs/operator-cockpit.md).

## Quick Start

```bash
git clone https://github.com/professor-moody/overwatch.git
cd overwatch
npm install
npm run setup -- --daemon --template ctf --name "My Lab" --cidr 10.10.10.0/24
npm run build
npm run doctor
npm run start:daemon
```

> **Note:** `node-pty` is an optional native dependency used for local PTY sessions. It requires native build tools (Python 3, C++ compiler). If it fails to install, the rest of Overwatch works normally — only `local_pty` sessions will be unavailable.

`npm run setup -- --daemon` creates local-only `.mcp.json`,
`.overwatch-mcp-token`, `.claude/settings.json`, and
`engagement.json` files with absolute paths and a fresh engagement nonce. The
live graph state persists separately to `state-<engagement-id>.json` beside the
config unless `OVERWATCH_STATE_FILE` is set.

Leave the daemon running, open `http://127.0.0.1:8384`, and run `claude` in
another terminal. Claude, the dashboard, the `overwatch` CLI, and dispatched
agents then share one engine and one engagement without competing writers.

For a solo Claude-only session, omit `--daemon`; setup retains the compatible
stdio configuration where Claude launches and owns Overwatch itself.

If you create a solo stdio config manually, `.mcp.json` should use absolute paths:

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

Then run `claude`. `.claude/settings.json` enables hooks that keep Claude using
Overwatch instead of drifting into raw target-facing Bash. See the full
[Getting Started](https://professor-moody.github.io/overwatch/getting-started/)
guide.

## Documentation

**[professor-moody.github.io/overwatch](https://professor-moody.github.io/overwatch/)** — architecture, configuration, 83 MCP tools, graph model, inference rules, skills library, operator playbook, and development guide.

## Disclaimer

This tool is designed for authorized security testing only. Do not run against production systems without explicit written authorization.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
