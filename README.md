# Overwatch

An offensive security engagement orchestrator built as an MCP server. The persistent state layer and reasoning substrate for LLM-powered penetration testing.

It runs as a **multi-agent operator cockpit**: a human operator drives a primary reasoning model, dispatches headless sub-agents, steers and talks to them in natural language, watches everything live, and answers questions agents escalate — all from the dashboard's Operator console. Every operator action routes through the same validated engine path, so OPSEC/scope/approval guards always apply. See [Operator Cockpit](docs/operator-cockpit.md).

## Quick Start

```bash
git clone https://github.com/professor-moody/overwatch.git
cd overwatch
npm install
npm run setup -- --template ctf --name "My Lab" --cidr 10.10.10.0/24
npm run build
npm run doctor
npm run start:daemon
```

> **Note:** `node-pty` is an optional native dependency used for local PTY sessions. It requires native build tools (Python 3, C++ compiler). If it fails to install, the rest of Overwatch works normally — only `local_pty` sessions will be unavailable.

`npm run setup` defaults to the shared daemon and creates local-only `.mcp.json`,
`.overwatch-mcp-token`, `.claude/settings.json`, and
`engagement.json`, wiring them to the local checkout with a fresh engagement nonce. The
live graph state persists separately to `state-<engagement-id>.json` beside the
config unless `OVERWATCH_STATE_FILE` is set.

The pre-start `npm run doctor` may warn that the shared daemon is not running
yet; that is expected on a first launch. Leave `npm run start:daemon` running,
open `http://127.0.0.1:8384`, and run `claude` in another terminal. You can run
`npm run doctor` again there to verify the live daemon and local build match.

There is exactly **one Overwatch runtime owner**. Terminal Claude connects to
that daemon over MCP; the browser dashboard and `overwatch` CLI use its API;
dashboard-deployed Claude workers connect back to it with task-specific MCP
credentials and leases. The workers do not inherit this checkout's project
Claude settings, hooks, MCP servers, or resumable terminal session. They keep
Claude's user settings only for authentication. This lets you keep using Claude
interactively in your terminal while the dashboard deploys agents, without
starting a second engine or mixing their sessions.

After later pulls, `npm run start:daemon` checks whether the compiled runtime
matches the checkout and rebuilds it automatically when needed, so an old
dashboard or planner cannot silently start from stale `dist` files. If the
dashboard says **Disconnected**, a planner exits unexpectedly, or `doctor`
reports a build mismatch, stop the old daemon, rebuild, run `npm run doctor`,
start the daemon once, and hard-reload the browser.

For the solo Claude-only compatibility mode, run `npm run setup:stdio` (or
`npm run setup -- --stdio`). That configuration lets one Claude session launch
and own Overwatch itself.

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

After pulling an update, the stable refresh path is:

```bash
git pull --ff-only origin main
npm ci
npm run build
npm run doctor
npm run start:daemon
```

Stop the previous daemon before the last command. This does not replace
`engagement.json`, its state/WAL, evidence, or reports.

## Documentation

**[professor-moody.github.io/overwatch](https://professor-moody.github.io/overwatch/)** — architecture, configuration, the generated MCP tool inventory, graph model, inference rules, skills library, operator playbook, and development guide.

## Disclaimer

This tool is designed for authorized security testing only. Do not run against production systems without explicit written authorization.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
