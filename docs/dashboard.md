# Live Dashboard

Overwatch includes a real-time graph visualization dashboard built with [sigma.js](https://www.sigmajs.org/) (WebGL) and [graphology](https://graphology.github.io/).

## Overview

The dashboard runs in the same process as the MCP server — no additional setup required. It provides a read-only view of the engagement graph with live updates via WebSocket.

## Access

The dashboard starts automatically on port **8384** (configurable via `OVERWATCH_DASHBOARD_PORT`).

```
http://localhost:8384
```

To disable the dashboard, set the port to `0`:

```bash
OVERWATCH_DASHBOARD_PORT=0
```

## Features

- **Force-directed graph layout** — nodes arrange themselves based on relationships
- **Node type filtering** — toggle visibility by type (hosts, services, credentials, etc.)
- **Search** — find nodes by label, IP, hostname, or any property
- **Dark theme** — designed for extended use during engagements
- **Live updates** — graph changes broadcast via WebSocket as findings are ingested
- **Side panels** — objectives, frontier items, active agents, and recent activity

## Architecture

```
Browser ◄──── WebSocket ────► DashboardServer
                                    │
                              onUpdate callback
                                    │
                              GraphEngine.persist()
```

- **HTTP** serves the self-contained SPA (`index.html`)
- **WebSocket** broadcasts full graph state on every `persist()` call
- **Read-only** — no mutations from the browser
- **GraphEngine** fires `onUpdate()` after every graph change

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard SPA |
| `/api/state` | GET | Current engagement state (JSON) |
| `/api/graph` | GET | Full graph export (JSON) |
| `ws://` | WebSocket | Live graph delta stream |

## Verifying Dashboard Status

Use [`run_lab_preflight`](tools/run-lab-preflight.md) to check dashboard readiness:

```
dashboard: {
  enabled: true,
  running: true,
  address: "http://localhost:8384"
}
```

Or check via [`get_state`](tools/get-state.md) which includes dashboard status in its response.
