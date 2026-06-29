# Terminal Operator CLI (`overwatch`)

`overwatch` is a standalone command-line client for a **live** engagement. It is a
thin client over the same `/api/*` HTTP surface the [Live Dashboard](dashboard.md)
uses, so you can watch and steer the *same* engagement the model is driving —
from your own shell (e.g. a second pane) — without round-tripping through Claude.

It is **not** part of `claude`/MCP. It's a separate binary you run yourself:

```
pane 1:  $ claude            # the model drives the engagement via MCP tools
pane 2:  $ overwatch status   # you watch / approve / deploy directly
```

## Prerequisites

The engagement must be running (it serves the API on `:8384`):

```bash
npm start -- --http      # or: npm run demo:daemon  (demo engagement)
```

Then, from the repo:

```bash
npm run overwatch -- <command> [options]
# or, once `npm link` / installed, just:
overwatch <command> [options]
```

## Commands

### Read

| Command | Shows |
|---|---|
| `overwatch status` | Engagement snapshot: graph, objectives, access, agents, approvals, top frontier, readiness |
| `overwatch frontier [--max N] [--type TYPE]` | Candidate next actions (the deterministic frontier) |
| `overwatch findings [--severity S]` | Classified findings + severity summary |
| `overwatch agents` | Running agent roster |
| `overwatch approvals` | Pending operator approvals |
| `overwatch opsec` | OPSEC noise budget + recommended approach |
| `overwatch sessions` | Interactive sessions |
| `overwatch queries` | Open questions agents are waiting on |

### Operate

| Command | Does |
|---|---|
| `overwatch approve <action-id>` | Approve a pending action |
| `overwatch deny <action-id> [--reason TEXT]` | Deny a pending action |
| `overwatch answer <query-id> <answer text…>` | Answer an agent's question |
| `overwatch deploy <target> [--archetype TYPE]` | Quick-deploy an agent at a raw IP/CIDR/domain (auto-scopes) |
| `overwatch dispatch --node <id…> [--skill S] [--archetype A]` | Dispatch an agent at existing graph node(s) |

A refusal (e.g. a frontier item already leased, or an out-of-scope target) prints
the server's reason and exits non-zero; a success prints a confirmation (deploy /
dispatch report the new task + agent id).

## Options

| Flag | Effect |
|---|---|
| `--json` | Print raw, compact API JSON (for `jq` / scripts); disables color |
| `--no-color` | Disable ANSI color |
| `--url <url>` | API base URL (default: `$OVERWATCH_URL` or `http://127.0.0.1:8384`) |
| `--token <tok>` | Bearer token for a remote, non-loopback server (`$OVERWATCH_DASHBOARD_TOKEN`) |
| `--help` | Help, or `overwatch <command> --help` |

Color auto-disables when output is piped or `NO_COLOR` is set, so
`overwatch status | tee` and `overwatch findings --json | jq` stay clean.

## Remote / authenticated servers

A loopback server (the default) needs no auth. For a server bound to a non-loopback
host, set the token (the server logs/uses `OVERWATCH_DASHBOARD_TOKEN`):

```bash
overwatch status --url https://host:8384 --token "$OVERWATCH_DASHBOARD_TOKEN"
# or via env:
OVERWATCH_URL=https://host:8384 OVERWATCH_DASHBOARD_TOKEN=… overwatch status
```

## For the model

When a sub-agent has shell access, `overwatch <read> --json` is a token-cheap way
to pull engagement state without an MCP round-trip — e.g. `overwatch frontier --json`.
The same data is available via the MCP tools ([`get_state`](tools/get-state.md),
[`next_task`](tools/next-task.md)); use whichever fits.

## See Also

- [Operator Cockpit](operator-cockpit.md) — the model-driven runtime + the web console
- [Live Dashboard](dashboard.md) — the visual operator surface over the same API
