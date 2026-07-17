# Terminal Operator CLI (`overwatch`)

`overwatch` is primarily a standalone command-line client for a **live**
engagement. Most commands use the same `/api/*` HTTP surface as the
[Live Dashboard](dashboard.md). The local `state migrate --check` command is the
exception: it inspects persisted files without requiring a running server.

It is **not** part of `claude`/MCP. It's a separate binary you run yourself:

```
pane 1:  $ npm run start:daemon  # the one Overwatch runtime owner
pane 2:  $ claude                # the model drives it via HTTP MCP
pane 3:  $ overwatch status      # you watch / approve / deploy directly
```

All three panes are adapters to the **same running Overwatch daemon and durable
engagement**. Start the daemon once; do not start a second copy for the
dashboard. Claude, the terminal CLI, and dashboard-deployed agents see the same
task leases, playbook claims, approvals, and findings. If one surface prepares
a playbook step, the others show its owner instead of silently claiming it too.
Dashboard-deployed Claude workers use isolated per-task MCP configuration and
do not share the human terminal's project settings, hooks, or resumable Claude
session.

## Prerequisites

The engagement must be running (it serves the API on `:8384`):

```bash
npm run start:daemon     # or: npm run demo:daemon  (demo engagement)
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
| `overwatch recovery` | WAL/state recovery, active config convergence, exact reconciliation hashes, and unresolved runtime ownership |
| `overwatch state migrate --check [--state-file PATH] [--config-file PATH]` | Side-effect-free local V0/V1, WAL, snapshot, and config migration readiness |
| `overwatch frontier [--max N] [--type TYPE]` | Candidate next actions (the deterministic frontier) |
| `overwatch findings [--severity S]` | Classified findings + severity summary |
| `overwatch agents` | Running agent roster |
| `overwatch approvals` | Pending operator approvals |
| `overwatch opsec` | OPSEC noise budget + recommended approach |
| `overwatch sessions` | Interactive sessions |
| `overwatch queries` | Open questions agents are waiting on |
| `overwatch playbooks [--credential ID] [--status STATUS] [--open]` | Durable credential-playbook runs, progress, and the owner of any active claim |

### Operate

| Command | Does |
|---|---|
| `overwatch approve <action-id>` | Approve a pending action |
| `overwatch deny <action-id> [--reason TEXT]` | Deny a pending action |
| `overwatch answer <query-id> <answer text…>` | Answer an agent's question |
| `overwatch deploy <target> [--archetype TYPE]` | Quick-deploy an agent at a raw IP/CIDR/domain (auto-scopes) |
| `overwatch dispatch --node <id…> [--skill S] [--archetype A]` | Dispatch an agent at existing graph node(s) |
| `overwatch session resume <session-id>` | Explicitly rebind a recovered `resume_available` listener |
| `overwatch config reconcile <use_file\|use_state> --file-hash SHA256 --state-hash SHA256` | Resolve an active config divergence using an explicit authority choice |
| `overwatch playbook start <run> <step>` | Prepare/claim one ready step and return its stable execution descriptor with `--json`; this does not execute it |
| `overwatch playbook retry <run> <step>` | Prepare a new append-only attempt after failure/interruption |
| `overwatch playbook interrupt <run> <step> [--reason TEXT]` | Release an abandoned prepared claim as interrupted so it can be retried |
| `overwatch playbook resume <run>` | Re-open an interrupted run after restart |
| `overwatch playbook skip <run> <step> [--reason TEXT]` | Skip a non-terminal step while retaining the reason and prior attempts |

A refusal (e.g. a frontier item already leased, or an out-of-scope target) prints
the server's reason and exits non-zero; a success prints a confirmation (deploy /
dispatch report the new task + agent id).

## Recovery and config reconciliation

`overwatch recovery` is always safe to run, including when recovery has placed
the server in read-only mode. It reports the base, contiguous-applied, on-disk,
and allocated WAL checkpoints; explicit preserved/malformed flags; the last
persistence error and durable-write failure streak; and the active config's
file/runtime/state revisions and hashes. A separate **Runtime ownership
warnings** section lists any run whose original process identity could not be
verified or safely reclaimed.

The CLI presents the combined write gate separately from **state/WAL health**.
A config-only divergence therefore reads as a paused/read-only combined status
with healthy state/WAL recovery. If underlying persistence is also degraded,
`state/WAL health` is degraded and the separate `persistence reason` explains
why configuration reconciliation cannot proceed.

When it reports `config_recovery.status: diverged`, inspect the semantic
difference and use only a mode listed in `allowed_resolutions`. Pass both hashes
from that same observation:

```bash
overwatch recovery

overwatch config reconcile use_state \
  --file-hash 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --state-hash abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
```

`use_file` applies the validated file to runtime and state. `use_state` restores
the file from durable state. Both create a fresh config revision and fail with a
conflict if either observed hash changed after inspection.

Do not reconcile a `write_incomplete` status: restart to let Overwatch complete
its known write intent. Config reconciliation is also refused while underlying
WAL/state recovery is incomplete.

## State migration preflight

Run this before upgrading a copied or stopped engagement:

```bash
overwatch state migrate --check \
  --config-file /path/to/engagement.json \
  --state-file /path/to/state-engagement-id.json
```

If `--state-file` is omitted, the CLI derives it from the config ID. The command
does not contact HTTP and does not create, rename, checkpoint, or compact
engagement files. It reports the selected primary/snapshot base, observed and
supported state/journal versions, WAL preflight blockers, config semantic
agreement, and whether revision 1 may be seeded.

Exit status is 0 for a current or migration-ready state and 1 for missing or
blocked state. A newer unsupported format must be opened with a compatible
binary; Overwatch deliberately refuses to downgrade or reseed it.

## Options

| Flag | Effect |
|---|---|
| `--json` | Print raw, compact API JSON (for `jq` / scripts); disables color |
| `--no-color` | Disable ANSI color |
| `--url <url>` | API base URL (default: `$OVERWATCH_URL` or `http://127.0.0.1:8384`) |
| `--token <tok>` | Bearer token for a remote, non-loopback server (`$OVERWATCH_DASHBOARD_TOKEN`) |
| `--state-file <path>` | Local state path for `state migrate --check` (`$OVERWATCH_STATE_FILE`) |
| `--config-file <path>` | Local config path for `state migrate --check` (`$OVERWATCH_CONFIG`) |
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
