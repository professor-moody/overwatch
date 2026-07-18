# Overwatch

**An MCP server that gives Claude a persistent engagement graph for offensive security operations.**

The core problem with LLM-driven pentesting: context windows are finite but engagements aren't. Every credential, lateral movement path, and discovered host matters — and they accumulate faster than they fit in a prompt. Overwatch moves durable engagement truth out of the context window. The model calls tools; a persistent server holds the graph, coordination records, and artifact references. Ephemeral runtime handles such as live PTYs, sockets, and process objects are deliberately not reconstructed after restart.

---

## What it does

You run Overwatch as an MCP server alongside Claude. As you work an engagement, every discovery feeds into a directed property graph: hosts, credentials, services, users, cloud identities, and the relationships between them. The LLM queries this graph to plan next steps, validates actions against scope and OPSEC constraints, and dispatches sub-agents for parallel work — all without you having to manually track state between sessions.

There is **one engine, several coordinated surfaces**: terminal Claude over MCP, the browser dashboard, the `overwatch` CLI, and dashboard-deployed agents all use the same daemon. An approval in one surface is visible in the others, and task leases prevent two workers from silently owning the same work. See the [Runtime Model](runtime-model.md) for how they tie together.

After compaction or restart, [`get_state()`](tools/get-state.md) returns an operational briefing: scope, discoveries, access, objectives, agents, and the current frontier. It is not a lossless export of every historical event or evidence byte. Use `get_history`, `get_evidence`, and `bundle_engagement` when you need the full records and referenced artifacts.

## Key Features

- **[Graph-based state](graph-model.md)** — Every attack path is a traversable route through the engagement graph, not a list of notes. Current generated counts appear below.
- **[Inference engine](concepts.md#inference-rules)** — Built-in rules fire when findings land (e.g., "OIDC audience matches AWS STS → probable AssumeRoleWithWebIdentity") and surface follow-on opportunities as scored frontier items automatically.
- **[Credential lifecycle intelligence](concepts.md#credential-lifecycle)** — Captured tokens track status (active/stale/expired), reachability via confirmed edges, expiry estimation, and provenance. The Credentials dashboard tab shows all of this at a glance.
- **[MCP tool reference](tools/index.md)** — State management, recovery and config reconciliation, action logging, graph queries, BloodHound/AzureHound ingestion, output parsers, recoverable interactive-session descriptors, durable credential playbooks, and pentest report generation. Runtime registration generates the checked-in count, categories, and schema hashes.
- **[Credential-driven playbooks](tools/cloud-playbooks.md)** — Captured cloud/SaaS credentials become durable, resumable runs with dependency-aware steps, append-only attempts, explicit ownership, and precise execution/parse outcomes.
- **[Offensive skills](skills/index.md)** — RAG-searchable methodology library covering AD, cloud, web, and infrastructure.
- **[Scope and OPSEC enforcement](concepts.md#opsec-noise)** — Hard constraints live in the deterministic layer. The LLM handles reasoning. Out-of-scope calls fail closed.
- **[Recoverable session intent](tools/sessions.md)** — Interactive shells and listeners with cursor-based I/O and TTY quality tracking. Durable descriptors survive restart; live connections and buffers do not masquerade as resumed sessions.
- **[Claude Code hooks](claude-hooks.md)** — Local hooks that re-anchor Claude to Overwatch, block raw target-facing Bash, and nudge discovery output back into the graph.
- **[Live dashboard](dashboard.md)** — Real-time graph visualization, approval queue, frontier view, agent status, credential tracker, findings panel with report generation.
- **[Tamper-evident audit trail](concepts.md#audit-trail)** — New engagements hash-chain the activity log by default. JSON-RPC tape capture and checkpoint signing are opt-in additions for wire-level audit and signer attribution.

### By the Numbers

<!-- BEGIN:capability-counts -->
| Capability | Count | Capability | Count |
|------------|------:|------------|------:|
| MCP tools | **95** | Offensive skills | **44** |
| Parser aliases | **138** | Built-in inference rules | **64** |
| Node types | **30** | Edge types | **90** |
| Agent archetypes | **15** | Tool categories | **8** |
<!-- END:capability-counts -->

## Quick Start

!!! tip "Just want to get running?"
    The [**Getting Started**](getting-started.md) guide is a tight 5-minute path: clone, run setup, start one daemon, then open the dashboard and terminal Claude. Everything else here is reference material you can come back to.

```bash
git clone https://github.com/professor-moody/overwatch.git
cd overwatch
npm ci
npm run build
npm run setup
npm run daemon:start
npm run doctor
OVERWATCH_ENGAGEMENT_ACTIVE=1 claude
```

`ctf.json` is the friendliest first-run template — no OPSEC constraints,
auto-approves everything. For real engagements switch to
`internal-pentest.json` or `external-assessment.json` — see
[Configuration](configuration.md).

The detached daemon remains running after `daemon:start` returns. Open
`http://127.0.0.1:8384` and launch
`OVERWATCH_ENGAGEMENT_ACTIVE=1 claude` from the repo in the same or another
terminal. (Plain `claude` connects, but leaves engagement-only anti-drift hooks
inactive.) Terminal Claude, the dashboard, the
[`overwatch` CLI](cli.md), and deployed agents share that one runtime; do not
launch a second stdio server beside it. Dashboard-managed Claude workers use
isolated per-task MCP configuration and do not inherit the terminal session's
project settings, hooks, or resume history.

Use **Console → Add Targets** and **Settings**—or the corresponding MCP
configuration tools—to update the current engagement. **New Engagement**
creates another inactive config; it does not switch this daemon, and dashboard
engagement switching is not currently supported.

The solo **stdio** compatibility mode is still available through
`npm run setup:stdio` (or `npm run setup -- --stdio`), but use the default daemon
whenever you want the dashboard, CLI, planner, or dispatched agents.
See [Two ways to run Overwatch](getting-started.md#two-ways-to-run-overwatch).

Full walk-through with template list, dashboard tour, and "what to say to the AI first" prompts: [Getting Started](getting-started.md). Or jump straight to a [lab workflow](playbook/index.md).

For the recurring operating routine—start/stop, concurrent terminal and
dashboard work, approvals, planner status, recovery, upgrade, and backup—use
[Daily Operation](daily-operations.md).

## Architecture at a Glance

One persistent engine; terminal Claude, the dashboard, CLI, and managed workers are adapters over the same live state and command services:

![Two surfaces, one engine](assets/two-surfaces-one-engine-light.svg#only-light)
![Two surfaces, one engine](assets/two-surfaces-one-engine-dark.svg#only-dark)

The internal component decomposition:

![System Architecture](assets/system-architecture-light.svg#only-light)
![System Architecture](assets/system-architecture-dark.svg#only-dark)

Learn more in the [Runtime Model](runtime-model.md), [Architecture](architecture.md), explore [Key Concepts](concepts.md), or jump to the [Tool Reference](tools/index.md).

## Where to Go Next

- **First time here?** → [Getting Started](getting-started.md) for the 5-minute install + first engagement.
- **Want the mental model?** → [Runtime Model](runtime-model.md) — one engine shared by terminal Claude, dashboard, CLI, and managed workers.
- **Want to understand the design?** → [Architecture](architecture.md) covers the system diagram, components, and design decisions. Then [Key Concepts](concepts.md) for the engagement-graph vocabulary (frontier, inference, OPSEC, audit trail).
- **Auditing or threat-modeling?** → [Threat Model](threat-model.md) states explicitly what the system trusts, what it defends against, and what residual risks remain.
- **Building or extending?** → [Roadmap](roadmap.md) for current tracks, [Tool Reference](tools/index.md) for every MCP tool, and [Development](development.md) for project structure and testing.
- **Running an actual engagement?** → [Operator Playbook](playbook/index.md) walks through GOAD AD labs, HTB single-host, network engagements.
