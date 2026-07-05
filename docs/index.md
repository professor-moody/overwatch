# Overwatch

**An MCP server that gives Claude a persistent engagement graph for offensive security operations.**

The core problem with LLM-driven pentesting: context windows are finite but engagements aren't. Every credential, lateral movement path, and discovered host matters — and they accumulate faster than they fit in a prompt. Overwatch solves this by moving state out of the context window entirely. The LLM calls tools. A persistent server holds the graph. Compaction, restarts, and agent handoffs lose nothing.

---

## What it does

You run Overwatch as an MCP server alongside Claude. As you work an engagement, every discovery feeds into a directed property graph: hosts, credentials, services, users, cloud identities, and the relationships between them. The LLM queries this graph to plan next steps, validates actions against scope and OPSEC constraints, and dispatches sub-agents for parallel work — all without you having to manually track state between sessions.

There is **one engine, two surfaces**: you drive the same `GraphEngine` from the **terminal** (Claude over MCP) and from the **dashboard** (a live web UI) — an approval in one resumes a blocked agent in the other. See the [Runtime Model](runtime-model.md) for how they tie together.

After a compaction or restart, one call to [`get_state()`](tools/get-state.md) reconstructs a full engagement briefing from the graph. You pick up exactly where you left off.

## Key Features

- **[Graph-based state](graph-model.md)** — 30 node types, 90 edge types. Every attack path is a traversable route through the engagement graph, not a list of notes.
- **[Inference engine](architecture.md#inference-rules)** — 64 built-in rules that fire when findings land (e.g., "OIDC audience matches AWS STS → probable AssumeRoleWithWebIdentity"). Surfaces follow-on opportunities as scored frontier items automatically.
- **[Credential lifecycle intelligence](concepts.md#credential-lifecycle)** — Captured tokens track status (active/stale/expired), reachability via confirmed edges, expiry estimation, and provenance. The Credentials dashboard tab shows all of this at a glance.
- **[80 MCP tools](tools/index.md)** — State management, action logging, graph queries, BloodHound/AzureHound ingestion, 75 output parsers, persistent interactive sessions, credential playbooks, and pentest report generation. (The live count + set come from `get_system_prompt`.)
- **[Credential-driven playbooks](tools/index.md)** — Five tools (`expand_aws_credential`, `expand_github_credential`, `expand_oidc_capture`, `exchange_refresh_token`, `expand_entra_credential`) that turn a captured credential into a sequenced recon plan queued through the approval gate.
- **[43 offensive skills](skills/index.md)** — RAG-searchable methodology library covering AD, cloud, web, and infrastructure.
- **[Scope and OPSEC enforcement](concepts.md#opsec-noise)** — Hard constraints live in the deterministic layer. The LLM handles reasoning. Out-of-scope calls fail closed.
- **[Persistent sessions](tools/sessions.md)** — Long-lived interactive shells (SSH, local PTY, reverse shell) with cursor-based I/O and TTY quality tracking.
- **[Claude Code hooks](claude-hooks.md)** — Local hooks that re-anchor Claude to Overwatch, block raw target-facing Bash, and nudge discovery output back into the graph.
- **[Live dashboard](dashboard.md)** — Real-time graph visualization, approval queue, frontier view, agent status, credential tracker, findings panel with report generation.
- **[Tamper-evident audit trail](concepts.md#audit-trail)** — Optional hash-chained activity log and JSON-RPC tape proxy. Retrospectives can prove the AI did exactly what it claimed, in the order it claimed.

### By the Numbers

| | |
|---|---|
| **80** MCP tools | **43** offensive skills |
| **75** output parsers / **130** `parse_output` keys (nmap, nxc, certipy, secretsdump, kerbrute, hashcat, responder, ldapsearch, enum4linux, rubeus, web dir enum, linpeas, nuclei, nikto, testssl, sqlmap, wpscan, httpx, dnsx, amass, subfinder, crt.sh, whois, theHarvester, trufflehog, linkfinder, openapi/graphql, security-headers, gowitness, katana, and more) | **64** built-in inference rules |
| **4000+** tests across **220+** files | **30** node types, **90** edge types |

## Quick Start

!!! tip "Just want to get running?"
    The [**Getting Started**](getting-started.md) guide is a tight 5-minute path: clone, copy a template, wire the MCP config, launch `claude`. Everything else here is reference material you can come back to.

```bash
git clone https://github.com/professor-moody/overwatch.git
cd overwatch
npm install && npm run build
cp engagement-templates/ctf.json engagement.json
# edit scope.cidrs and scope.domains, then add to ~/.claude/settings.json
claude
```

`ctf.json` is the friendliest first-run template — no OPSEC constraints,
auto-approves everything. For real engagements switch to
`internal-pentest.json` or `external-pentest.json` — see
[Configuration](configuration.md).

Full walk-through with template list, dashboard tour, and "what to say to the AI first" prompts: [Getting Started](getting-started.md). Or jump straight to a [lab workflow](playbook/index.md).

## Architecture at a Glance

One persistent engine; the terminal (Claude over MCP) and the dashboard (HTTP/WebSocket) are two surfaces driving the same live state:

![Two surfaces, one engine](assets/two-surfaces-one-engine-light.svg#only-light)
![Two surfaces, one engine](assets/two-surfaces-one-engine-dark.svg#only-dark)

The internal component decomposition:

![System Architecture](assets/system-architecture-light.svg#only-light)
![System Architecture](assets/system-architecture-dark.svg#only-dark)

Learn more in the [Runtime Model](runtime-model.md), [Architecture](architecture.md), explore [Key Concepts](concepts.md), or jump to the [Tool Reference](tools/index.md).

## Where to Go Next

- **First time here?** → [Getting Started](getting-started.md) for the 5-minute install + first engagement.
- **Want the mental model?** → [Runtime Model](runtime-model.md) — one engine, two surfaces (terminal + dashboard), and how they tie together.
- **Want to understand the design?** → [Architecture](architecture.md) covers the system diagram, components, and design decisions. Then [Key Concepts](concepts.md) for the engagement-graph vocabulary (frontier, inference, OPSEC, audit trail).
- **Auditing or threat-modeling?** → [Threat Model](threat-model.md) states explicitly what the system trusts, what it defends against, and what residual risks remain.
- **Building or extending?** → [Roadmap](roadmap.md) for current tracks, [Tool Reference](tools/index.md) for every MCP tool, and [Development](development.md) for project structure and testing.
- **Running an actual engagement?** → [Operator Playbook](playbook/index.md) walks through GOAD AD labs, HTB single-host, network engagements.
