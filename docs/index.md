# Overwatch

**An MCP server that gives Claude a persistent engagement graph for offensive security operations.**

The core problem with LLM-driven pentesting: context windows are finite but engagements aren't. Every credential, lateral movement path, and discovered host matters — and they accumulate faster than they fit in a prompt. Overwatch solves this by moving state out of the context window entirely. The LLM calls tools. A persistent server holds the graph. Compaction, restarts, and agent handoffs lose nothing.

---

## What it does

You run Overwatch as an MCP server alongside Claude. As you work an engagement, every discovery feeds into a directed property graph: hosts, credentials, services, users, cloud identities, and the relationships between them. The LLM queries this graph to plan next steps, validates actions against scope and OPSEC constraints, and dispatches sub-agents for parallel work — all without you having to manually track state between sessions.

After a compaction or restart, one call to [`get_state()`](tools/get-state.md) reconstructs a full engagement briefing from the graph. You pick up exactly where you left off.

## Key Features

- **[Graph-based state](graph-model.md)** — 23 node types, 73 edge types. Every attack path is a traversable route through the engagement graph, not a list of notes.
- **[Inference engine](architecture.md#inference-rules)** — 61 built-in rules that fire when findings land (e.g., "OIDC audience matches AWS STS → probable AssumeRoleWithWebIdentity"). Surfaces follow-on opportunities as scored frontier items automatically.
- **[Credential lifecycle intelligence](concepts.md#credential-lifecycle)** — Captured tokens track status (active/stale/expired), reachability via confirmed edges, expiry estimation, and provenance. The Credentials dashboard tab shows all of this at a glance.
- **[60+ MCP tools](tools/index.md)** — State management, action logging, graph queries, BloodHound/AzureHound ingestion, 50 output parsers, persistent interactive sessions, credential playbooks, and pentest report generation.
- **[Credential-driven playbooks](tools/index.md)** — Five tools (`expand_aws_credential`, `expand_github_credential`, `expand_oidc_capture`, `exchange_refresh_token`, `expand_entra_credential`) that turn a captured credential into a sequenced recon plan queued through the approval gate.
- **[34 offensive skills](skills/index.md)** — RAG-searchable methodology library covering AD, cloud, web, and infrastructure.
- **[Scope and OPSEC enforcement](concepts.md#opsec)** — Hard constraints live in the deterministic layer. The LLM handles reasoning. Out-of-scope calls fail closed.
- **[Persistent sessions](tools/sessions.md)** — Long-lived interactive shells (SSH, local PTY, reverse shell) with cursor-based I/O and TTY quality tracking.
- **[Live dashboard](dashboard.md)** — Real-time graph visualization, approval queue, frontier view, agent status, credential tracker, findings panel with report generation.
- **[Tamper-evident audit trail](concepts.md#audit-trail)** — Optional hash-chained activity log and JSON-RPC tape proxy. Retrospectives can prove the AI did exactly what it claimed, in the order it claimed.

### By the Numbers

| | |
|---|---|
| **60+** MCP tools | **34** offensive skills |
| **50** output parsers (nmap, nxc, certipy, secretsdump, kerbrute, hashcat, responder, ldapsearch, enum4linux, rubeus, web dir enum, linpeas, nuclei, nikto, testssl, pacu, prowler, sqlmap, wpscan, and more) | **61** built-in inference rules |
| **2775+** tests across **127** files | **23** node types, **73** edge types |

## Quick Start

!!! tip "Just want to get running?"
    The [**Getting Started**](getting-started.md) guide is a tight 5-minute path: clone, copy a template, wire the MCP config, launch `claude`. Everything else here is reference material you can come back to.

```bash
git clone https://github.com/professor-moody/overwatch.git
cd overwatch
npm install && npm run build
cp engagement-templates/internal-pentest.json engagement.json
# edit scope.cidrs and scope.domains, then add to ~/.claude/settings.json
claude
```

Full walk-through with template list, dashboard tour, and "what to say to the AI first" prompts: [Getting Started](getting-started.md). Or jump straight to a [lab workflow](playbook/index.md).

## Architecture at a Glance

![System Architecture](assets/system-architecture-light.svg#only-light)
![System Architecture](assets/system-architecture-dark.svg#only-dark)

Learn more in [Architecture](architecture.md), explore [Key Concepts](concepts.md), or jump to the [Tool Reference](tools/index.md).

## Where to Go Next

- **First time here?** → [Getting Started](getting-started.md) for the 5-minute install + first engagement.
- **Want to understand the design?** → [Architecture](architecture.md) covers the system diagram, components, and design decisions. Then [Key Concepts](concepts.md) for the engagement-graph vocabulary (frontier, inference, OPSEC, audit trail).
- **Auditing or threat-modeling?** → [Threat Model](threat-model.md) states explicitly what the system trusts, what it defends against, and what residual risks remain.
- **Building or extending?** → [Tool Reference](tools/index.md) for every MCP tool. [Development](development.md) for project structure and testing.
- **Running an actual engagement?** → [Operator Playbook](playbook/index.md) walks through GOAD AD labs, HTB single-host, network engagements.
