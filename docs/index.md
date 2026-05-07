# Overwatch

**An offensive security engagement orchestrator built as an MCP server.**

LLM-powered penetration testing has a fundamental problem: the context window is finite, but engagements are not. Every discovery, credential, and relationship matters — and stuffing it into a prompt doesn't scale. Overwatch solves this by inverting the pattern. Instead of the LLM holding state, a **persistent MCP server** holds the engagement graph. The LLM proposes actions. The server validates them. The graph survives compaction, restarts, and session handoffs with zero information loss.

---

## Why Overwatch

| Problem | Overwatch Solution |
|---------|-------------------|
| Context window overflow loses engagement state | Graph lives outside the context window; `get_state()` reconstructs everything |
| No structured way to track discoveries | Directed property graph — traversable attack paths, not rows in a table |
| LLM can't enforce scope/OPSEC consistently | Deterministic layer handles hard constraints; LLM handles reasoning |
| Manual note-taking across sessions | Automatic persistence with atomic writes and snapshot rollback |
| No way to parallelize work | Sub-agent dispatch with scoped subgraph views |

## Key Features

- **[Graph-based state](graph-model.md)** — Engagements are directed property graphs: hosts, services, credentials, users, and the relationships between them. Every attack path is a traversable route.
- **Survives compaction** — The orchestrator lives outside the context window. After compaction, [`get_state()`](tools/get-state.md) reconstructs a complete briefing. Zero information loss.
- **[Hybrid scoring](architecture.md#hybrid-scoring)** — Deterministic layer handles hard constraints (scope, dedup, OPSEC vetoes). The LLM handles nuanced reasoning (chain spotting, sequencing, risk).
- **[Inference rules](architecture.md#inference-rules)** — Findings trigger automatic hypothesis generation (e.g., "SMB signing disabled → relay target"). These become frontier items for the LLM to evaluate.
- **[Full graph access](tools/query-graph.md)** — `query_graph()` gives unrestricted access for creative path discovery beyond scored frontier items.
- **[51 MCP tools](tools/index.md)** — From state management to BloodHound/AzureHound ingestion to structured output parsing to persistent interactive sessions to pentest report generation, plus first-class [operator-infrastructure registration](tools/register-mock-service.md).
- **[34 offensive skills](skills/index.md)** — RAG-searchable methodology library covering AD, cloud, web, and infrastructure.
- **[Persistent sessions](tools/sessions.md)** — Long-lived interactive sessions (SSH, local PTY, reverse shell) with cursor-based I/O, ownership enforcement, and TTY quality tracking. Listener-mode sessions auto-register as `mock_service` graph nodes so captured credentials attribute back to the listener that caught them.
- **[Live dashboard](dashboard.md)** — Real-time WebGL graph visualization with interactive node dragging, path highlighting, and neighborhood focus. Operator-controlled infrastructure renders alongside discovered targets.
- **[Tamper-evident audit trail](concepts.md#audit-trail)** — Optional hash-chained activity log + JSON-RPC tape proxy let retrospectives prove the AI did exactly what it claimed, in the order it claimed.
- **[Retrospective analysis](playbook/retrospective.md)** — Post-engagement skill gaps, inference suggestions, RLVR training traces, automatic inference rule application, technique priors, and skill annotations.
- **[IAM policy simulation](concepts.md#iam-policy-simulation)** — Cloud-native permission evaluation for AWS (deny-overrides-allow), Azure (RBAC scope hierarchy), and GCP (deny policy precedence).
- **[Credential lifecycle intelligence](concepts.md#credential-lifecycle)** — Automatic expiry estimation, graduated frontier scoring, and provenance chain tracking.
- **[Web attack path modeling](concepts.md#web-attack-path-modeling)** — API endpoint nodes, authentication bypass edges, and automated web attack inference rules.

### By the Numbers

| | |
|---|---|
| **51** MCP tools | **34** offensive skills |
| **28** output parsers with 50 aliases (nmap, nxc, certipy, secretsdump, kerbrute, hashcat, responder, ldapsearch, enum4linux, rubeus, web dir enum, linpeas, nuclei, nikto, testssl, pacu, prowler, burp, zap, sqlmap, wpscan, getnpusers, getuserspns, gettgt, getst, smbclient, wmiexec, psexec) | **61** built-in declarative inference rules |
| **2440+** tests across **99** files | **23** node types, **73** edge types |

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
