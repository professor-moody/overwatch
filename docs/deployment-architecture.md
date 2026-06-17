# Deployment Architecture: One Engine, Many Drivers

> **Status:** Accepted (June 2026). The **MCP driver** is in production and is the
> driver for external lab work. The **no-MCP internal driver** is planned, not yet
> built — recorded here so the path is ready when internal engagements need it.

This is the decision record for how Overwatch reaches a model and how a model
reaches Overwatch's tools — across environments that allow MCP and environments
that do not. It complements the [Bedrock Integration Plan](bedrock-integration-plan.md)
and the [Operator Cockpit](operator-cockpit.md) runtime description.

## Context

Overwatch has to run in two environments with different constraints:

- **External lab** (assessing our own external footprint): MCP is permitted. The
  current architecture is fine and is what we will use for external testing.
- **Internal**: only *approved* MCP servers may be used. Overwatch is not approved
  and will not be for some time, so **MCP is effectively unavailable internally.**

Two more constraints shape the answer:

- **Easiest thing to run wins**, and it should reuse model access we already have
  approved — internally that is **Claude Code and Claude headless** (`claude -p`).
- **No control over Bedrock model settings.** We cannot rely on constructing
  arbitrary Bedrock payloads or enabling provider-native tool-use, so an embedded
  loop that builds its own Bedrock request is not a path we control.

## What we already have

The decision is cheap because the engine is already transport-agnostic — verified
in code, not aspirational:

- The full action lifecycle (validate → approve → `action_started` → execute →
  evidence → parse/report → `action_completed` → graph/frontier → event) lives in
  `runInstrumentedProcess` (`src/tools/_process-runner.ts`) and `GraphEngine`.
  Its inputs are plain objects with **zero MCP types**.
- **Two non-MCP callers already exist and prove it:** the dashboard
  (`dashboard-server.ts` calls engine methods directly over HTTP/WS) and the
  scripted agent runner (`scripted-agent-runner.ts` calls `runInstrumentedProcess`
  directly). Both emit the same audit events as the MCP path.
- **MCP is load-bearing in exactly one place:** the headless reasoning agent's
  *return path* — `claude -p` connects back to `/mcp` to invoke tools
  (`headless-mcp-runner.ts`). The operator's primary model also drives via MCP.
  Tool registration and the stdio/HTTP transports are thin edges (`src/app.ts`).

So MCP is not the brain. The domain engine + action lifecycle is the brain and the
single executor; transports are **drivers** that route into it.

## Decision

1. **The engine is the system of record and the one executor. MCP is one driver,
   not the platform.** Every driver routes through the same `runInstrumentedProcess`
   + `GraphEngine` lifecycle, so scope, OPSEC, approval, evidence, and audit apply
   uniformly regardless of how the action arrived.
2. **Keep the MCP driver as-is.** It is correct, it is what external lab testing
   needs soon, and it stays first-class.
3. **Add a no-MCP internal driver** that reuses Claude headless: `claude -p` driving
   Overwatch through a thin `overwatch` CLI / local HTTP surface, with **no MCP
   server to approve.** Same executor, same lifecycle, same audit trail.
4. **Drivers are selected per environment.** The engine, dashboard, lifecycle, and
   archetype tool-surfaces are identical across them.

## The drivers

| Driver | Environment | How the model reaches tools | Status |
|--------|-------------|-----------------------------|--------|
| **MCP** | External lab (where approved) | Primary + headless agents speak MCP to `/mcp` | Shipped |
| **Headless Claude + CLI** | Internal (MCP blocked) | `claude -p` with Bash limited to the `overwatch` CLI → local execution endpoints → executor | Planned |
| **Human-only console** | Any | Operator drives the dashboard + scripted automation, no reasoning agent | Available today (once operator target-exec endpoints land) |
| **Embedded native-tool loop** | Only with raw model-API control | Overwatch builds the model request with provider-native tool-use | Not pursued — we do not control Bedrock settings |

The launching of headless Claude was never the MCP part — the runner already spawns
`claude -p` in-process next to the engine. Only the **return path** (how the agent
invokes instrumented tools) uses MCP today. The internal driver swaps that return
path for the CLI; nothing else about the agent runtime changes.

## Consequences and tradeoffs

- **One codebase, environment-keyed drivers.** The MCP investment is preserved, and
  the internal path reuses already-approved Claude headless — nothing new to get
  approved.
- **CLI driver is clunkier for the model than MCP.** Structured tool schemas become
  CLI strings plus parsed (JSON) output, so the model needs a clear tool contract.
  Manageable, but more prompt/contract upkeep than MCP's auto-discovery.
- **The per-archetype tool boundary moves.** Today it is `--allowedTools
  mcp__overwatch__*`; under the CLI driver it becomes `--allowedTools
  "Bash(overwatch:*)"` plus CLI-side enforcement of the archetype's scope. Still a
  real boundary, enforced differently.
- **The Bash-guard hook flips meaning.** Today it blocks raw target-facing Bash;
  under the CLI driver it must *allow* the `overwatch` CLI while still blocking other
  target-facing shell.

!!! note "Open question — refines the driver, does not block the decision"
    Is the internal restriction on **MCP-the-protocol**, or only on **registering
    non-approved MCP servers** in the client? If it is the latter, the Claude Agent
    SDK's in-process tools (`createSdkMcpServer` — in-memory, no network server,
    nothing to register) would give *structured* tools without an approvable server,
    which is cleaner than CLI strings. We believe it is the latter but are not
    certain; confirm with the platform/policy owners before building the CLI driver.

## Future implementation (when internal need arrives)

Sequenced so each step is independently useful:

1. **Local execution surface** — `POST /api/actions/run` (+ `run_tool`, sessions) on
   the dashboard server → `runInstrumentedProcess`. This also completes the
   **human-only console**: operators get target execution without MCP.
2. **`overwatch` CLI** — a thin client over that surface (repoint the existing
   [CLI Adapter](playbook/cli-adapter.md) from `/mcp` to the local HTTP). Emits clean
   JSON for the model to parse.
3. **Runner driver swap** — `headless-mcp-runner.ts` gains a non-MCP mode: drop
   `--mcp-config`, set `--allowedTools "Bash(overwatch:*)"`, inject the CLI tool
   contract into the system prompt.
4. **Hook update** — the Bash-guard allows `overwatch …` and blocks other
   target-facing Bash.
5. **Parity tests** — assert the non-MCP driver produces identical
   `action_started` / evidence / `action_completed` audit events to the MCP driver.

## Non-goals

- Not removing or deprecating MCP — it is the external-lab driver and stays
  first-class.
- Not adopting LangGraph, Temporal, or A2A as part of this decision.
- Not depending on Bedrock-specific APIs or on controlling Bedrock model settings.

## See also

- [Architecture Overview](architecture.md) — component map and the executor seam.
- [Operator Cockpit](operator-cockpit.md#roles) — the headless multi-agent runtime
  and per-role tool surfaces.
- [Bedrock Integration Plan](bedrock-integration-plan.md) — system-contract and
  middleware work for enterprise Bedrock clients.
- [CLI Adapter](playbook/cli-adapter.md) — the shell surface the internal driver
  builds on.
