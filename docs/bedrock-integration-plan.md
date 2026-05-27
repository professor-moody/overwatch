# Bedrock Integration Plan

This is a future implementation plan for enterprise Claude deployments that call Anthropic models through Amazon Bedrock. It is not required for normal Claude Code + MCP usage.

## Current Reality

Overwatch exposes dynamic operating instructions through the MCP tool `get_system_prompt(role="primary")`. In Claude Code, that prompt is returned as a tool result inside the conversation, not inserted into the provider-level `system` field.

That distinction matters:

- Overwatch MCP can generate the engagement briefing, tool contract, OPSEC reminders, and graph workflow.
- The MCP server cannot force Bedrock's `system` field to contain those instructions.
- Only the Bedrock client or enterprise wrapper that constructs the API payload can place text in the `system` field.
- Claude Code hooks are local Claude Code behavior. Bedrock integrations need equivalent middleware if they want the same grounding or Bash-guard behavior.

## Goal

Keep the live engagement state in Overwatch, while giving enterprise Bedrock clients a compact system-level contract that says how the model should use Overwatch.

The system field should be stable and short. Live state should continue to come from `get_system_prompt(role="primary")`, `get_state()`, `next_task()`, and graph queries.

## Proposed Phases

### Phase 1: Client Contract

Document a small Bedrock system contract for wrapper teams:

```text
You are operating inside an authorized Overwatch engagement.
Use Overwatch MCP tools as the source of truth for scope, state, objectives, actions, evidence, and findings.
At session start and after compaction, call get_system_prompt(role="primary"), then get_state().
Do not answer engagement-state questions from memory. Route recon output through parse_output, report_finding, or ingest_json.
Use run_tool/run_bash/open_session through Overwatch for target-facing execution.
```

This gives Bedrock a durable anchor without duplicating the full generated prompt.

### Phase 2: Payload Examples

Add examples for common Bedrock wrapper shapes:

- `system`: compact Overwatch contract.
- `messages`: user request and prior transcript.
- `tools`: MCP tool definitions exposed by the client runtime.
- first model action: call `get_system_prompt(role="primary")`.

The examples should make clear that the generated Overwatch prompt is still tool-returned context unless the wrapper explicitly promotes a compact contract into `system`.

### Phase 3: Middleware Parity

Implement optional wrapper middleware equivalent to the Claude Code hooks:

- User-prompt grounding: prepend a short engagement reminder when the prompt is clearly engagement work.
- Tool-use guard: block raw target-facing shell execution unless routed through Overwatch.
- Post-tool nudge: if command output looks like discovery data, remind the model to ingest it.
- Stop check: detect drift and require graph ingestion before continuing.

These behaviors belong in the enterprise client or gateway, not the MCP server.

### Phase 4: Verification

Add a Bedrock smoke harness that verifies:

- the payload `system` contains the compact Overwatch contract;
- the first turn calls `get_system_prompt(role="primary")`;
- target-facing commands are routed through Overwatch tools;
- discovery output is ingested into the graph or explicitly marked as non-discovery;
- tape/activity logs show the expected attribution.

## Non-Goals

- Do not move the full generated system prompt into static docs.
- Do not make Overwatch depend on Bedrock-specific APIs.
- Do not duplicate live engagement state into the system field.
- Do not replace MCP tools with prompt-only workflow instructions.

## Operational Guidance

For now, treat Bedrock support as a client integration concern. Overwatch should continue to provide a clear dynamic prompt and reliable MCP tool behavior. When an enterprise wrapper controls the API payload, it can add the compact contract to `system`; otherwise, `get_system_prompt(role="primary")` remains the authoritative runtime bootstrap.
