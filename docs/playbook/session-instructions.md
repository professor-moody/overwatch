# Session Instructions

How to configure the primary session and sub-agents for Overwatch.

## Primary Session

The primary session runs Claude Code (Opus) with Overwatch as an MCP server. It follows this core loop:

### Core Loop

1. **Start every session** by calling `get_state()` — this gives the complete engagement briefing from the graph (scope, discoveries, access, objectives, frontier)

2. **Assess the frontier** by calling `next_task()` — candidates are pre-filtered by the deterministic layer (out-of-scope, duplicates, OPSEC vetoes already removed)

3. **Score and prioritize** the candidates. For each, consider:
    - Does this open a multi-step attack chain?
    - What's the likely defensive posture?
    - What sequencing makes sense?
    - What's the risk/reward ratio given the OPSEC profile?
    - Does this move toward an objective?

4. **Explore the graph** with `query_graph()` when the frontier doesn't capture a pattern you're seeing

5. **Validate before executing** with `validate_action()` — catches scope violations, OPSEC blacklist hits, and impossible targets

6. **Log execution start** with `log_action_event(event_type="action_started")` before major tool execution

7. **Execute** using shell commands, scripts, or other tools

8. **Parse or report results**:
    - Use `parse_output()` for supported tool output (nmap, nxc, certipy, etc.)
    - Use `report_finding()` for manual observations or unsupported tools

9. **Log completion** with `log_action_event(event_type="action_completed" | "action_failed")`

10. **Dispatch sub-agents** with `register_agent()` for parallel work

11. **Monitor and re-plan** by periodically calling `get_state()` to see new frontier items from agent findings

### Key Principles

- **The graph is your memory** — after compaction, `get_state()` reconstructs everything
- **Report early, report often** — every finding triggers inference rules that may surface new attack paths
- **Use structured action logging** — `validate_action()` gives the `action_id`; `log_action_event()` records execution
- **The deterministic layer is a guardrail, not a brain** — it filters the impossible; the LLM does the offensive thinking
- **Validate before you execute** — every significant action goes through `validate_action()` first
- **Use `query_graph()` liberally** — if you have a hunch about a relationship, query for it
- **Respect OPSEC** — check the engagement's OPSEC profile and factor noise levels into decisions

## Sub-Agent Instructions

When dispatching sub-agents via `register_agent`, give them these instructions:

> You are an Overwatch sub-agent working a specific task. Your tools:
>
> - `get_agent_context` — get your scoped subgraph view
> - `validate_action` — check before executing
> - `log_action_event` — record action start/completion/failure
> - `parse_output` — use for supported raw tool output
> - `report_finding` — report every discovery immediately
> - `query_graph` — explore the graph for more context
> - `get_skill` — get methodology guidance for your task
>
> Work your assigned task. Validate first, log execution start, execute, parse/report findings, then log completion or failure.

### Sub-Agent Workflow

1. Call `get_agent_context` with the `task_id` to receive the scoped subgraph
2. Review the frontier item and assigned skill
3. Call `validate_action` before each significant action
4. Call `log_action_event(event_type="action_started")`
5. Execute the tool/command
6. Call `parse_output` or `report_finding` with results
7. Call `log_action_event(event_type="action_completed" | "action_failed")`
8. The primary session will call `update_agent` to mark the task complete

## AGENTS.md

Place the primary session instructions in an `AGENTS.md` file at the project root (gitignored by default). Claude Code reads this file automatically at session start.
