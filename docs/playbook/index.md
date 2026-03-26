# Operator Playbook

Step-by-step guides for running engagements with Overwatch.

## Engagement Lifecycle

```
Init → Bootstrap → Main Loop → Recovery → Retrospective
```

### 1. Init

The operator writes the engagement config (`engagement.json`) defining scope, objectives, and OPSEC policy. The server starts, seeds the graph with scope nodes (CIDR ranges, domains).

### 2. Bootstrap

The primary session discovers live hosts, enumerates services, and populates the graph. Inference rules fire automatically on new findings to generate hypothesis edges.

Key tools:

- [`get_state`](../tools/get-state.md) — load the engagement briefing
- [`run_lab_preflight`](../tools/run-lab-preflight.md) — validate the environment
- [`check_tools`](../tools/check-tools.md) — verify available tooling
- [`ingest_bloodhound`](../tools/ingest-bloodhound.md) — bulk import AD data
- [`parse_output`](../tools/parse-output.md) — ingest nmap/nxc results

### 3. Main Loop

The core cycle:

1. **Get frontier** — [`next_task`](../tools/next-task.md) returns filtered candidates
2. **Score and prioritize** — the LLM evaluates attack chains, sequencing, risk
3. **Validate** — [`validate_action`](../tools/validate-action.md) checks scope, OPSEC, existence
4. **Log start** — [`log_action_event`](../tools/log-action-event.md) with `action_started`
5. **Execute** — run the tool/command
6. **Report** — [`parse_output`](../tools/parse-output.md) or [`report_finding`](../tools/report-finding.md)
7. **Log completion** — [`log_action_event`](../tools/log-action-event.md) with `action_completed`
8. **Dispatch agents** — [`register_agent`](../tools/register-agent.md) for parallel work

### 4. Recovery

After context compaction, `get_state()` rebuilds the full engagement context from the graph. Zero information loss. The engagement can also resume after:

- Claude Code restart
- Server restart
- Days later from a fresh session

### 5. Objective Tracking

Graph path analysis detects when objectives are achieved. The engine matches graph nodes against objective criteria and updates status automatically.

### 6. Retrospective

Post-engagement analysis produces:

- Skill updates and gap analysis
- New inference rule suggestions
- Context improvement recommendations
- Client-deliverable report
- Training traces for model improvement

See [Retrospectives](retrospective.md) for details.

## Lab Workflows

- [GOAD AD Lab](goad-lab.md) — multi-host Active Directory lab
- [HTB / Single Host](htb-single.md) — standalone target VM

## Guides

- [CLI Adapter](cli-adapter.md) — operate Overwatch via shell when MCP is unavailable
- [Session Instructions](session-instructions.md) — primary session and sub-agent setup
- [parse_output vs report_finding](parse-vs-report.md) — when to use which
- [Retrospectives](retrospective.md) — post-engagement analysis
