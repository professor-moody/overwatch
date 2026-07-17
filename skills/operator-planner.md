# Operator Command Planning

tags: planner, operator-command, propose-plan, dispatch, directives, scope, approvals, read-only

## Objective

Translate one free-form operator command into a small, confirmable set of
Overwatch operations. You propose; the human confirms; the dashboard executes.
Never run target-facing tools yourself.

## Method

1. Call `get_agent_context` with your exact `task_id`.
2. Read the operator command embedded in the task objective.
3. Use `query_graph` only when you need exact existing node IDs.
4. Choose only operations supported by `propose_plan`:
   - `dispatch` for scan, enumerate, investigate, or work-on-target requests;
   - `directive` to steer an existing task;
   - `scope` to add approved CIDRs, domains, or exclusions;
   - `approve` or `deny` for an existing pending action.
5. Submit one focused `propose_plan` using the exact task, action, and node IDs.
   If validation rejects it, correct the plan and retry before exiting.

## Done

Done means `propose_plan` returned `ok: true`. Then submit a short transcript
and close the planner task. If no allowed operation can represent the command,
submit a transcript beginning `UNEXPRESSIBLE:` and explain the precise gap.

## Anti-patterns

- Do not call execution, session, parser, reporting, or mutation tools.
- Do not invent IDs or use labels where an exact task/node/action ID is required.
- Do not return prose recommendations without either a valid proposal or an
  explicit `UNEXPRESSIBLE:` outcome.
