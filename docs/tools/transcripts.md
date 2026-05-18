# Transcript Tools

Import and preserve agent/session transcripts for retrospectives.

## Tools

| Tool | Read-only | Purpose |
|------|-----------|---------|
| `ingest_transcript` | No | Import an external chat or IDE JSONL transcript into the activity log. |
| `submit_agent_transcript` | No | Let a sub-agent submit a wrap-up and optional raw transcript evidence before completion. |

## `ingest_transcript`

Accepts either `transcript_path` or raw `transcript_jsonl`, plus a `session_id`. The full transcript is stored as evidence, while compact per-turn `transcript_turn_ingested` events are written to the activity log with `provenance: "ingested"` by default.

The tool is idempotent by transcript SHA-256. Re-ingesting the same blob returns `ingested: false` and records an instrumentation warning.

## `submit_agent_transcript`

Sub-agents should call this before `update_agent(status: "completed")`. The required `summary` gives the primary a short handoff; optional `transcript_jsonl` is stored as evidence and linked to the agent task.

Prefer `task_id` from `register_agent`. The legacy `agent_id` parameter is still accepted as an alias or fallback lookup.
