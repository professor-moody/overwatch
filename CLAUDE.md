# Overwatch Bootstrap

Use dynamic instructions, not this file, as the source of truth.

At session start — and after any compaction — immediately call `get_system_prompt(role="primary")` and follow the returned instructions.

If `get_system_prompt` is unavailable, fall back to [AGENTS.md](./AGENTS.md) (includes a static [tool reference](./AGENTS.md#tool-reference) for offline use).

Do not treat this file as the engagement briefing or tool reference.
Those are generated dynamically from current engagement state.
