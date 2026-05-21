# Overwatch Bootstrap

Use dynamic instructions, not this file, as the source of truth.

At session start — and after any compaction — immediately call `get_system_prompt(role="primary")` and follow the returned instructions.

If `get_system_prompt` is unavailable, fall back to [AGENTS.md](./AGENTS.md) (includes a static [tool reference](./AGENTS.md#tool-reference) for offline use).

Do not treat this file as the engagement briefing or tool reference.
Those are generated dynamically from current engagement state.

When changing operator workflow, keep `src/services/prompt-generator.ts`, [AGENTS.md](./AGENTS.md), and [docs/tools/index.md](./docs/tools/index.md) aligned. The generated prompt wins at runtime; the markdown files are bootstrap and offline fallbacks.

Claude Code hooks in `.claude/hooks/` reinforce this at runtime: they add grounding context, block raw target-facing Bash, and nudge discovery output back into the graph. Keep hook behavior aligned with the generated prompt.

**Important:** pulling the repo does not activate MCP or hooks by itself. `.mcp.json` and `.claude/settings.json` are local and gitignored. Recommended setup: copy `.mcp.example.json` to `.mcp.json` for MCP, and copy `.claude/settings.example.json` to `.claude/settings.json` for hooks. See [Claude Code Hooks](docs/claude-hooks.md).
