// ============================================================
// Shared MCP tool-output serialization
// ============================================================
// The heavy read tools (get_state, next_task, query_graph, find_paths) return
// large JSON payloads to the model. Pretty-printing (`JSON.stringify(x, null, 2)`)
// adds ~20-30% token overhead that the model gains nothing from. `toolText` lets
// those tools serialize compactly when the caller opts in via a `compact` param;
// the default stays pretty so behavior is unchanged for everyone else.

export interface ToolTextResult {
  // The MCP SDK's CallToolResult carries an index signature; a named return type
  // must declare one too (object literals are exempt, named interfaces are not).
  [x: string]: unknown;
  content: Array<{ type: 'text'; text: string }>;
}

/** Build a `{ content: [{ type: 'text', text }] }` tool result. Compact JSON when
 *  `opts.compact` is true (no indentation), pretty-printed otherwise. */
export function toolText(value: unknown, opts?: { compact?: boolean }): ToolTextResult {
  const text = opts?.compact ? JSON.stringify(value) : JSON.stringify(value, null, 2);
  return { content: [{ type: 'text', text }] };
}

/** The opt-in `compact` input-schema description, shared across the heavy tools. */
export const COMPACT_PARAM_DESCRIPTION =
  'Return compact JSON (no indentation) to save tokens. Default false (pretty-printed). The payload is identical either way — only whitespace differs.';
