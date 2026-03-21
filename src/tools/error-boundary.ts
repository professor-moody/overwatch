// ============================================================
// Overwatch — Tool Error Boundary
// Wraps MCP tool handlers so unhandled errors return structured
// error responses instead of crashing the server process.
// ============================================================

/**
 * Wraps an MCP tool handler with error handling.
 * On unhandled throw, logs tool name + full stack trace to stderr
 * and returns an MCP-compliant isError response to the LLM.
 *
 * Bootstrap/startup code in index.ts should NOT use this —
 * real process-level failures must crash loudly.
 */
export function withErrorBoundary<T extends (...args: any[]) => any>(
  toolName: string,
  handler: T,
): T {
  const wrapped = ((...args: any[]) => {
    try {
      const result = handler(...args);
      // Handle both sync and async handlers
      if (result && typeof result.then === 'function') {
        return (result as Promise<any>).catch((err: unknown) => {
          return handleError(toolName, err);
        });
      }
      return result;
    } catch (err: unknown) {
      return handleError(toolName, err);
    }
  }) as T;
  return wrapped;
}

function handleError(toolName: string, err: unknown) {
  const message = err instanceof Error ? err.message : String(err);
  const stack = err instanceof Error ? err.stack : undefined;
  console.error(`[ERROR] Tool "${toolName}" threw:`, message);
  if (stack) console.error(stack);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        error: message,
        tool: toolName,
      }),
    }],
    isError: true,
  };
}
