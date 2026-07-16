// ============================================================
// Overwatch — Tool Error Boundary
// Wraps MCP tool handlers so unhandled errors return structured
// error responses instead of crashing the server process.
// ============================================================

import type { ToolTelemetry } from '../services/tool-telemetry.js';

// Shared telemetry instance — set once at startup via setTelemetry()
let _telemetry: ToolTelemetry | null = null;

export function setTelemetry(t: ToolTelemetry): void {
  _telemetry = t;
}

export function getTelemetry(): ToolTelemetry | null {
  return _telemetry;
}

/**
 * Wraps an MCP tool handler with error handling and optional telemetry.
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
    const start = Date.now();
    try {
      const result = handler(...args);
      // Handle both sync and async handlers
      if (result && typeof result.then === 'function') {
        return (result as Promise<any>)
          .then((res: any) => {
            _telemetry?.record(toolName, Date.now() - start, false);
            return res;
          })
          .catch((err: unknown) => {
            _telemetry?.record(toolName, Date.now() - start, true);
            return handleError(toolName, err);
          });
      }
      _telemetry?.record(toolName, Date.now() - start, false);
      return result;
    } catch (err: unknown) {
      _telemetry?.record(toolName, Date.now() - start, true);
      return handleError(toolName, err);
    }
  }) as T;
  return wrapped;
}

export type ErrorClassification = 'validation_error' | 'not_found' | 'scope_violation' | 'internal_error';

function classifyError(message: string): ErrorClassification {
  const lower = message.toLowerCase();
  if (lower.includes('not found') || lower.includes('does not exist') || lower.includes('no such')) return 'not_found';
  if (lower.includes('not in scope') || lower.includes('scope violation') || lower.includes('out of scope')) return 'scope_violation';
  if (lower.includes('invalid') || lower.includes('validation') || lower.includes('required') || lower.includes('must be')) return 'validation_error';
  return 'internal_error';
}

function handleError(toolName: string, err: unknown) {
  const message = err instanceof Error ? err.message : String(err);
  const stack = err instanceof Error ? err.stack : undefined;
  const code = typeof (err as { code?: unknown } | null)?.code === 'string'
    ? (err as { code: string }).code
    : undefined;
  console.error(`[ERROR] Tool "${toolName}" threw:`, message);
  if (stack) console.error(stack);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        success: false,
        error: message,
        classification: classifyError(message),
        ...(code ? { code } : {}),
        tool: toolName,
      }),
    }],
    isError: true,
  };
}

/**
 * Convenience: build a successful MCP tool response.
 */
export function toolSuccess(data: unknown, warnings?: string[]) {
  const payload: Record<string, unknown> = { success: true, data };
  if (warnings && warnings.length > 0) payload.warnings = warnings;
  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify(payload, null, 2),
    }],
  };
}

/**
 * Convenience: build a failed MCP tool response with isError flag.
 */
export function toolError(error: string, classification: ErrorClassification, toolName?: string) {
  const payload: Record<string, unknown> = { success: false, error, classification };
  if (toolName) payload.tool = toolName;
  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify(payload),
    }],
    isError: true,
  };
}
