// ============================================================
// Overwatch — Transcript Parser
// Flexible JSONL → typed turn parser. Supports several common
// chat-transcript shapes (Copilot, Claude, OpenAI tool-calls,
// generic role-based) and extracts an Overwatch action_id when a
// tool-call/tool-result record references one.
// ============================================================

export type TranscriptTurnRole = 'user' | 'assistant' | 'tool_call' | 'tool_result' | 'system' | 'unknown';

export interface ParsedTranscriptTurn {
  index: number;            // 0-based position in the JSONL stream
  role: TranscriptTurnRole;
  tool_name?: string;       // for tool_call / tool_result
  action_id?: string;       // extracted from tool args / result when present
  summary: string;          // short, single-line description (~200 chars max)
  raw_size: number;         // byte length of the original record
}

export interface ParseTranscriptResult {
  turns: ParsedTranscriptTurn[];
  parse_errors: Array<{ line: number; reason: string }>;
}

const SUMMARY_MAX = 200;

function summarize(text: unknown): string {
  if (text === undefined || text === null) return '';
  const s = typeof text === 'string' ? text : JSON.stringify(text);
  const oneLine = s.replace(/\s+/g, ' ').trim();
  return oneLine.length > SUMMARY_MAX ? `${oneLine.slice(0, SUMMARY_MAX - 1)}…` : oneLine;
}

function pickFirstString(obj: any, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = obj?.[k];
    if (typeof v === 'string' && v.length > 0) return v;
  }
  return undefined;
}

function extractActionId(payload: any): string | undefined {
  if (!payload || typeof payload !== 'object') return undefined;
  // Common locations: top-level action_id, nested in arguments/input/params/result
  const direct = pickFirstString(payload, ['action_id']);
  if (direct) return direct;
  for (const key of ['arguments', 'args', 'input', 'params', 'result', 'output', 'content']) {
    const inner = payload[key];
    if (typeof inner === 'object' && inner !== null) {
      const found = pickFirstString(inner, ['action_id']);
      if (found) return found;
    }
    // Sometimes arguments are encoded as a JSON string
    if (typeof inner === 'string' && inner.includes('action_id')) {
      try {
        const parsed = JSON.parse(inner);
        const found = pickFirstString(parsed, ['action_id']);
        if (found) return found;
      } catch { /* not JSON, ignore */ }
    }
  }
  return undefined;
}

function classifyRole(record: any): TranscriptTurnRole {
  if (!record || typeof record !== 'object') return 'unknown';

  // Explicit role field (OpenAI / Claude / Copilot common)
  const role = typeof record.role === 'string' ? record.role.toLowerCase() : undefined;
  const type = typeof record.type === 'string' ? record.type.toLowerCase() : undefined;

  // Tool-call indicators
  if (type === 'tool_use' || type === 'tool_call' || role === 'tool_call') return 'tool_call';
  if (type === 'tool_result' || role === 'tool' || role === 'tool_result' || role === 'function') return 'tool_result';

  // OpenAI-style: assistant message containing tool_calls array
  if (role === 'assistant' && Array.isArray(record.tool_calls) && record.tool_calls.length > 0) return 'tool_call';

  if (role === 'user' || type === 'user' || type === 'human') return 'user';
  if (role === 'assistant' || type === 'assistant' || type === 'ai') return 'assistant';
  if (role === 'system' || type === 'system') return 'system';

  return 'unknown';
}

function extractToolName(record: any, role: TranscriptTurnRole): string | undefined {
  if (role !== 'tool_call' && role !== 'tool_result') return undefined;
  const name = pickFirstString(record, ['tool_name', 'name', 'tool', 'function_name']);
  if (name) return name;
  // OpenAI style: tool_calls[0].function.name
  if (Array.isArray(record?.tool_calls) && record.tool_calls.length > 0) {
    const tc = record.tool_calls[0];
    return pickFirstString(tc?.function ?? tc, ['name']);
  }
  return undefined;
}

function summaryForRecord(record: any, role: TranscriptTurnRole, toolName?: string): string {
  if (role === 'user' || role === 'assistant' || role === 'system') {
    // content can be a string or an array of {type,text} blocks
    const content = record.content ?? record.text ?? record.message;
    if (typeof content === 'string') return summarize(content);
    if (Array.isArray(content)) {
      const text = content
        .map((c: any) => (typeof c === 'string' ? c : (typeof c?.text === 'string' ? c.text : '')))
        .filter(Boolean)
        .join(' ');
      if (text) return summarize(text);
    }
    return summarize(record.content ?? record);
  }
  if (role === 'tool_call') {
    return summarize(`${toolName ?? 'tool'} call`);
  }
  if (role === 'tool_result') {
    const out = record.output ?? record.result ?? record.content;
    return summarize(`${toolName ?? 'tool'} result: ${typeof out === 'string' ? out : JSON.stringify(out ?? '')}`);
  }
  return summarize(record);
}

/**
 * Parse a JSONL transcript blob into typed turns. Lines that are blank or
 * cannot be parsed as JSON are recorded in `parse_errors` and skipped; a
 * malformed file does not throw.
 */
export function parseTranscriptJsonl(jsonl: string): ParseTranscriptResult {
  const lines = jsonl.split(/\r?\n/);
  const turns: ParsedTranscriptTurn[] = [];
  const parse_errors: Array<{ line: number; reason: string }> = [];

  let index = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().length === 0) continue;
    let record: any;
    try {
      record = JSON.parse(line);
    } catch (err) {
      parse_errors.push({ line: i + 1, reason: (err as Error).message });
      continue;
    }
    const role = classifyRole(record);
    const tool_name = extractToolName(record, role);
    const action_id = extractActionId(record);
    turns.push({
      index,
      role,
      tool_name,
      action_id,
      summary: summaryForRecord(record, role, tool_name),
      raw_size: line.length,
    });
    index += 1;
  }

  return { turns, parse_errors };
}

/** Stable hash for idempotency. SHA-256 hex of the raw blob. */
export async function hashTranscript(jsonl: string): Promise<string> {
  const { createHash } = await import('crypto');
  return createHash('sha256').update(jsonl).digest('hex');
}
