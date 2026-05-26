import type { McpToolRegistryResponse, ToolCheckResult } from './types';

export interface SmokeValidationResult {
  ok: boolean;
  status?: 'pass' | 'warn' | 'fail';
  detail?: string;
  expected?: string;
  actualKeys?: string[];
  action?: string;
}

const CORE_MCP_TOOLS = [
  'get_state',
  'validate_action',
  'run_bash',
  'parse_output',
  'report_finding',
  'get_system_prompt',
];

export function topLevelKeys(value: unknown): string[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return [];
  return Object.keys(value as Record<string, unknown>).sort();
}

function fail(detail: string, expected: string, data: unknown, action?: string): SmokeValidationResult {
  return {
    ok: false,
    status: 'fail',
    detail,
    expected,
    actualKeys: topLevelKeys(data),
    action,
  };
}

export function validatePendingActionsSmoke(data: unknown): SmokeValidationResult {
  const expected = '{ pending: [], count: number }';
  if (!data || typeof data !== 'object') {
    return fail('shape mismatch: response is not an object', expected, data);
  }
  const body = data as { pending?: unknown; count?: unknown };
  if (!Array.isArray(body.pending)) {
    return fail('shape mismatch: pending field missing', expected, data);
  }
  if (typeof body.count !== 'number') {
    return fail('shape mismatch: count field missing', expected, data);
  }
  if (body.count !== body.pending.length) {
    return fail('shape mismatch: count does not match pending length', expected, data);
  }
  return { ok: true, status: 'pass' };
}

export function validateHostToolsSmoke(data: unknown): SmokeValidationResult {
  const expected = '{ installed_count: number, missing_count: number, tools: ToolStatus[] }';
  if (!data || typeof data !== 'object') {
    return fail('endpoint broken: response is not an object', expected, data);
  }
  const body = data as Partial<ToolCheckResult>;
  if (!Array.isArray(body.tools) || typeof body.installed_count !== 'number' || typeof body.missing_count !== 'number') {
    return fail('shape mismatch: host tool inventory fields missing', expected, data);
  }
  if (body.installed_count + body.missing_count !== body.tools.length) {
    return fail('shape mismatch: installed + missing does not equal tools length', expected, data);
  }
  if (body.tools.length === 0) {
    return fail('endpoint broken: host tool inventory is empty', expected, data);
  }
  if (body.missing_count > 0) {
    return {
      ok: false,
      status: 'warn',
      detail: `${body.missing_count} optional host tool${body.missing_count === 1 ? '' : 's'} missing`,
      expected,
      actualKeys: topLevelKeys(data),
      action: 'Install only the tools required for this engagement profile.',
    };
  }
  return { ok: true, status: 'pass' };
}

export function validateMcpToolsSmoke(data: unknown): SmokeValidationResult {
  const expected = '{ total: number, categories: Record<string, number>, tools: McpToolInfo[] }';
  if (!data || typeof data !== 'object') {
    return fail('endpoint broken: response is not an object', expected, data);
  }
  const body = data as Partial<McpToolRegistryResponse>;
  if (!Array.isArray(body.tools) || typeof body.total !== 'number' || !body.categories || typeof body.categories !== 'object') {
    return fail('shape mismatch: MCP registry fields missing', expected, data);
  }
  if (body.total !== body.tools.length) {
    return fail('shape mismatch: total does not match tools length', expected, data);
  }
  const names = new Set(body.tools.map(tool => tool.name));
  const missingCore = CORE_MCP_TOOLS.filter(name => !names.has(name));
  if (missingCore.length > 0) {
    return {
      ok: false,
      status: 'fail',
      detail: `MCP registry missing core tools: ${missingCore.join(', ')}`,
      expected,
      actualKeys: topLevelKeys(data),
      action: 'Restart the Overwatch MCP server and check tool registration logs.',
    };
  }
  return { ok: true, status: 'pass' };
}
