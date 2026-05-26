import { describe, expect, it } from 'vitest';
import {
  validateHostToolsSmoke,
  validateMcpToolsSmoke,
  validatePendingActionsSmoke,
} from '../smoke-checks';

describe('dashboard smoke response contracts', () => {
  it('accepts the current pending-action response shape', () => {
    expect(validatePendingActionsSmoke({ pending: [], count: 0 })).toEqual({ ok: true, status: 'pass' });
  });

  it('rejects the stale pending-action actions[] shape with diagnostics', () => {
    const result = validatePendingActionsSmoke({ actions: [] });
    expect(result.ok).toBe(false);
    expect(result.status).toBe('fail');
    expect(result.expected).toBe('{ pending: [], count: number }');
    expect(result.actualKeys).toEqual(['actions']);
  });

  it('warns when host-tool inventory is valid but optional binaries are missing', () => {
    const result = validateHostToolsSmoke({
      installed_count: 1,
      missing_count: 1,
      tools: [
        { name: 'nmap', installed: true },
        { name: 'certipy', installed: false },
      ],
    });
    expect(result.ok).toBe(false);
    expect(result.status).toBe('warn');
    expect(result.detail).toContain('optional host tool');
  });

  it('accepts MCP registry responses that include core workflow tools', () => {
    const core = ['get_state', 'validate_action', 'run_bash', 'parse_output', 'report_finding', 'get_system_prompt'];
    const result = validateMcpToolsSmoke({
      total: core.length,
      categories: { core: core.length },
      tools: core.map(name => ({ name, description: name, category: 'core' })),
    });
    expect(result).toEqual({ ok: true, status: 'pass' });
  });

  it('fails MCP registry responses missing core workflow tools', () => {
    const result = validateMcpToolsSmoke({
      total: 1,
      categories: { core: 1 },
      tools: [{ name: 'get_state', description: 'state', category: 'core' }],
    });
    expect(result.ok).toBe(false);
    expect(result.status).toBe('fail');
    expect(result.detail).toContain('validate_action');
  });
});
