import { describe, expect, it } from 'vitest';
import {
  validateHostToolsSmoke,
  validateMcpToolsSmoke,
  validatePendingActionsSmoke,
} from '../smoke-checks';
import { TOOL_CATEGORIES, TOOL_REGISTRY_SHA256 } from '../tool-categories.generated';

const canonicalCategories = Object.fromEntries(
  TOOL_CATEGORIES.map(category => [category.id, category.count]),
);
const canonicalTotal = TOOL_CATEGORIES.reduce((total, category) => total + category.count, 0);

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
    const names = [...core, ...Array.from({ length: canonicalTotal - core.length }, (_, index) => `tool_${index}`)];
    const result = validateMcpToolsSmoke({
      total: canonicalTotal,
      registry_sha256: TOOL_REGISTRY_SHA256,
      categories: canonicalCategories,
      tools: names.map(name => ({ name, description: name, category: 'generated' })),
    });
    expect(result).toEqual({ ok: true, status: 'pass' });
  });

  it('fails MCP registry responses missing core workflow tools', () => {
    const result = validateMcpToolsSmoke({
      total: canonicalTotal,
      registry_sha256: TOOL_REGISTRY_SHA256,
      categories: canonicalCategories,
      tools: Array.from({ length: canonicalTotal }, (_, index) => ({
        name: index === 0 ? 'get_state' : `tool_${index}`,
        description: 'state',
        category: 'generated',
      })),
    });
    expect(result.ok).toBe(false);
    expect(result.status).toBe('fail');
    expect(result.detail).toContain('validate_action');
  });

  it('fails when the daemon and dashboard were built from different tool registries', () => {
    const result = validateMcpToolsSmoke({
      total: canonicalTotal,
      registry_sha256: '0'.repeat(64),
      categories: canonicalCategories,
      tools: Array.from({ length: canonicalTotal }, (_, index) => ({
        name: `tool_${index}`,
        description: 'tool',
        category: 'generated',
      })),
    });
    expect(result.ok).toBe(false);
    expect(result.detail).toContain('does not match this dashboard build');
    expect(result.action).toContain('Rebuild');
  });
});
