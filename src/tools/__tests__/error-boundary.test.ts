import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { withErrorBoundary, setTelemetry, getTelemetry, toolSuccess, toolError } from '../error-boundary.js';
import { ToolTelemetry } from '../../services/tool-telemetry.js';

describe('withErrorBoundary', () => {
  it('passes through successful returns unchanged', async () => {
    const handler = async (args: any) => ({
      content: [{ type: 'text' as const, text: String(args.x) }],
    });
    const wrapped = withErrorBoundary('test_tool', handler);
    const result: any = await wrapped({ x: 42 });
    expect(result.content[0].text).toBe('42');
    expect(result.isError).toBeUndefined();
  });

  it('catches throw and returns isError with tool name + logs stack', async () => {
    const handler = async (_args: any) => {
      throw new Error('kaboom');
    };
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const wrapped = withErrorBoundary('exploding_tool', handler);
    const result: any = await wrapped({});

    expect(result.isError).toBe(true);
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.error).toBe('kaboom');
    expect(parsed.tool).toBe('exploding_tool');
    expect(parsed.success).toBe(false);
    expect(parsed.classification).toBe('internal_error');

    // Verify it logged tool name and stack
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('exploding_tool'),
      expect.stringContaining('kaboom'),
    );
    // Stack trace should also be logged
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('Error: kaboom'),
    );
    consoleSpy.mockRestore();
  });

  it('catches async rejection and returns isError', async () => {
    const handler = async (_args: any) => {
      await Promise.resolve();
      throw new Error('async boom');
    };
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const wrapped = withErrorBoundary('async_tool', handler);
    const result: any = await wrapped({});

    expect(result.isError).toBe(true);
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.error).toBe('async boom');
    expect(parsed.tool).toBe('async_tool');
    consoleSpy.mockRestore();
  });

  it('handles non-Error throws (string)', async () => {
    const handler = async (_args: any) => {
      throw 'string error';
    };
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const wrapped = withErrorBoundary('string_throw', handler);
    const result: any = await wrapped({});

    expect(result.isError).toBe(true);
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.error).toBe('string error');
    consoleSpy.mockRestore();
  });

  it('preserves extra properties on successful return', async () => {
    const handler = async (_args: any) => ({
      content: [{ type: 'text' as const, text: 'ok' }],
      _meta: { custom: true },
    });
    const wrapped = withErrorBoundary('typed_tool', handler);
    const result: any = await wrapped({ name: 'test' });
    expect(result.content[0].text).toBe('ok');
    expect(result._meta).toEqual({ custom: true });
  });

  it('classifies "not found" errors correctly', async () => {
    const handler = async (_args: any) => { throw new Error('Node xyz does not exist'); };
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const wrapped = withErrorBoundary('test', handler);
    const result: any = await wrapped({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.classification).toBe('not_found');
    consoleSpy.mockRestore();
  });

  it('classifies scope violation errors correctly', async () => {
    const handler = async (_args: any) => { throw new Error('Target not in scope'); };
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const wrapped = withErrorBoundary('test', handler);
    const result: any = await wrapped({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.classification).toBe('scope_violation');
    consoleSpy.mockRestore();
  });

  it('classifies validation errors correctly', async () => {
    const handler = async (_args: any) => { throw new Error('Invalid input: must be a string'); };
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const wrapped = withErrorBoundary('test', handler);
    const result: any = await wrapped({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.classification).toBe('validation_error');
    consoleSpy.mockRestore();
  });
});

describe('telemetry integration', () => {
  let savedTelemetry: any;

  beforeEach(() => {
    savedTelemetry = getTelemetry();
    setTelemetry(new ToolTelemetry());
  });

  afterEach(() => {
    setTelemetry(savedTelemetry);
  });

  it('records successful calls via withErrorBoundary', async () => {
    const handler = async (_args: any) => ({ content: [{ type: 'text' as const, text: 'ok' }] });
    const wrapped = withErrorBoundary('my_tool', handler);
    await wrapped({});

    const stats = getTelemetry()!.getStats();
    expect(stats.get('my_tool')!.calls).toBe(1);
    expect(stats.get('my_tool')!.errors).toBe(0);
  });

  it('records errors via withErrorBoundary', async () => {
    const handler = async (_args: any) => { throw new Error('fail'); };
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const wrapped = withErrorBoundary('fail_tool', handler);
    await wrapped({});

    const stats = getTelemetry()!.getStats();
    expect(stats.get('fail_tool')!.calls).toBe(1);
    expect(stats.get('fail_tool')!.errors).toBe(1);
    consoleSpy.mockRestore();
  });
});

describe('toolSuccess / toolError helpers', () => {
  it('toolSuccess builds correct MCP shape', () => {
    const result = toolSuccess({ count: 5 });
    expect(result.content[0].type).toBe('text');
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.success).toBe(true);
    expect(parsed.data).toEqual({ count: 5 });
    expect(parsed.warnings).toBeUndefined();
    expect((result as any).isError).toBeUndefined();
  });

  it('toolSuccess includes warnings when provided', () => {
    const result = toolSuccess({ ok: true }, ['something is slow']);
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.warnings).toEqual(['something is slow']);
  });

  it('toolError builds correct MCP shape with isError', () => {
    const result = toolError('not found', 'not_found', 'query_graph');
    expect(result.isError).toBe(true);
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.success).toBe(false);
    expect(parsed.error).toBe('not found');
    expect(parsed.classification).toBe('not_found');
    expect(parsed.tool).toBe('query_graph');
  });
});
