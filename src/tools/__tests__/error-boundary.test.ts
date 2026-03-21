import { describe, it, expect, vi } from 'vitest';
import { withErrorBoundary } from '../error-boundary.js';

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
});
