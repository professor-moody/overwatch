import { describe, expect, it, vi } from 'vitest';
import { resolveDemoNow } from '../demo-clock.js';

describe('demo clock', () => {
  it('uses a fixed override for reproducible fixtures', () => {
    const wallClock = vi.fn(() => new Date('2099-01-01T00:00:00.000Z'));
    expect(resolveDemoNow('2026-08-26T18:00:00.000Z', wallClock).toISOString())
      .toBe('2026-08-26T18:00:00.000Z');
    expect(wallClock).not.toHaveBeenCalled();
  });

  it('captures wall time once when no override is supplied', () => {
    const wallClock = vi.fn(() => new Date('2026-08-26T18:00:00.000Z'));
    expect(resolveDemoNow(undefined, wallClock).toISOString()).toBe('2026-08-26T18:00:00.000Z');
    expect(wallClock).toHaveBeenCalledTimes(1);
  });

  it('rejects malformed overrides', () => {
    expect(() => resolveDemoNow('not-a-time')).toThrow(/valid ISO-8601/);
  });
});
