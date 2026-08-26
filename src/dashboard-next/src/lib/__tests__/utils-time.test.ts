import { describe, expect, it } from 'vitest';
import { agentElapsedMs, formatElapsed, formatRelativeTime } from '../utils';

describe('trustworthy time presentation', () => {
  it('prefers a stable server elapsed value', () => {
    expect(agentElapsedMs({ status: 'running', assigned_at: '2000-01-01T00:00:00Z', elapsed_ms: 65_000 })).toBe(65_000);
    expect(formatElapsed(65_000)).toBe('1m 5s');
  });

  it('rejects malformed and future clocks', () => {
    expect(agentElapsedMs({ status: 'running', assigned_at: 'not-a-date' })).toBeUndefined();
    expect(agentElapsedMs({ status: 'running', assigned_at: '2999-01-01T00:00:00Z' }, 0)).toBeUndefined();
    expect(formatElapsed(undefined)).toBe('Time unavailable');
    expect(formatRelativeTime('not-a-date')).toBe('Time unavailable');
  });
});
