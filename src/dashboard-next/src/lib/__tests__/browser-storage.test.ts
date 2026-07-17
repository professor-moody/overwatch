import { describe, expect, it } from 'vitest';
import { createSafeBrowserStorage, type StorageLike } from '../browser-storage';

describe('safe browser storage', () => {
  it('uses page memory when the storage property getter is unavailable', () => {
    const memory = new Map<string, string>();
    const storage = createSafeBrowserStorage('local', () => {
      throw new Error('localStorage denied');
    }, memory);

    expect(storage.getItem('layout')).toBeNull();
    expect(storage.setItem('layout', 'expanded')).toBe(false);
    expect(storage.getItem('layout')).toBe('expanded');
    expect(storage.removeItem('layout')).toBe(false);
    expect(storage.getItem('layout')).toBeNull();
  });

  it('catches getItem, setItem, and removeItem failures independently', () => {
    const memory = new Map<string, string>();
    const throwing: StorageLike = {
      getItem: () => { throw new Error('get denied'); },
      setItem: () => { throw new Error('set denied'); },
      removeItem: () => { throw new Error('remove denied'); },
    };
    const storage = createSafeBrowserStorage('session', () => throwing, memory);

    expect(storage.getItem('planner')).toBeNull();
    expect(storage.setItem('planner', 'command-1')).toBe(false);
    expect(storage.getItem('planner')).toBe('command-1');
    expect(storage.removeItem('planner')).toBe(false);
    expect(storage.getItem('planner')).toBeNull();
  });

  it('keeps failed writes and removals authoritative over stale persisted values', () => {
    const persisted = new Map([['planner', 'stale-command']]);
    const partial: StorageLike = {
      getItem: key => persisted.get(key) ?? null,
      setItem: () => { throw new Error('write denied'); },
      removeItem: () => { throw new Error('remove denied'); },
    };
    const storage = createSafeBrowserStorage('session', () => partial, new Map());

    expect(storage.getItem('planner')).toBe('stale-command');
    expect(storage.setItem('planner', 'current-command')).toBe(false);
    expect(storage.getItem('planner')).toBe('current-command');
    expect(storage.removeItem('planner')).toBe(false);
    expect(storage.getItem('planner')).toBeNull();
  });

  it('honors a successful native miss instead of resurrecting cached data', () => {
    const persisted = new Map<string, string>();
    const native: StorageLike = {
      getItem: key => persisted.get(key) ?? null,
      setItem: (key, value) => { persisted.set(key, value); },
      removeItem: key => { persisted.delete(key); },
    };
    const memory = new Map([['planner', 'stale-command']]);
    const storage = createSafeBrowserStorage('session', () => native, memory);

    expect(storage.getItem('planner')).toBeNull();
    expect(memory.has('planner')).toBe(false);
  });

  it('disables process-global memory fallback for server-side adapters', () => {
    const storage = createSafeBrowserStorage('session', () => undefined, new Map(), false);

    expect(storage.setItem('token', 'must-not-leak')).toBe(false);
    expect(storage.getItem('token')).toBeNull();
  });

  it('keeps local and session fallback values isolated', () => {
    const local = createSafeBrowserStorage('local', () => undefined, new Map());
    const session = createSafeBrowserStorage('session', () => undefined, new Map());

    local.setItem('shared-key', 'local-value');
    session.setItem('shared-key', 'session-value');

    expect(local.getItem('shared-key')).toBe('local-value');
    expect(session.getItem('shared-key')).toBe('session-value');
  });
});
