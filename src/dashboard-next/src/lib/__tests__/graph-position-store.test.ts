import { describe, expect, it } from 'vitest';
import {
  clearGraphPositions,
  graphPositionStorageKey,
  loadGraphPositions,
  saveGraphNodePosition,
} from '../graph-position-store';

function memoryStorage() {
  const data = new Map<string, string>();
  return {
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => data.set(key, value),
    removeItem: (key: string) => data.delete(key),
  };
}

describe('graph position store', () => {
  it('saves and loads positions by engagement id and node id', () => {
    const storage = memoryStorage();

    saveGraphNodePosition('eng-1', 'node-a', { x: 4, y: -2 }, storage);
    saveGraphNodePosition('eng-1', 'node-b', { x: 8, y: 3 }, storage);

    expect(loadGraphPositions('eng-1', storage)).toEqual({
      'node-a': { x: 4, y: -2 },
      'node-b': { x: 8, y: 3 },
    });
    expect(loadGraphPositions('eng-2', storage)).toEqual({});
  });

  it('clears saved positions for the current engagement only', () => {
    const storage = memoryStorage();
    saveGraphNodePosition('eng-1', 'node-a', { x: 1, y: 1 }, storage);
    saveGraphNodePosition('eng-2', 'node-a', { x: 2, y: 2 }, storage);

    clearGraphPositions('eng-1', storage);

    expect(loadGraphPositions('eng-1', storage)).toEqual({});
    expect(loadGraphPositions('eng-2', storage)).toEqual({ 'node-a': { x: 2, y: 2 } });
  });

  it('ignores malformed persisted values', () => {
    const storage = memoryStorage();
    storage.setItem(graphPositionStorageKey('eng-1'), JSON.stringify({
      good: { x: 1, y: 2 },
      bad: { x: '1', y: 2 },
    }));

    expect(loadGraphPositions('eng-1', storage)).toEqual({ good: { x: 1, y: 2 } });
  });

  it('keeps graph interaction usable when every storage method throws', () => {
    const storage = {
      getItem: () => { throw new Error('get denied'); },
      setItem: () => { throw new Error('set denied'); },
      removeItem: () => { throw new Error('remove denied'); },
    };

    expect(loadGraphPositions('storage-denied', storage)).toEqual({});
    expect(saveGraphNodePosition('storage-denied', 'node-a', { x: 3, y: 7 }, storage))
      .toEqual({ 'node-a': { x: 3, y: 7 } });
    expect(loadGraphPositions('storage-denied', storage))
      .toEqual({ 'node-a': { x: 3, y: 7 } });
    expect(() => clearGraphPositions('storage-denied', storage)).not.toThrow();
    expect(loadGraphPositions('storage-denied', storage)).toEqual({});
  });
});
