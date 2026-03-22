import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { resolve } from 'path';
import { pathToFileURL } from 'url';

async function loadUiModule() {
  const url = pathToFileURL(resolve('/Users/keys/projects/overwatch/src/dashboard/ui.js')).href;
  await import(`${url}?t=${Date.now()}-${Math.random()}`);
  return (globalThis as any).window.OverwatchUI;
}

describe('dashboard ui frontier helpers', () => {
  beforeEach(() => {
    (globalThis as any).window = { OverwatchGraph: {} };
  });

  afterEach(() => {
    delete (globalThis as any).window;
  });

  it('derives navigation target from incomplete node frontier items', async () => {
    const ui = await loadUiModule();

    expect(ui.getFrontierTargetNodeIds({
      type: 'incomplete_node',
      node_id: 'host-10-3-10-10',
    })).toEqual(['host-10-3-10-10']);
  });

  it('derives navigation targets from edge frontier items', async () => {
    const ui = await loadUiModule();

    expect(ui.getFrontierTargetNodeIds({
      type: 'inferred_edge',
      edge_source: 'user-admin',
      edge_target: 'host-10-3-10-10',
    })).toEqual(['user-admin', 'host-10-3-10-10']);
  });
});
