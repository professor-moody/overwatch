import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { resolve } from 'path';
import { pathToFileURL } from 'url';
import { readFileSync } from 'fs';

async function loadUiModule() {
  const url = pathToFileURL(resolve('/Users/keys/projects/overwatch/src/dashboard/ui.js')).href;
  await import(`${url}?t=${Date.now()}-${Math.random()}`);
  return (globalThis as any).window.OverwatchUI;
}

describe('dashboard ui frontier helpers', () => {
  beforeEach(() => {
    const elements = new Map<string, any>();
    elements.set('shortcuts-overlay', {
      classList: {
        classes: new Set<string>(),
        add(name: string) { this.classes.add(name); },
        remove(name: string) { this.classes.delete(name); },
        toggle(name: string, force?: boolean) {
          if (typeof force === 'boolean') {
            if (force) this.classes.add(name);
            else this.classes.delete(name);
            return force;
          }
          if (this.classes.has(name)) {
            this.classes.delete(name);
            return false;
          }
          this.classes.add(name);
          return true;
        },
        contains(name: string) { return this.classes.has(name); },
      },
    });

    (globalThis as any).window = { OverwatchGraph: {} };
    (globalThis as any).document = {
      getElementById(id: string) {
        return elements.get(id) || null;
      },
    };
  });

  afterEach(() => {
    delete (globalThis as any).window;
    delete (globalThis as any).document;
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

  it('keeps shortcuts overlay state synchronized across repeated toggles', async () => {
    const ui = await loadUiModule();
    const overlay = (globalThis as any).document.getElementById('shortcuts-overlay');

    ui.toggleShortcutsOverlay();
    expect(overlay.classList.contains('visible')).toBe(true);

    ui.toggleShortcutsOverlay();
    expect(overlay.classList.contains('visible')).toBe(false);

    ui.setShortcutsOverlayVisible(true);
    expect(overlay.classList.contains('visible')).toBe(true);

    ui.toggleShortcutsOverlay();
    expect(overlay.classList.contains('visible')).toBe(false);
  });

  it('does not reference Google Fonts in dashboard html', () => {
    const html = readFileSync(resolve('/Users/keys/projects/overwatch/src/dashboard/index.html'), 'utf8');
    expect(html).not.toContain('fonts.googleapis.com');
    expect(html).not.toContain('fonts.gstatic.com');
  });
});
