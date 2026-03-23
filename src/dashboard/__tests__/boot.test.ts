import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'fs';
import { resolve } from 'path';

const DASHBOARD_DIR = resolve('/Users/keys/projects/overwatch/src/dashboard');

const SCRIPT_FILES = ['node-display.js', 'graph.js', 'ui.js', 'ws.js', 'main.js'];

const REMOTE_CDN_PATTERNS = [
  'cdn.jsdelivr.net',
  'cdnjs.cloudflare.com',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
  'unpkg.com',
];

/**
 * Extract top-level const/let/var declarations from a plain JS file.
 * Only matches declarations at the start of a line (no leading whitespace),
 * which corresponds to global scope in non-module scripts.
 */
function extractTopLevelDeclarations(source: string): string[] {
  const names: string[] = [];
  const pattern = /^(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=/gm;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(source)) !== null) {
    // Verify this is truly at column 0 (top-level in a plain script)
    const lineStart = source.lastIndexOf('\n', match.index) + 1;
    if (match.index === lineStart) {
      names.push(match[1]);
    }
  }
  return names;
}

describe('dashboard boot integrity', () => {
  it('has no duplicate top-level declarations across dashboard scripts', () => {
    const allDecls = new Map<string, string[]>();

    for (const file of SCRIPT_FILES) {
      const source = readFileSync(resolve(DASHBOARD_DIR, file), 'utf8');
      const decls = extractTopLevelDeclarations(source);
      for (const name of decls) {
        const files = allDecls.get(name) || [];
        files.push(file);
        allDecls.set(name, files);
      }
    }

    const collisions: string[] = [];
    for (const [name, files] of allDecls) {
      if (files.length > 1) {
        collisions.push(`"${name}" declared in: ${files.join(', ')}`);
      }
    }

    expect(collisions, `Global scope collisions found:\n${collisions.join('\n')}`).toEqual([]);
  });

  it('does not reference remote CDN URLs in dashboard HTML', () => {
    const html = readFileSync(resolve(DASHBOARD_DIR, 'index.html'), 'utf8');

    for (const pattern of REMOTE_CDN_PATTERNS) {
      expect(html, `Found remote CDN reference: ${pattern}`).not.toContain(pattern);
    }
  });

  it('references only local vendor assets in script tags', () => {
    const html = readFileSync(resolve(DASHBOARD_DIR, 'index.html'), 'utf8');
    const scriptSrcPattern = /<script\s+src="([^"]+)"/g;
    let match: RegExpExecArray | null;
    const srcs: string[] = [];

    while ((match = scriptSrcPattern.exec(html)) !== null) {
      srcs.push(match[1]);
    }

    // All src values should be relative paths, not absolute URLs
    for (const src of srcs) {
      expect(src, `Script src "${src}" should be a relative path`).not.toMatch(/^https?:\/\//);
    }

    // Should include vendor assets
    expect(srcs.some(s => s.includes('vendor/graphology'))).toBe(true);
    expect(srcs.some(s => s.includes('vendor/sigma'))).toBe(true);
    expect(srcs.some(s => s.includes('vendor/graphology-layout-forceatlas2'))).toBe(true);
  });

  it('loads all dashboard modules without missing global exports', async () => {
    // Set up minimal browser globals
    const elements = new Map<string, any>();
    elements.set('node-filters', { innerHTML: '', appendChild() {} });
    elements.set('focus-banner', { classList: { add() {}, remove() {} }, querySelector() { return { textContent: '' }; } });
    elements.set('path-info-bar', { classList: { add() {}, remove() {} }, querySelector() { return { textContent: '' }; } });
    elements.set('minimap-canvas', {
      clientWidth: 120, clientHeight: 80, width: 0, height: 0,
      getContext() { return { clearRect() {}, beginPath() {}, moveTo() {}, lineTo() {}, stroke() {}, arc() {}, fill() {}, strokeRect() {} }; },
      getBoundingClientRect() { return { left: 0, top: 0, width: 120, height: 80 }; },
      addEventListener() {},
    });
    elements.set('sigma-container', {
      clientWidth: 800, clientHeight: 600,
      getBoundingClientRect() { return { left: 0, top: 0, width: 800, height: 600 }; },
      classList: { add() {}, remove() {}, toggle() {} },
    });
    elements.set('btn-layout', { textContent: '', classList: { add() {}, remove() {} } });
    elements.set('graph-tooltip', { classList: { add() {}, remove() {}, toggle() {} }, style: {}, innerHTML: '' });
    elements.set('ws-status', { className: '', innerHTML: '' });

    const { default: Graph } = await import('graphology');

    (globalThis as any).window = {};
    (globalThis as any).document = {
      getElementById(id: string) { return elements.get(id) || null; },
      createElement() { return { className: '', innerHTML: '', onclick: null, classList: { add() {}, remove() {}, toggle() {} } }; },
    };
    (globalThis as any).graphology = { Graph };

    try {
      const { pathToFileURL } = await import('url');

      // Load in order: node-display → graph → ui → ws
      for (const file of ['node-display.js', 'graph.js', 'ui.js', 'ws.js']) {
        const url = pathToFileURL(resolve(DASHBOARD_DIR, file)).href;
        await import(`${url}?t=${Date.now()}-${Math.random()}`);
      }

      expect((globalThis as any).window.OverwatchNodeDisplay).toBeDefined();
      expect((globalThis as any).window.OverwatchGraph).toBeDefined();
      expect((globalThis as any).window.OverwatchUI).toBeDefined();
      expect((globalThis as any).window.OverwatchWS).toBeDefined();
    } finally {
      delete (globalThis as any).window;
      delete (globalThis as any).document;
      delete (globalThis as any).graphology;
    }
  });
});
