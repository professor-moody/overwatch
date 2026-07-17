import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

const SOURCE_ROOT = join(process.cwd(), 'src/dashboard-next/src');
const TRANSPORT = 'lib/dashboard-transport.ts';

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return entry.name === '__tests__' ? [] : sourceFiles(path);
    return /\.tsx?$/.test(entry.name) ? [path] : [];
  });
}

describe('dashboard transport architecture', () => {
  it('owns every direct fetch and WebSocket construction', () => {
    const violations: string[] = [];
    for (const path of sourceFiles(SOURCE_ROOT)) {
      const name = relative(SOURCE_ROOT, path);
      if (name === TRANSPORT) continue;
      const source = readFileSync(path, 'utf8');
      if (/\b(?:globalThis\.)?fetch\s*\(/.test(source)) violations.push(`${name}: direct fetch`);
      if (/new\s+(?:globalThis\.)?WebSocket\s*\(/.test(source)) violations.push(`${name}: direct WebSocket`);
    }
    expect(violations).toEqual([]);
  });

  it('builds API and WebSocket request paths from the shared registries', () => {
    const violations: string[] = [];
    for (const path of sourceFiles(SOURCE_ROOT)) {
      const name = relative(SOURCE_ROOT, path);
      const source = readFileSync(path, 'utf8');
      if (name !== 'lib/api.generated.ts' && /["'`]\/api\//.test(source)) {
        violations.push(`${name}: handwritten API route`);
      }
      if (/createDashboardWebSocket\s*\(\s*["'`]\//.test(source)) {
        violations.push(`${name}: handwritten WebSocket route`);
      }
    }
    expect(violations).toEqual([]);
  });
});
