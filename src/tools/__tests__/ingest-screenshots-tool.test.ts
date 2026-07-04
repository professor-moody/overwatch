import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerIngestScreenshotsTool } from '../ingest-screenshots.js';
import { EvidenceStore } from '../../services/evidence-store.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { webappOriginId } from '../../services/parser-utils.js';
import type { Finding, EngagementConfig } from '../../types.js';

let dir: string;      // report dir (PNGs + gowitness.jsonl)
let stateDir: string; // evidence store state dir

function build() {
  const handlers: Record<string, (args: any) => Promise<any>> = {};
  const fakeServer = {
    registerTool(name: string, _cfg: unknown, handler: (args: any) => Promise<any>) { handlers[name] = handler; },
  } as unknown as McpServer;
  const store = new EvidenceStore(join(stateDir, 'state.json'));
  const ingested: Finding[] = [];
  const engine = {
    getEvidenceStore: () => store,
    getNode: () => null,
    ingestFinding: (f: Finding) => { ingested.push(f); return { new_nodes: f.nodes.map(n => n.id), new_edges: [], updated_nodes: [], updated_edges: [], inferred_edges: [] }; },
  };
  registerIngestScreenshotsTool(fakeServer, engine as any);
  return { handlers, store, ingested };
}

// Minimal but valid PNG bytes (magic + a distinguishing tail); binary — includes
// bytes that would not survive a UTF-8 round-trip.
const png = (tag: number) => Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0xff, tag, 0x80]);

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'ow-shots-'));
  stateDir = mkdtempSync(join(tmpdir(), 'ow-shots-state-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  rmSync(stateDir, { recursive: true, force: true });
});

describe('ingest_screenshots tool', () => {
  it('stores each PNG as screenshot evidence and stamps screenshot_evidence_id on the webapp', async () => {
    writeFileSync(join(dir, 'a.png'), png(0x11));
    writeFileSync(join(dir, 'b.png'), png(0x22));
    writeFileSync(join(dir, 'gowitness.jsonl'), [
      JSON.stringify({ url: 'https://a.acme.com', response_code: 200, file_name: 'a.png' }),
      JSON.stringify({ url: 'https://b.acme.com', response_code: 200, file_name: 'b.png' }),
    ].join('\n'));

    const { handlers, store, ingested } = build();
    const res = await handlers.ingest_screenshots({ report_dir: dir });
    const summary = JSON.parse(res.content[0].text);
    expect(summary.screenshots_stored).toBe(2);
    expect(summary.skipped).toBe(0);

    const webapps = ingested[0].nodes.filter((n: any) => n.type === 'webapp') as any[];
    expect(webapps).toHaveLength(2);
    for (const wa of webapps) {
      expect(typeof wa.screenshot_evidence_id).toBe('string');
      // the stored bytes are byte-identical (binary-safe round-trip)
      const back = store.getContentBuffer(wa.screenshot_evidence_id);
      expect(back).not.toBeNull();
      const rec = store.getRecord(wa.screenshot_evidence_id);
      expect(rec?.evidence_type).toBe('screenshot');
    }
    // the two screenshots are distinct blobs
    const ids = webapps.map(w => w.screenshot_evidence_id);
    expect(new Set(ids).size).toBe(2);
  });

  it('rejects a path-traversal file_name (stays inside report_dir)', async () => {
    // plant a file OUTSIDE report_dir that a traversal would reach
    writeFileSync(join(stateDir, 'escape.png'), png(0x99));
    writeFileSync(join(dir, 'gowitness.jsonl'),
      JSON.stringify({ url: 'https://evil.acme.com', response_code: 200, file_name: `../${'ow-shots-state'}/escape.png` }));
    const { handlers } = build();
    const res = await handlers.ingest_screenshots({ report_dir: dir });
    const summary = JSON.parse(res.content[0].text);
    expect(summary.screenshots_stored).toBe(0);
    expect(summary.skipped).toBe(1);
    expect(summary.skipped_detail.join(' ')).toMatch(/escapes report_dir/);
  });

  it('skips a missing PNG without failing the whole ingest', async () => {
    writeFileSync(join(dir, 'there.png'), png(0x33));
    writeFileSync(join(dir, 'gowitness.jsonl'), [
      JSON.stringify({ url: 'https://x.acme.com', file_name: 'missing.png' }),
      JSON.stringify({ url: 'https://y.acme.com', file_name: 'there.png' }),
    ].join('\n'));
    const { handlers } = build();
    const res = await handlers.ingest_screenshots({ report_dir: dir });
    const summary = JSON.parse(res.content[0].text);
    expect(summary.screenshots_stored).toBe(1);
    expect(summary.skipped).toBe(1);
    expect(summary.skipped_detail.join(' ')).toMatch(/missing/);
  });

  it('errors cleanly when report_dir or the jsonl is absent', async () => {
    const { handlers } = build();
    const r1 = await handlers.ingest_screenshots({ report_dir: join(dir, 'nope') });
    expect(r1.isError).toBe(true);
    const r2 = await handlers.ingest_screenshots({ report_dir: dir }); // no gowitness.jsonl written
    expect(r2.isError).toBe(true);
    expect(r2.content[0].text).toMatch(/not found/);
  });

  it('a webapp with no screenshot_path is ingested but stores no evidence', async () => {
    writeFileSync(join(dir, 'gowitness.jsonl'), JSON.stringify({ url: 'https://z.acme.com', response_code: 200 }));
    const { handlers, ingested } = build();
    const res = await handlers.ingest_screenshots({ report_dir: dir });
    expect(JSON.parse(res.content[0].text).screenshots_stored).toBe(0);
    expect(ingested[0].nodes.some((n: any) => n.type === 'webapp')).toBe(true);
  });

  it('END-TO-END: screenshot_evidence_id survives ingestion onto the PERSISTED graph node', async () => {
    writeFileSync(join(dir, 'a.png'), png(0x11));
    writeFileSync(join(dir, 'gowitness.jsonl'), JSON.stringify({ url: 'https://a.acme.com', response_code: 200, file_name: 'a.png' }));

    const config = {
      id: 't', name: 't', created_at: new Date().toISOString(),
      scope: { cidrs: [], domains: ['acme.com'], exclusions: [] }, objectives: [],
      opsec: { name: 'pentest', max_noise: 1, blacklisted_techniques: [] },
    } as unknown as EngagementConfig;
    const engine = new GraphEngine(config, join(stateDir, 'real-state.json'));
    try {
      const handlers: Record<string, (args: any) => Promise<any>> = {};
      const fakeServer = { registerTool(n: string, _c: unknown, h: (a: any) => Promise<any>) { handlers[n] = h; } } as any;
      registerIngestScreenshotsTool(fakeServer, engine);

      const res = await handlers.ingest_screenshots({ report_dir: dir });
      expect(JSON.parse(res.content[0].text).screenshots_stored).toBe(1);

      // The property must land on the REAL persisted node (not stripped by
      // normalizeFindingNode / ingestFinding), and the bytes must be retrievable.
      const node = engine.getNode(webappOriginId('https://a.acme.com')) as any;
      expect(node).not.toBeNull();
      expect(typeof node.screenshot_evidence_id).toBe('string');
      const back = engine.getEvidenceStore().getContentBuffer(node.screenshot_evidence_id);
      expect(back!.equals(png(0x11))).toBe(true);
    } finally {
      engine.dispose();
    }
  });
});
