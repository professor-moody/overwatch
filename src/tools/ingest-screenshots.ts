// ============================================================
// ingest_screenshots — make gowitness/aquatone captures VIEWABLE.
//
// `parse_output(gowitness)` records a `screenshot_path` string on each webapp,
// but the PNG bytes never enter Overwatch, so nothing can display them. This
// tool reads the report's PNG files off disk, stores each into the evidence
// store as a `screenshot` blob (binary-safe, via createBlobStream), and stamps
// the resulting `screenshot_evidence_id` onto the webapp node — so the dashboard
// can render it (GET /api/evidence/<id>/image).
//
// The bytes are read directly from disk and never pass through the LLM context.
// File resolution is path-traversal guarded to stay inside `report_dir`.
// ============================================================

import { existsSync, readFileSync, statSync } from 'fs';
import { basename, resolve, sep } from 'path';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import type { NodeProperties } from '../types.js';
import { withErrorBoundary } from './error-boundary.js';
import { parseGowitness } from '../services/parsers/gowitness.js';
import { prepareFindingForIngest } from '../services/finding-validation.js';

interface IngestScreenshotsParams {
  report_dir: string;
  jsonl_path?: string;
  agent_id?: string;
  action_id?: string;
}

const MAX_IMAGE_BYTES = 25 * 1024 * 1024; // 25 MB — a screenshot far exceeding this is not one

function err(message: string): { content: { type: 'text'; text: string }[]; isError: true } {
  return { content: [{ type: 'text', text: JSON.stringify({ error: message }, null, 2) }], isError: true };
}

export function registerIngestScreenshotsTool(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'ingest_screenshots',
    {
      title: 'Ingest Screenshots (make gowitness/aquatone captures viewable)',
      description: `Read a visual-recon report's PNG files off disk and ingest them so they're VIEWABLE in the dashboard. Complements parse_output(gowitness) — that records the graph nodes + a screenshot_path reference; this additionally stores each PNG in the evidence store and stamps the webapp node with a screenshot_evidence_id (rendered at /api/evidence/<id>/image).

Run gowitness first (e.g. \`gowitness scan single -u https://target --write-jsonl\`, which writes ./gowitness.jsonl + screenshot PNGs), then call this with report_dir pointing at that directory. Image bytes are read straight from disk (never through the model context); file resolution is guarded to stay inside report_dir.`,
      inputSchema: {
        report_dir: z.string().describe('Absolute directory holding the screenshot PNGs (and, by default, gowitness.jsonl).'),
        jsonl_path: z.string().optional().describe('Path to the gowitness JSON-lines report. Defaults to <report_dir>/gowitness.jsonl.'),
        agent_id: z.string().optional().describe('Attribution: agent that ran the capture.'),
        action_id: z.string().optional().describe('Attribution: action id to tie the evidence to.'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    withErrorBoundary('ingest_screenshots', async (params: IngestScreenshotsParams) => {
      const reportDir = resolve(params.report_dir);
      if (!existsSync(reportDir) || !statSync(reportDir).isDirectory()) {
        return err(`report_dir does not exist or is not a directory: ${reportDir}`);
      }
      const jsonlPath = params.jsonl_path ? resolve(params.jsonl_path) : resolve(reportDir, 'gowitness.jsonl');
      if (!existsSync(jsonlPath)) {
        return err(`gowitness JSON-lines report not found: ${jsonlPath}`);
      }

      const finding = parseGowitness(readFileSync(jsonlPath, 'utf-8'), params.agent_id ?? 'ingest-screenshots');
      const store = engine.getEvidenceStore();

      let stored = 0;
      const skipped: string[] = [];
      for (const node of finding.nodes) {
        const n = node as NodeProperties;
        if (n.type !== 'webapp') continue;
        const sp = typeof n.screenshot_path === 'string' ? n.screenshot_path : undefined;
        if (!sp) continue;

        // Resolve the PNG inside report_dir; reject anything that escapes it.
        const pngPath = resolve(reportDir, sp);
        if (pngPath !== reportDir && !pngPath.startsWith(reportDir + sep)) { skipped.push(`${sp} (escapes report_dir)`); continue; }
        let st;
        try { st = statSync(pngPath); } catch { skipped.push(`${sp} (missing)`); continue; }
        if (!st.isFile()) { skipped.push(`${sp} (not a file)`); continue; }
        if (st.size > MAX_IMAGE_BYTES) { skipped.push(`${sp} (too large)`); continue; }

        try {
          const bytes = readFileSync(pngPath);
          const sink = store.createBlobStream({
            evidence_type: 'screenshot',
            filename: basename(sp),
            kind: 'content',
            agent_id: params.agent_id,
            action_id: params.action_id,
          });
          sink.write(bytes);
          await sink.end();
          if (sink.error()) { skipped.push(`${sp} (store error)`); continue; }
          n.screenshot_evidence_id = sink.evidence_id;
          stored += 1;
        } catch (e) {
          skipped.push(`${sp} (${e instanceof Error ? e.message : String(e)})`);
        }
      }

      // Ingest the webapp nodes (now carrying screenshot_evidence_id) — merges
      // by origin with any existing webapp from parse_output(gowitness)/httpx.
      const prepared = prepareFindingForIngest(finding, id => engine.getNode(id));
      if (prepared.errors.length > 0) {
        return err(`Screenshot ingest rejected — invalid graph mutation: ${prepared.errors.map(e => e.message).join('; ')}`);
      }
      const result = engine.ingestFinding(prepared.finding);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            screenshots_stored: stored,
            skipped: skipped.length,
            skipped_detail: skipped.slice(0, 20),
            webapps: finding.nodes.filter(x => (x as NodeProperties).type === 'webapp').length,
            new_nodes: result.new_nodes.length,
            updated_nodes: result.updated_nodes.length,
          }, null, 2),
        }],
      };
    }),
  );
}
