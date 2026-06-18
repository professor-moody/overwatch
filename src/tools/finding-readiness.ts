import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { buildFindings, type ReportFinding } from '../services/report-generator.js';
import { classifyAllFindings } from '../services/finding-classifier.js';
import { withErrorBoundary } from './error-boundary.js';

type Readiness = 'client_ready' | 'needs_validation' | 'draft';

interface FindingReadiness {
  id: string;
  title: string;
  severity: string;
  category: string;
  readiness: Readiness;
  evidence_chains: number;
  proof_cards: number;
  captured_evidence: boolean;
  classified: boolean;
  affected_assets: number;
  gaps: string[];
}

/** Heuristic proof-readiness over a derived finding. Read-only — surfaces the
 *  signals + gaps for the operator/evidence_auditor to judge, not a verdict.
 *  Exported for unit testing of the readiness tiers + gap strings. */
export function assess(f: ReportFinding): FindingReadiness {
  const proof_cards = f.proof_cards?.length ?? 0;
  const evidence_chains = f.evidence?.length ?? 0;
  // "captured" = a chain cites real evidence-store bytes / raw output, not just a claim.
  const captured_evidence = (f.evidence ?? []).some(
    c => !!c.stdout_evidence_id || !!c.stderr_evidence_id || !!c.raw_output || !!c.evidence_content,
  );
  const classified = !!f.classification;
  const affected_assets = f.affected_assets?.length ?? 0;

  let readiness: Readiness;
  if (proof_cards > 0 || captured_evidence) readiness = 'client_ready';
  else if (evidence_chains > 0 || affected_assets > 0) readiness = 'needs_validation';
  else readiness = 'draft';

  const gaps: string[] = [];
  if (readiness !== 'client_ready') gaps.push('no captured evidence — run/parse the action that proves this finding');
  if (!classified) gaps.push('unclassified — no CWE/OWASP/ATT&CK mapping');
  if (affected_assets === 0) gaps.push('no affected assets linked');

  return {
    id: f.id, title: f.title, severity: f.severity, category: f.category,
    readiness, evidence_chains, proof_cards, captured_evidence, classified, affected_assets, gaps,
  };
}

export function registerFindingReadinessTools(server: McpServer, engine: GraphEngine): void {

  // ============================================================
  // Tool: get_finding_readiness
  // Read-only proof-readiness rollup for the evidence_auditor archetype.
  // ============================================================
  server.registerTool(
    'get_finding_readiness',
    {
      title: 'Get Finding Readiness',
      description: `Audit findings for proof readiness before reporting. For each finding returns a readiness label — **client_ready** (backed by captured evidence / proof cards), **needs_validation** (a claim with no captured evidence yet), or **draft** (thin) — plus the concrete gaps to close. Derived from the same finding builder + classifier the report uses. Read-only; optionally scope to one finding_id.`,
      inputSchema: {
        finding_id: z.string().optional().describe('Audit a single finding by id (default: all findings)'),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    withErrorBoundary('get_finding_readiness', async ({ finding_id }) => {
      const graph = engine.exportGraph();
      const history = engine.getFullHistory();
      const config = engine.getConfig();
      const evidenceLoader = (id: string): string | null => {
        try { return engine.getEvidenceStore().getRawOutput(id); } catch { return null; }
      };
      let findings = buildFindings(graph, history, config, { evidenceLoader });
      const classifications = classifyAllFindings(findings, graph);
      findings = findings.map(f => ({ ...f, classification: classifications.get(f.id) ?? f.classification }));
      if (finding_id) findings = findings.filter(f => f.id === finding_id);

      const assessed = findings.map(assess);
      const summary = {
        total: assessed.length,
        client_ready: assessed.filter(a => a.readiness === 'client_ready').length,
        needs_validation: assessed.filter(a => a.readiness === 'needs_validation').length,
        draft: assessed.filter(a => a.readiness === 'draft').length,
      };
      return { content: [{ type: 'text', text: JSON.stringify({ summary, findings: assessed }, null, 2) }] };
    }),
  );
}
