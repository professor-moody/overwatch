// ============================================================
// Overwatch — research_cve (CVE/exploit research recording tool)
//
// The web search + judgment is the AGENT's job (a headless 'research' role
// sub-agent with WebSearch/WebFetch). This tool RECORDS the structured outcome:
// it ingests applicable candidates as `vulnerability` nodes + `VULNERABLE_TO`
// edges (tested:false — they are candidates, not confirmed), and ALWAYS stamps
// `cve_checked_at` on the service so the `cve_research` frontier item stops
// regenerating (even when nothing was found). Keeps ingestion typed/consistent
// with the scanner parsers instead of hand-built report_finding payloads.
// ============================================================

import { v4 as uuidv4 } from 'uuid';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import type { Finding, NodeType, EdgeType } from '../types.js';
import { vulnerabilityId, normalizeKeyPart } from '../services/parser-utils.js';
import { prepareFindingForIngest } from '../services/finding-validation.js';
import { withErrorBoundary } from './error-boundary.js';

export interface CveCandidate {
  cve?: string;
  title: string;
  cvss?: number;
  vuln_type?: string;
  exploit_available?: boolean;
  poc_url?: string;
  applicable: boolean;
  confidence?: number;
  notes?: string;
}

export interface RecordCveResearchArgs {
  service_id: string;
  agent_id?: string;
  summary: string;
  candidates: CveCandidate[];
}

export type RecordCveResearchResult =
  | { ok: true; service_id: string; cve_checked_at: string; candidates_recorded: number; new_nodes: string[]; new_edges: string[] }
  | { ok: false; error?: string; errors?: unknown[] };

/**
 * Core recording logic, extracted from the tool handler so it's unit-testable
 * without standing up an MCP server. Ingests applicable candidates as candidate
 * vulnerability nodes + VULNERABLE_TO(tested:false) edges and stamps
 * `cve_checked_at` on the service (always — even with zero candidates).
 */
export function recordCveResearch(engine: GraphEngine, args: RecordCveResearchArgs): RecordCveResearchResult {
  const { service_id, agent_id, summary, candidates } = args;
  const svc = engine.getNode(service_id);
  if (!svc || svc.type !== 'service') {
    return { ok: false, error: `service node not found: ${service_id}` };
  }
  const now = new Date().toISOString();
  const aid = agent_id || 'research-cve';
  const applicable = candidates.filter(c => c.applicable);

  const nodes: Finding['nodes'] = [
    { id: service_id, type: 'service' as NodeType, label: svc.label ?? service_id, cve_checked_at: now, cve_check_summary: summary },
  ];
  const edges: Finding['edges'] = [];

  for (const c of applicable) {
    const ident = c.cve || normalizeKeyPart(c.title);
    const vid = vulnerabilityId(ident, service_id);
    const noteParts = [c.notes, c.poc_url ? `POC/advisory: ${c.poc_url}` : null].filter(Boolean);
    nodes.push({
      id: vid,
      type: 'vulnerability' as NodeType,
      label: c.cve || c.title,
      cve: c.cve,
      cvss: c.cvss,
      vuln_type: c.vuln_type || (c.cve ? 'cve' : 'misc'),
      exploit_available: c.exploit_available,
      affected_component: svc.service_name || svc.label,
      discovered_by: aid,
      discovered_at: now,
      confidence: c.confidence ?? 0.6,
      notes: noteParts.length ? noteParts.join(' | ') : undefined,
    });
    edges.push({
      source: service_id,
      target: vid,
      properties: {
        type: 'VULNERABLE_TO' as EdgeType,
        confidence: c.confidence ?? 0.6,
        tested: false,
        discovered_at: now,
        discovered_by: aid,
      },
    });
  }

  const finding: Finding = {
    id: uuidv4(), agent_id: aid, timestamp: now, tool_name: 'research_cve',
    target_node_ids: [service_id], nodes, edges,
  };
  const prepared = prepareFindingForIngest(finding, (id: string) => engine.getNode(id));
  if (prepared.errors.length > 0) {
    return { ok: false, errors: prepared.errors };
  }
  const result = engine.ingestFinding(prepared.finding);
  // An empty-candidates research still only MERGES attributes onto the existing
  // service node (no new node/edge), which doesn't invalidate the frontier cache
  // on its own — force it so `cve_checked_at` retires the cve_research item now.
  engine.invalidateFrontierCache();
  engine.logActionEvent({
    description: `CVE research recorded for ${svc.label}: ${applicable.length}/${candidates.length} applicable candidate(s)`,
    event_type: 'instrumentation_warning',
    category: 'system',
    result_classification: 'neutral',
    agent_id: aid,
    details: { reason: 'cve_research_recorded', service_id, candidates: candidates.length, applicable: applicable.length },
  });
  return { ok: true, service_id, cve_checked_at: now, candidates_recorded: applicable.length, new_nodes: result.new_nodes, new_edges: result.new_edges };
}

export function registerResearchCveTools(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'research_cve',
    {
      title: 'Record CVE Research',
      description: `Record the outcome of operator-style CVE/exploit research for a versioned service.

You (the research agent) do the web research first — search vendor advisories / NVD / Exploit-DB / GitHub for the service's product+version, find CVEs and public POCs, and judge which actually apply to the discovered version. Then call this tool ONCE with all credible candidates (or an empty list if none apply).

Applicable candidates are ingested as \`vulnerability\` nodes + \`VULNERABLE_TO\` edges (marked \`tested: false\` — candidates for the primary to verify/exploit). The service is always stamped \`cve_checked_at\` so it isn't re-queued for research.`,
      inputSchema: {
        service_id: z.string().describe('The service node id that was researched'),
        agent_id: z.string().optional().describe('Your agent id (for attribution)'),
        summary: z.string().describe('One-line summary of what the research found'),
        candidates: z.array(z.object({
          cve: z.string().optional().describe('CVE id, e.g. CVE-2021-41773'),
          title: z.string().describe('Short title if no CVE id'),
          cvss: z.number().min(0).max(10).optional(),
          vuln_type: z.string().optional().describe('rce | sqli | auth_bypass | …'),
          exploit_available: z.boolean().optional().describe('true if a public POC/exploit exists'),
          poc_url: z.string().optional().describe('URL of the advisory or POC'),
          applicable: z.boolean().describe('true if this CVE applies to the discovered version'),
          confidence: z.number().min(0).max(1).optional().describe('your confidence the service is affected'),
          notes: z.string().optional(),
        })).default([]).describe('Researched candidates; only applicable=true ones become VULNERABLE_TO edges'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    withErrorBoundary('research_cve', async ({ service_id, agent_id, summary, candidates }) => {
      const result = recordCveResearch(engine, { service_id, agent_id, summary, candidates });
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        ...(result.ok ? {} : { isError: true }),
      };
    }),
  );
}
