import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { nodeTypeSchema, edgeTypeSchema } from '../types.js';
import type { Finding, NodeType, EdgeType } from '../types.js';
import { prepareFindingForIngest } from '../services/finding-validation.js';
import { deriveNodeExcerpts } from '../services/parser-utils.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerFindingTools(server: McpServer, engine: GraphEngine): void {

  // ============================================================
  // Tool: report_finding
  // Agents report discoveries here. Updates graph + runs inference.
  // ============================================================
  server.registerTool(
    'report_finding',
    {
      title: 'Report Finding',
      description: `Report a discovery from agent execution. This is how new information enters the graph.

Submit nodes (hosts, services, credentials, users, etc.) and edges (relationships between them).
The orchestrator will:
1. Add/update nodes and edges in the graph
2. Run inference rules to generate new hypothetical edges
3. Re-evaluate objectives
4. Persist state to disk

Always report findings as they occur — do not batch them. Interim reporting enables
reactive re-planning by the primary session.

Returns: Summary of what was added/updated and any new inferred edges.`,
      inputSchema: {
        agent_id: z.string().optional().describe('ID of the reporting agent (optional for primary session)'),
        action_id: z.string().optional().describe('Stable action ID linking this finding to a validated/executed action'),
        tool_name: z.string().optional().describe('Tool or command family that produced this finding'),
        tool: z.string().optional().describe('Alias for tool_name'),
        target_node_ids: z.array(z.string()).default([]).describe('Primary graph node IDs this finding came from'),
        frontier_item_id: z.string().optional().describe('Frontier item this finding came from'),
        nodes: z.array(z.object({
          id: z.string().describe('Unique node ID, e.g. host-10-10-10-5, svc-10-10-10-5-445'),
          type: nodeTypeSchema,
          label: z.string().describe('Human-readable label'),
          properties: z.record(z.unknown()).optional().describe('Additional properties as key-value pairs')
        })).default([]).describe('New or updated nodes to add to the graph'),
        edges: z.array(z.object({
          source: z.string().describe('Source node ID'),
          target: z.string().describe('Target node ID'),
          type: edgeTypeSchema,
          confidence: z.number().min(0).max(1).default(1.0),
          properties: z.record(z.unknown()).optional()
        })).default([]).describe('New or updated edges'),
        evidence: z.object({
          type: z.enum(['screenshot', 'log', 'file', 'command_output']),
          content: z.string(),
          filename: z.string().optional()
        }).optional().describe('Supporting evidence'),
        raw_output: z.string().optional().describe('Raw command/tool output for logging'),
        excerpts: z.array(z.object({
          evidence_id: z.string().optional().describe('Evidence blob the offsets index into; defaults to this finding\'s evidence blob'),
          node_id: z.string().optional().describe('Graph node this excerpt justifies'),
          edge_key: z.string().optional().describe('Graph edge this excerpt justifies'),
          byte_start: z.number().int().min(0).describe('Start byte offset into the evidence blob (inclusive)'),
          byte_end: z.number().int().min(0).describe('End byte offset into the evidence blob (exclusive)'),
          matched_by: z.string().optional().describe('What recognized the signal (rule/regex/parser/agent)'),
          snippet: z.string().optional().describe('The matched text captured at conclusion time'),
        })).optional().describe('Matched-signal excerpts: the specific byte range(s) of the evidence that justify this finding, so a reader can verify how it was found.')
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      }
    },
    withErrorBoundary('report_finding', async ({ agent_id, action_id, tool_name: rawToolName, tool, target_node_ids = [], frontier_item_id, nodes, edges, evidence, raw_output, excerpts }) => {
      const tool_name = rawToolName || tool;
      const normalizedActionId = action_id || uuidv4();
      const warnings: string[] = [];
      const finding: Finding = {
        id: uuidv4(),
        agent_id: agent_id || 'primary',
        timestamp: new Date().toISOString(),
        action_id: normalizedActionId,
        tool_name,
        frontier_item_id,
        target_node_ids,
        nodes: nodes.map(n => ({
          id: n.id,
          type: n.type as NodeType,
          label: n.label,
          ...n.properties
        })),
        edges: edges.map(e => ({
          source: e.source,
          target: e.target,
          properties: {
            type: e.type as EdgeType,
            confidence: e.confidence,
            ...e.properties
          }
        })),
        evidence,
        raw_output,
        excerpts,
      };

      const frontierType = frontier_item_id ? engine.getFrontierItem(frontier_item_id)?.type : undefined;
      if (!action_id) {
        warnings.push('report_finding was called without prior action context; generated a new action_id, but retrospective linkage will be weaker.');
        engine.logActionEvent({
          description: 'Finding reported without prior action context',
          agent_id,
          action_id: normalizedActionId,
          event_type: 'instrumentation_warning',
          category: 'system',
          frontier_type: frontierType,
          tool_name,
          frontier_item_id,
          result_classification: 'neutral',
          details: { warning: 'missing_action_context' },
        });
      }

      const prepared = prepareFindingForIngest(finding, nodeId => engine.getNode(nodeId));

      // Salvage instead of nuking the whole finding: invalid EDGES (a missing
      // endpoint or a type-constraint violation) are dropped so the rest of the
      // finding still lands. Only node-level integrity failures (e.g. a
      // credential claiming reusable access without material) are fatal, because
      // ingesting those would corrupt downstream reasoning.
      const edgeErrors = prepared.errors.filter(
        e => e.code === 'missing_node_reference' || e.code === 'edge_type_constraint',
      );
      const fatalErrors = prepared.errors.filter(
        e => e.code !== 'missing_node_reference' && e.code !== 'edge_type_constraint',
      );

      if (fatalErrors.length > 0) {
        engine.logActionEvent({
          description: 'Finding report rejected: invalid graph mutation',
          agent_id,
          action_id: normalizedActionId,
          category: 'finding',
          tool_name,
          frontier_type: frontierType,
          frontier_item_id,
          result_classification: 'failure',
          details: { validation_errors: prepared.errors },
        });
        engine.persist();
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              action_id: normalizedActionId,
              finding_id: finding.id,
              validation_errors: prepared.errors,
            }, null, 2),
          }],
          isError: true,
        };
      }

      // Drop the invalid edges from the prepared finding, and surface the drop
      // loudly (activity console + tool result) so a partial ingest is never
      // silent — the operator sees what the agent found but couldn't link.
      if (edgeErrors.length > 0) {
        const skipSet = new Set(
          edgeErrors.map(e => `${e.source_id}→${e.target_id}→${e.edge_type}`),
        );
        prepared.finding.edges = prepared.finding.edges.filter(
          e => !skipSet.has(`${e.source}→${e.target}→${e.properties.type}`),
        );
        const droppedEdges = edgeErrors.map(e => ({
          source: e.source_id,
          target: e.target_id,
          edge_type: e.edge_type,
          reason: e.message,
          suggestion: e.suggestion,
        }));
        engine.logActionEvent({
          description: `Finding partially ingested: ${edgeErrors.length} invalid edge(s) dropped`,
          agent_id,
          action_id: normalizedActionId,
          event_type: 'instrumentation_warning',
          category: 'finding',
          tool_name,
          frontier_type: frontierType,
          frontier_item_id,
          result_classification: 'failure',
          details: { dropped_edges: droppedEdges },
        });
        warnings.push(
          `${edgeErrors.length} edge(s) failed schema validation and were dropped; the finding's nodes were still ingested. See dropped_edges.`,
        );
      }

      // Store full evidence in the durable evidence store, keep inline
      // snippets in the activity log for fast access and report rendering.
      const evidenceDetails: Record<string, unknown> = {
        node_count: prepared.finding.nodes.length,
        // Report what actually ingests — prepared.finding.edges has any salvaged
        // (schema-invalid) edges already dropped, so the count can't overstate.
        edge_count: prepared.finding.edges.length,
        ingested_node_ids: prepared.finding.nodes.map(n => n.id),
      };
      let storedEvidenceId: string | undefined;
      if (evidence || raw_output) {
        const store = engine.getEvidenceStore();
        storedEvidenceId = store.store({
          action_id: normalizedActionId,
          finding_id: finding.id,
          // M1: durable node→evidence index — persist which nodes this evidence
          // supports so a report can still find the blob after the activity log
          // that referenced it has rolled over.
          node_ids: prepared.finding.nodes.map(n => n.id),
          evidence_type: evidence?.type || 'command_output',
          filename: evidence?.filename,
          content: evidence?.content,
          raw_output,
          // Self-describing record: the tool the agent named as the source.
          ...(tool_name ? { tool: tool_name } : {}),
        });
        evidenceDetails.evidence_id = storedEvidenceId;
      }
      if (evidence) {
        evidenceDetails.evidence_type = evidence.type;
        evidenceDetails.evidence_content = evidence.content?.slice(0, 8192);
        if (evidence.filename) evidenceDetails.evidence_filename = evidence.filename;
      }
      if (raw_output) {
        evidenceDetails.raw_output = raw_output.slice(0, 8192);
      }

      // 3c: persist matched-signal excerpts. Prefer the agent's own explicit
      // excerpts; when it supplied none, derive them generically from raw_output for
      // verbatim high-value values (credential material / CVE ids) — the same
      // fleet-wide derivation the parse_output path uses (#2). This closes the
      // report_finding parity gap the worker-agent dogfood exposed: an agent that
      // captures stdout and reports a finding gets "how it was found" byte ranges
      // without hand-computing offsets. Derivation indexes raw_output, which is
      // exactly the bytes stored as this finding's raw evidence blob, so the offsets
      // stay verifiable (a non-verbatim value yields no excerpt, never a bogus one).
      const explicitExcerpts = excerpts ?? [];
      const effectiveExcerpts = explicitExcerpts.length > 0
        ? explicitExcerpts
        : (raw_output
          ? deriveNodeExcerpts(prepared.finding, raw_output, { matched_by: tool_name || 'report_finding' })
          : []);
      // Backfill evidence_id to this finding's durable blob when omitted, drop
      // malformed spans (end must exceed start) with a loud warning so a bad locator
      // never silently claims to prove something.
      if (effectiveExcerpts.length > 0) {
        const validExcerpts = effectiveExcerpts
          .map(ex => ({ ...ex, evidence_id: ex.evidence_id ?? storedEvidenceId }))
          .filter(ex => {
            const ok = ex.byte_end > ex.byte_start && (ex.evidence_id !== undefined || ex.snippet !== undefined);
            if (!ok) {
              warnings.push(`Dropped an excerpt with an invalid byte range (${ex.byte_start}-${ex.byte_end}) or no blob/snippet.`);
            }
            return ok;
          });
        if (validExcerpts.length > 0) evidenceDetails.excerpts = validExcerpts;
      }

      const result = engine.ingestFinding(prepared.finding);

      // Finding ingestion owns campaign attribution so the successful dedup
      // fingerprint and campaign link share one durable state patch. Duplicate
      // findings additionally commit their attribution merge, dedup counter,
      // canonical audit event, and campaign link in one EngineTransaction.
      const campaign_id = result.campaign_id;

      // Blob-first ordering is intentional: a crash or failed ingest may leave
      // an unreferenced content-addressed blob for later cleanup, but durable
      // activity must never claim that evidence/finding landed before the graph
      // mutation actually succeeds.
      engine.logActionEvent({
        description: `Finding reported: ${prepared.finding.nodes.length} nodes, ${prepared.finding.edges.length} edges`,
        agent_id,
        action_id: normalizedActionId,
        event_type: 'finding_reported',
        category: 'finding',
        frontier_type: frontierType,
        tool_name,
        target_node_ids: [
          ...(target_node_ids.length > 0 ? target_node_ids : []),
          ...finding.nodes.map(n => n.id),
        ],
        frontier_item_id,
        linked_finding_ids: [finding.id],
        result_classification: 'success',
        details: evidenceDetails,
      });

      // Durability: a reported finding is the engagement's most important data —
      // flush it (and the campaign link above) to disk synchronously rather than
      // riding the ≤500ms debounce, so a daemon crash right after report_finding
      // can't lose it. report_finding is a single, infrequent call (not a bulk
      // batch), so the extra write is cheap.
      engine.flushNow();

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            action_id: normalizedActionId,
            finding_id: finding.id,
            campaign_id,
            new_nodes: result.new_nodes,
            new_edges: result.new_edges,
            inferred_edges: result.inferred_edges,
            evidence_id: (evidenceDetails.evidence_id as string) || undefined,
            warnings: warnings.length > 0 ? warnings : undefined,
            message: `Ingested: ${result.new_nodes.length} new nodes, ${result.new_edges.length} new edges, ${result.inferred_edges.length} inferred edges`
          }, null, 2)
        }]
      };
    })
  );

  // ============================================================
  // Tool: get_evidence
  // Retrieve full-fidelity evidence by ID or list stored evidence.
  // ============================================================
  server.registerTool(
    'get_evidence',
    {
      title: 'Get Evidence',
      description: `Retrieve full-fidelity evidence stored during findings.

When evidence or raw_output is submitted via report_finding, the full payload
is stored durably on disk (not truncated). Use this tool to retrieve the
complete content by evidence_id, or list all stored evidence records.

The evidence_id is returned in report_finding responses and stored in
activity log details.evidence_id fields.`,
      inputSchema: {
        evidence_id: z.string().optional().describe('Specific evidence ID to retrieve full content'),
        action_id: z.string().optional().describe('List evidence for a specific action'),
        finding_id: z.string().optional().describe('List evidence for a specific finding'),
        list_only: z.boolean().default(false).describe('If true, return manifest records without content'),
        max_bytes: z.number().int().positive().max(4 * 1024 * 1024).default(256 * 1024)
          .describe('Cap on returned content/raw_output bytes (default 256 KiB). Evidence blobs can be arbitrarily large; a full read on a poll can pin the daemon.'),
        offset: z.number().int().nonnegative().default(0)
          .describe('Byte offset into raw_output for paging; the response returns next_offset + truncated to continue.'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('get_evidence', async ({ evidence_id, action_id, finding_id, list_only, max_bytes, offset }) => {
      const store = engine.getEvidenceStore();
      // Defensive defaults: the MCP layer applies the zod defaults, but direct callers
      // (and tests) may omit them; a 0-byte cap would silently return no content.
      const capBytes = max_bytes ?? 256 * 1024;
      const readOffset = offset ?? 0;

      if (evidence_id) {
        const record = store.getRecord(evidence_id);
        if (!record) {
          return {
            content: [{ type: 'text', text: JSON.stringify({ error: `Evidence ${evidence_id} not found` }) }],
            isError: true,
          };
        }
        if (list_only) {
          return { content: [{ type: 'text', text: JSON.stringify(record, null, 2) }] };
        }
        // M11: bounded read. A full getRawOutput/getContent on an arbitrarily large blob
        // (called on a poll) can pin the daemon. Read a bounded raw slice from `offset`
        // and expose next_offset + truncated so callers can page.
        const slice = store.getRawOutputSlice(evidence_id, readOffset, capBytes);
        const rawTruncated = slice ? !slice.eof : false;
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              ...record,
              content: store.getContent(evidence_id, { max_bytes: capBytes }),
              raw_output: slice?.text ?? null,
              raw_output_total_bytes: slice?.total_bytes,
              raw_output_offset: slice?.offset ?? readOffset,
              raw_output_truncated: rawTruncated,
              ...(rawTruncated && slice ? { next_offset: slice.offset + slice.bytes_read } : {}),
            }, null, 2),
          }],
        };
      }

      const records = store.list(
        action_id || finding_id ? { action_id, finding_id } : undefined,
      );
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            total: records.length,
            records,
          }, null, 2),
        }],
      };
    }),
  );
}
