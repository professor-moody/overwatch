import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { nodeTypeSchema, edgeTypeSchema } from '../types.js';
import type { Finding, NodeType, EdgeType } from '../types.js';
import { prepareFindingForIngest } from '../services/finding-validation.js';
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
        raw_output: z.string().optional().describe('Raw command/tool output for logging')
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      }
    },
    withErrorBoundary('report_finding', async ({ agent_id, action_id, tool_name, target_node_ids = [], frontier_item_id, nodes, edges, evidence, raw_output }) => {
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
        raw_output
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
      if (prepared.errors.length > 0) {
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

      // Store full evidence in the durable evidence store, keep inline
      // snippets in the activity log for fast access and report rendering.
      const evidenceDetails: Record<string, unknown> = {
        node_count: finding.nodes.length,
        edge_count: finding.edges.length,
        ingested_node_ids: finding.nodes.map(n => n.id),
      };
      if (evidence || raw_output) {
        const store = engine.getEvidenceStore();
        const evidenceId = store.store({
          action_id: normalizedActionId,
          finding_id: finding.id,
          evidence_type: evidence?.type || 'command_output',
          filename: evidence?.filename,
          content: evidence?.content,
          raw_output,
        });
        evidenceDetails.evidence_id = evidenceId;
      }
      if (evidence) {
        evidenceDetails.evidence_type = evidence.type;
        evidenceDetails.evidence_content = evidence.content?.slice(0, 8192);
        if (evidence.filename) evidenceDetails.evidence_filename = evidence.filename;
      }
      if (raw_output) {
        evidenceDetails.raw_output = raw_output.slice(0, 8192);
      }

      engine.logActionEvent({
        description: `Finding reported: ${finding.nodes.length} nodes, ${finding.edges.length} edges`,
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

      const result = engine.ingestFinding(prepared.finding);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            action_id: normalizedActionId,
            finding_id: finding.id,
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
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('get_evidence', async ({ evidence_id, action_id, finding_id, list_only }) => {
      const store = engine.getEvidenceStore();

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
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              ...record,
              content: store.getContent(evidence_id),
              raw_output: store.getRawOutput(evidence_id),
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
