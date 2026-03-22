import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { parseOutput, getSupportedParsers } from '../services/output-parsers.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerParseOutputTools(server: McpServer, engine: GraphEngine): void {

  // ============================================================
  // Tool: parse_output
  // Parse common tool outputs into structured Findings
  // ============================================================
  server.registerTool(
    'parse_output',
    {
      title: 'Parse Tool Output',
      description: `Parse raw output from common offensive tools into structured graph data.

Supported tools:
- **nmap** / **nmap-xml**: Nmap XML output → host + service nodes + RUNS edges
- **nxc** / **netexec**: NXC (NetExec) output → host + SMB service nodes, connected share nodes, access edges
- **certipy**: Certipy JSON output → certificate nodes, enrollment edges, ESC edges
- **secretsdump** / **impacket-secretsdump**: SAM/NTDS hashes → credential + user nodes + OWNS_CRED edges
- **kerbrute**: User enumeration + password spray → user + domain + credential nodes
- **hashcat**: Cracked hashes (NTLM, Kerberoast, AS-REP, NTLMv2) → credential nodes
- **responder**: Captured NTLMv2 hashes → credential + user + host nodes + capture evidence

The parsed output is automatically ingested into the graph. This reduces LLM token cost
by handling structured parsing deterministically.

Pass the tool name and the raw output content.`,
      inputSchema: {
        tool_name: z.string().describe('Name of the tool that produced the output (e.g. nmap, nxc, certipy)'),
        output: z.string().describe('Raw tool output to parse'),
        agent_id: z.string().optional().describe('Agent ID to attribute the findings to'),
        action_id: z.string().optional().describe('Stable action ID linking this parse to a validated/executed action'),
        frontier_item_id: z.string().optional().describe('Frontier item this parse came from'),
        ingest: z.boolean().default(true).describe('Automatically ingest parsed findings into the graph'),
        list_parsers: z.boolean().default(false).describe('List all supported parser names'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      }
    },
    withErrorBoundary('parse_output', async ({ tool_name, output, agent_id, action_id, frontier_item_id, ingest, list_parsers }) => {
      const normalizedActionId = action_id || uuidv4();
      if (list_parsers) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ supported_parsers: getSupportedParsers() }, null, 2)
          }]
        };
      }

      const finding = parseOutput(tool_name, output, agent_id);
      if (!finding) {
        engine.logActionEvent({
          description: `Output parse failed: no parser for ${tool_name}`,
          agent_id,
          action_id: normalizedActionId,
          event_type: 'parse_output',
          category: 'finding',
          tool_name,
          frontier_item_id,
          frontier_type: frontier_item_id ? engine.getFrontierItem(frontier_item_id)?.type : undefined,
          result_classification: 'failure',
        });
        engine.persist();
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: `No parser found for tool: ${tool_name}`,
              supported_parsers: getSupportedParsers(),
            }, null, 2)
          }],
          isError: true,
        };
      }

      finding.action_id = normalizedActionId;
      finding.tool_name = tool_name;
      finding.frontier_item_id = frontier_item_id;

      if (finding.nodes.length === 0 && finding.edges.length === 0) {
        engine.logActionEvent({
          description: `Output parsed for ${tool_name} but no graph data was extracted`,
          agent_id: finding.agent_id,
          action_id: normalizedActionId,
          event_type: 'parse_output',
          category: 'finding',
          tool_name,
          frontier_item_id,
          frontier_type: frontier_item_id ? engine.getFrontierItem(frontier_item_id)?.type : undefined,
          linked_finding_ids: [finding.id],
          result_classification: 'neutral',
          details: { parsed_nodes: 0, parsed_edges: 0, ingested: false },
        });
        engine.persist();
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              parsed: true,
              nodes: 0,
              edges: 0,
              message: 'Output parsed but no data extracted. Check the output format.',
            }, null, 2)
          }]
        };
      }

      let ingestResult: { new_nodes: string[]; new_edges: string[]; inferred_edges: string[] } | undefined;
      if (ingest) {
        ingestResult = engine.ingestFinding(finding);
      }

      engine.logActionEvent({
        description: ingest
          ? `Output parsed and ingested for ${tool_name}`
          : `Output parsed for ${tool_name} without ingest`,
        agent_id: finding.agent_id,
        action_id: normalizedActionId,
        event_type: 'parse_output',
        category: 'finding',
        tool_name,
        frontier_item_id,
        frontier_type: frontier_item_id ? engine.getFrontierItem(frontier_item_id)?.type : undefined,
        linked_finding_ids: [finding.id],
        result_classification: ingest ? 'success' : 'neutral',
        details: {
          parsed_nodes: finding.nodes.length,
          parsed_edges: finding.edges.length,
          ingested: ingest,
          new_nodes: ingest ? ingestResult!.new_nodes.length : 0,
          new_edges: ingest ? ingestResult!.new_edges.length : 0,
          inferred_edges: ingest ? ingestResult!.inferred_edges.length : 0,
        },
      });
      engine.persist();

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            parsed: true,
            tool: tool_name,
            action_id: normalizedActionId,
            finding_id: finding.id,
            nodes_parsed: finding.nodes.length,
            edges_parsed: finding.edges.length,
            ingested: ingest ? {
              new_nodes: ingestResult!.new_nodes.length,
              new_edges: ingestResult!.new_edges.length,
              inferred_edges: ingestResult!.inferred_edges.length,
            } : undefined,
            message: ingest
              ? `Parsed and ingested: ${ingestResult!.new_nodes.length} nodes, ${ingestResult!.new_edges.length} edges, ${ingestResult!.inferred_edges.length} inferred`
              : `Parsed: ${finding.nodes.length} nodes, ${finding.edges.length} edges (not ingested)`,
          }, null, 2)
        }]
      };
    })
  );
}
