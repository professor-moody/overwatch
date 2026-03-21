import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { parseOutput, getSupportedParsers } from '../services/output-parsers.js';

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
- **crackmapexec** / **cme** / **netexec** / **nxc**: CME/NXC output → user nodes, share nodes, access edges
- **certipy**: Certipy JSON output → certificate nodes, enrollment edges, ESC edges

The parsed output is automatically ingested into the graph. This reduces LLM token cost
by handling structured parsing deterministically.

Pass the tool name and the raw output content.`,
      inputSchema: {
        tool_name: z.string().describe('Name of the tool that produced the output (e.g. nmap, cme, certipy)'),
        output: z.string().describe('Raw tool output to parse'),
        agent_id: z.string().optional().describe('Agent ID to attribute the findings to'),
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
    async ({ tool_name, output, agent_id, ingest, list_parsers }) => {
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

      if (finding.nodes.length === 0 && finding.edges.length === 0) {
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

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            parsed: true,
            tool: tool_name,
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
    }
  );
}
