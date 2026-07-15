import { z } from 'zod';
import { readFileSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { getSupportedParsers } from '../services/parsers/index.js';
import { parseAndMaybeIngest, type ParseIngestResult } from '../services/parse-ingest.js';
import { withErrorBoundary } from './error-boundary.js';
import { validateFilePath } from '../utils/path-validation.js';
import { ParserContextSchema } from '../types.js';

/** Render the shared parse result into the parse_output tool's JSON response shapes. */
function formatParseResult(
  result: ParseIngestResult,
  parsed_from: 'output' | 'file_path',
  ingest: boolean,
): { content: { type: 'text'; text: string }[]; isError?: boolean } {
  const json = (obj: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(obj, null, 2) }] });
  const warnings = result.warnings && result.warnings.length > 0 ? result.warnings : undefined;
  const common = {
    parse_status: result.parse_status,
    parse_outcome: result.parse_outcome,
    tool: result.tool,
    action_id: result.action_id,
    finding_id: result.finding_id,
    parsed_from,
    nodes_parsed: result.nodes_parsed,
    edges_parsed: result.edges_parsed,
    warnings,
    partial: result.partial,
    partial_reason: result.partial_reason,
    parse_stream: result.parse_stream,
    parsed_from_evidence: result.parsed_from_evidence,
    evidence_read_error: result.evidence_read_error,
    exit_code: result.exit_code,
    failure_stage: result.failure_stage,
    parser_exception: result.parser_exception,
  };
  if (result.parse_outcome === 'partial') {
    return json({
      ...common,
      parsed: true,
      ingested: result.ingested,
      isError: false,
      message: ingest && result.ingested
        ? `Partially parsed and ingested: ${result.ingested.new_nodes} nodes, ${result.ingested.new_edges} edges, ${result.ingested.inferred_edges} inferred`
        : `Partially parsed: ${result.nodes_parsed} nodes, ${result.edges_parsed} edges (not ingested)`,
    });
  }
  switch (result.parse_status) {
    case 'no_parser':
      return {
        ...json({ ...common, parsed: false, ingested: false, isError: true, error: result.error, supported_parsers: result.supported_parsers }),
        isError: true,
      };
    case 'parser_exception':
      return {
        ...json({
          ...common, parsed: false, ingested: false, isError: true, error: result.error,
          message: `Parser '${result.tool}' threw — see error field for the exception and input prefix.`,
        }),
        isError: true,
      };
    case 'no_data':
      return {
        ...json({
          ...common, parsed: false, ingested: false, isError: true,
          message: 'Output parsed but no data extracted. Check the output format.',
        }),
        isError: true,
      };
    case 'validation_failed':
      return {
        ...json({
          ...common, parsed: result.parsed, ingested: false, isError: true,
          validation_errors: result.validation_errors,
        }),
        isError: true,
      };
    case 'ok':
    default:
      return json({
        ...common, parsed: true, ingested: result.ingested, isError: false,
        message: ingest && result.ingested
          ? `Parsed and ingested: ${result.ingested.new_nodes} nodes, ${result.ingested.new_edges} edges, ${result.ingested.inferred_edges} inferred`
          : `Parsed: ${result.nodes_parsed} nodes, ${result.edges_parsed} edges (not ingested)`,
      });
  }
}

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
- **ldapsearch** / **ldapdomaindump** / **ldap**: LDIF or ldapdomaindump JSON → user + group + host + domain nodes with UAC flags, SPNs, group memberships
- **enum4linux** / **enum4linux-ng**: JSON or text output → host + SMB service + user + group + share nodes, null session detection
- **rubeus**: Kerberoast/AS-REP roast hashes + monitor/triage captured tickets → user + credential nodes + OWNS_CRED edges
- **gobuster** / **feroxbuster** / **ffuf** / **dirbuster**: Directory enumeration → service node enrichment with discovered paths, login form detection

The parsed output is automatically ingested into the graph. This reduces LLM token cost
by handling structured parsing deterministically.

Pass either the raw output content or a local file path for large artifacts.`,
      inputSchema: {
        tool_name: z.string().optional().describe('Name of the tool that produced the output (e.g. nmap, nxc, certipy)'),
        tool: z.string().optional().describe('Alias for tool_name'),
        output: z.string().optional().describe('Raw tool output to parse'),
        file_path: z.string().optional().describe('Local file path to a saved text artifact to parse'),
        agent_id: z.string().optional().describe('Agent ID to attribute the findings to'),
        action_id: z.string().optional().describe('Stable action ID linking this parse to a validated/executed action'),
        frontier_item_id: z.string().optional().describe('Frontier item this parse came from'),
        context: ParserContextSchema.optional().describe('Optional credential, tenant, repository, branch, cloud, target, domain, host, or provider-specific parser context'),
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
    withErrorBoundary('parse_output', async ({ tool_name: rawToolName, tool, output, file_path, agent_id, action_id, frontier_item_id, context, ingest, list_parsers }) => {
      const tool_name = rawToolName || tool;
      if (list_parsers) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ supported_parsers: getSupportedParsers() }, null, 2) }]
        };
      }

      if (!tool_name) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: 'Provide "tool_name" (or "tool") — the name of the tool that produced the output.',
              supported_parsers: getSupportedParsers(),
            }, null, 2),
          }],
          isError: true,
        };
      }

      const outputProvided = output !== undefined;
      const filePathProvided = file_path !== undefined;
      if (Number(outputProvided) + Number(filePathProvided) !== 1) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ error: 'Provide exactly one of "output" or "file_path".' }, null, 2),
          }],
          isError: true,
        };
      }

      let outputText: string;
      if (filePathProvided) {
        let resolvedPath: string;
        try {
          resolvedPath = validateFilePath(file_path!);
        } catch (error) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({ error: `Invalid file_path: ${error instanceof Error ? error.message : String(error)}` }, null, 2),
            }],
            isError: true,
          };
        }
        try {
          outputText = readFileSync(resolvedPath, 'utf8');
        } catch (error) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: `Failed to read parser input from file_path: ${file_path}`,
                details: error instanceof Error ? error.message : String(error),
              }, null, 2),
            }],
            isError: true,
          };
        }
      } else {
        outputText = output!;
      }

      const result = parseAndMaybeIngest(engine, { tool_name, outputText, agent_id, action_id, frontier_item_id, context, ingest });
      return formatParseResult(result, filePathProvided ? 'file_path' : 'output', ingest);
    })
  );
}
