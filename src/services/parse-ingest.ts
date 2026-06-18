// Shared parse → (optional) ingest pipeline. Extracted from the parse_output
// MCP tool so both the tool and the dashboard re-parse route (Analysis
// workspace) run identical logic: the same domain-alias enrichment, parser
// dispatch, validation, event logging, and graph ingestion. Callers differ
// only in input resolution (output string / file / evidence blob) and in how
// they render the structured result.

import { v4 as uuidv4 } from 'uuid';
import type { GraphEngine } from './graph-engine.js';
import type { ParseContext } from '../types.js';
import { parseOutput, getSupportedParsers, isParserError } from './parsers/index.js';
import { prepareFindingForIngest } from './finding-validation.js';

export interface ParseIngestOpts {
  tool_name: string;
  outputText: string;
  agent_id?: string;
  /** Stable action id; a new one is minted when absent (weaker retrospective linkage). */
  action_id?: string;
  frontier_item_id?: string;
  context?: ParseContext;
  /** Apply the parsed finding to the graph (false = preview only). */
  ingest: boolean;
}

export type ParseStatus = 'ok' | 'no_data' | 'validation_failed' | 'parser_exception' | 'no_parser';

export interface ParseIngestResult {
  parsed: boolean;
  parse_status: ParseStatus;
  /** True for the failure statuses (no_parser / parser_exception / no_data / validation_failed). */
  isError: boolean;
  tool: string;
  action_id: string;
  finding_id?: string;
  nodes_parsed: number;
  edges_parsed: number;
  ingested?: { new_nodes: number; new_edges: number; inferred_edges: number };
  validation_errors?: unknown[];
  warnings?: string[];
  /** Parser-exception detail or no-parser message. */
  error?: string;
  supported_parsers?: string[];
}

/**
 * Parse `outputText` with the named parser and, when `ingest` is true, apply it
 * to the graph. Logs the same lifecycle events as the parse_output tool and
 * persists. Never throws for the expected failure modes — they come back as a
 * result with `isError: true` and a `parse_status`.
 */
export function parseAndMaybeIngest(engine: GraphEngine, opts: ParseIngestOpts): ParseIngestResult {
  const { tool_name, outputText, agent_id, frontier_item_id, context, ingest } = opts;
  const action_id = opts.action_id || uuidv4();
  const warnings: string[] = [];

  // Build a NetBIOS→FQDN domain alias map from existing graph domain nodes so
  // parsers can attribute credentials/users to the right domain.
  const enrichedContext: ParseContext = { ...context };
  if (!enrichedContext.domain_aliases) {
    const aliases: Record<string, string> = {};
    for (const node of engine.getNodesByType('domain')) {
      const fqdn = (node.domain_name || node.label || '') as string;
      if (fqdn && fqdn.includes('.')) {
        const fqdnLower = fqdn.toLowerCase();
        const firstLabel = fqdn.split('.')[0].toUpperCase();
        aliases[firstLabel] = fqdnLower;
        if (typeof node.netbios_name === 'string' && node.netbios_name.length > 0) {
          aliases[node.netbios_name.toUpperCase()] = fqdnLower;
        }
      }
    }
    if (Object.keys(aliases).length > 0) enrichedContext.domain_aliases = aliases;
  }

  const frontierType = frontier_item_id ? engine.getFrontierItem(frontier_item_id)?.type : undefined;

  const finding = parseOutput(tool_name, outputText, agent_id, enrichedContext);
  if (!finding) {
    engine.logActionEvent({
      description: `Output parse failed: no parser for ${tool_name}`,
      agent_id, action_id, event_type: 'parse_output', category: 'finding',
      tool_name, frontier_item_id, frontier_type: frontierType, result_classification: 'failure',
    });
    engine.persist();
    return {
      parsed: false, parse_status: 'no_parser', isError: true, tool: tool_name, action_id,
      nodes_parsed: 0, edges_parsed: 0,
      error: `No parser found for tool: ${tool_name}`,
      supported_parsers: getSupportedParsers(),
    };
  }

  finding.action_id = action_id;
  finding.tool_name = tool_name;
  finding.frontier_item_id = frontier_item_id;

  if (isParserError(finding)) {
    engine.logActionEvent({
      description: `Parser '${tool_name}' threw an exception`,
      agent_id: finding.agent_id, action_id, event_type: 'parse_output', category: 'finding',
      tool_name, frontier_item_id, frontier_type: frontierType, result_classification: 'failure',
      details: { parse_status: 'parser_exception' },
    });
    engine.persist();
    return {
      parsed: false, parse_status: 'parser_exception', isError: true, tool: tool_name, action_id,
      finding_id: finding.id, nodes_parsed: 0, edges_parsed: 0, error: finding.raw_output,
    };
  }

  if (tool_name === 'certipy' && finding.nodes.length > 0 && finding.edges.length === 0) {
    warnings.push('Certipy text fallback used — only template names extracted. ESC edges, CA data, and enrollment permissions are missing. Re-run certipy with JSON output (-json) for full ADCS attack path analysis.');
  }

  if (!opts.action_id) {
    warnings.push('parse_output was called without prior action context; generated a new action_id, but retrospective linkage will be weaker.');
    engine.logActionEvent({
      description: 'Parsed output without prior action context',
      agent_id: finding.agent_id, action_id, event_type: 'instrumentation_warning', category: 'system',
      frontier_type: frontierType, tool_name, frontier_item_id, result_classification: 'neutral',
      details: { warning: 'missing_action_context' },
    });
  }

  if (finding.nodes.length === 0 && finding.edges.length === 0) {
    engine.logActionEvent({
      description: `Output parsed for ${tool_name} but no graph data was extracted`,
      agent_id: finding.agent_id, action_id, event_type: 'parse_output', category: 'finding',
      tool_name, frontier_item_id, frontier_type: frontierType, linked_finding_ids: [finding.id],
      result_classification: 'failure',
      details: { parsed_nodes: 0, parsed_edges: 0, ingested: false, parse_status: 'no_data' },
    });
    engine.persist();
    return {
      parsed: false, parse_status: 'no_data', isError: true, tool: tool_name, action_id,
      finding_id: finding.id, nodes_parsed: 0, edges_parsed: 0,
      warnings: warnings.length > 0 ? warnings : undefined,
    };
  }

  const prepared = prepareFindingForIngest(finding, nodeId => engine.getNode(nodeId));
  if (prepared.errors.length > 0) {
    engine.logActionEvent({
      description: `Output parse rejected for ${tool_name}: invalid graph mutation`,
      agent_id: finding.agent_id, action_id, event_type: 'parse_output', category: 'finding',
      tool_name, frontier_item_id, frontier_type: frontierType, linked_finding_ids: [finding.id],
      result_classification: 'failure',
      details: { validation_errors: prepared.errors },
    });
    engine.persist();
    return {
      parsed: true, parse_status: 'validation_failed', isError: true, tool: tool_name, action_id,
      finding_id: finding.id, nodes_parsed: finding.nodes.length, edges_parsed: finding.edges.length,
      validation_errors: prepared.errors, warnings: warnings.length > 0 ? warnings : undefined,
    };
  }

  let ingestResult: { new_nodes: string[]; new_edges: string[]; inferred_edges: string[] } | undefined;
  if (ingest) {
    ingestResult = engine.ingestFinding(prepared.finding);
  }

  engine.logActionEvent({
    description: ingest ? `Output parsed and ingested for ${tool_name}` : `Output parsed for ${tool_name} without ingest`,
    agent_id: finding.agent_id, action_id, event_type: 'parse_output', category: 'finding',
    tool_name, frontier_item_id, frontier_type: frontierType, linked_finding_ids: [finding.id],
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
    parsed: true, parse_status: 'ok', isError: false, tool: tool_name, action_id,
    finding_id: finding.id, nodes_parsed: finding.nodes.length, edges_parsed: finding.edges.length,
    ingested: ingest
      ? { new_nodes: ingestResult!.new_nodes.length, new_edges: ingestResult!.new_edges.length, inferred_edges: ingestResult!.inferred_edges.length }
      : undefined,
    warnings: warnings.length > 0 ? warnings : undefined,
  };
}
