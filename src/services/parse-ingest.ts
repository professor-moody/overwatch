// Shared parse → (optional) ingest pipeline. Extracted from the parse_output
// MCP tool so both the tool and the dashboard re-parse route (Analysis
// workspace) run identical logic: the same domain-alias enrichment, parser
// dispatch, validation, event logging, and graph ingestion. Callers differ
// only in input resolution (output string / file / evidence blob) and in how
// they render the structured result.

import { v4 as uuidv4 } from 'uuid';
import type { GraphEngine } from './graph-engine.js';
import { ParserContextSchema, type ParseContext } from '../types.js';
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
  /** Input was incomplete, but any valid artifacts may still be ingested. */
  partial?: boolean;
  partial_reason?: string;
  parse_stream?: 'stdout' | 'stderr' | 'combined';
  parsed_from_evidence?: boolean;
  evidence_read_error?: string;
  exit_code?: number | null;
  parser_details?: Record<string, unknown>;
  /**
   * Optional application-command terminalizer. The callback is responsible for
   * committing `appendAudit` with the supplied result in one durable boundary.
   */
  command_completion?: ParseIngestCommandCompletion;
}

export type ParseOutcome = 'ok' | 'no_data' | 'validation_failed' | 'parser_exception' | 'partial';
/** `no_parser` remains as a legacy status; `parse_outcome` is canonical. */
export type ParseStatus = ParseOutcome | 'no_parser';

export interface ParseIngestResult {
  parsed: boolean;
  parse_status: ParseStatus;
  parse_outcome: ParseOutcome;
  /** True for the failure statuses (no_parser / parser_exception / no_data / validation_failed). */
  isError: boolean;
  tool: string;
  action_id: string;
  finding_id?: string;
  campaign_id?: string;
  nodes_parsed: number;
  edges_parsed: number;
  ingested?: false | { new_nodes: number; new_edges: number; inferred_edges: number };
  validation_errors?: unknown[];
  warnings?: string[];
  /** Parser-exception detail or no-parser message. */
  error?: string;
  /** Legacy inline-parser alias retained for one-release response compatibility. */
  parser_exception?: string;
  supported_parsers?: string[];
  failure_stage?: 'context' | 'parser_selection' | 'finding_validation';
  partial?: true;
  partial_reason?: string;
  parse_stream?: 'stdout' | 'stderr' | 'combined';
  parsed_from_evidence?: boolean;
  evidence_read_error?: string;
  exit_code?: number | null;
  parser_details?: Record<string, unknown>;
}

export type ParseIngestCommandCompletion = (
  result: ParseIngestResult,
  appendAudit: () => void,
) => void;

/**
 * Parser context is operational metadata, but provider extensions are open-
 * ended. Persist enough to reproduce a parse while removing any extension
 * value whose key looks like credential material.
 */
function parserContextForAudit(context: ParseContext): ParseContext {
  const walk = (value: unknown, key = ''): unknown => {
    const identifierKey = /^(source_credential_id|source_idp_application_id|credential_execution_binding)$/i.test(key);
    if (!identifierKey && /(authorization|bearer|password|secret|private[_-]?key|api[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?cookie|cred_value)/i.test(key)) {
      return '<redacted>';
    }
    if (Array.isArray(value)) return value.map(item => walk(item));
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([childKey, child]) => [childKey, walk(child, childKey)]));
    }
    return value;
  };
  return walk(context) as ParseContext;
}

/**
 * Parse `outputText` with the named parser and, when `ingest` is true, apply it
 * to the graph. Logs the same lifecycle events as the parse_output tool and
 * persists. Never throws for the expected failure modes — they come back as a
 * result with `isError: true` and a `parse_status`.
 */
export function parseAndMaybeIngest(engine: GraphEngine, opts: ParseIngestOpts): ParseIngestResult {
  const { tool_name, outputText, agent_id, frontier_item_id, ingest } = opts;
  const action_id = opts.action_id || uuidv4();
  const warnings: string[] = [];
  const frontierType = frontier_item_id ? engine.getFrontierItem(frontier_item_id)?.type : undefined;
  const quality = {
    partial: opts.partial ? true as const : undefined,
    partial_reason: opts.partial ? opts.partial_reason : undefined,
    parse_stream: opts.parse_stream,
    parsed_from_evidence: opts.parsed_from_evidence || undefined,
    evidence_read_error: opts.evidence_read_error,
    exit_code: opts.exit_code,
  };
  const finish = (
    result: ParseIngestResult,
    audit: Parameters<GraphEngine['logActionEvent']>[0],
  ): ParseIngestResult => {
    if (opts.command_completion) {
      opts.command_completion(result, () => {
        engine.logActionEvent(audit);
      });
    } else {
      engine.logActionEvent(audit);
      engine.persist();
    }
    return result;
  };

  const parsedContext = ParserContextSchema.safeParse(opts.context ?? {});
  if (!parsedContext.success) {
    const result: ParseIngestResult = {
      parsed: false, parse_status: 'validation_failed', parse_outcome: 'validation_failed',
      isError: true, tool: tool_name, action_id, nodes_parsed: 0, edges_parsed: 0,
      ingested: false, validation_errors: parsedContext.error.issues, failure_stage: 'context',
      ...quality,
    };
    return finish(result, {
      description: `Output parse rejected for ${tool_name}: invalid parser context`,
      agent_id, action_id, event_type: 'parse_output', category: 'finding',
      tool_name, frontier_item_id, frontier_type: frontierType, result_classification: 'failure',
      details: {
        parse_status: 'validation_failed', parse_outcome: 'validation_failed',
        failure_stage: 'context', validation_errors: parsedContext.error.issues,
        parsed_nodes: 0, parsed_edges: 0, ingested: false, ...quality,
      },
    });
  }

  // Build a NetBIOS→FQDN domain alias map from existing graph domain nodes so
  // parsers can attribute credentials/users to the right domain.
  const enrichedContext: ParseContext = { ...parsedContext.data };
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
  const durableParserContext = parserContextForAudit(enrichedContext);

  const finding = parseOutput(tool_name, outputText, agent_id, enrichedContext);
  if (!finding) {
    const result: ParseIngestResult = {
      parsed: false, parse_status: 'no_parser', parse_outcome: 'validation_failed', isError: true, tool: tool_name, action_id,
      nodes_parsed: 0, edges_parsed: 0, ingested: false, failure_stage: 'parser_selection',
      error: `No parser found for tool: ${tool_name}`,
      supported_parsers: getSupportedParsers(),
      ...quality,
    };
    return finish(result, {
      description: `Output parse failed: no parser for ${tool_name}`,
      agent_id, action_id, event_type: 'parse_output', category: 'finding',
      tool_name, frontier_item_id, frontier_type: frontierType, result_classification: 'failure',
      details: {
        parse_status: 'no_parser', parse_outcome: 'validation_failed', failure_stage: 'parser_selection',
        parsed_nodes: 0, parsed_edges: 0, ingested: false, parser_context: durableParserContext, ...quality,
      },
    });
  }

  finding.action_id = action_id;
  finding.tool_name = tool_name;
  finding.frontier_item_id = frontier_item_id;

  if (isParserError(finding)) {
    const result: ParseIngestResult = {
      parsed: false, parse_status: 'parser_exception', parse_outcome: 'parser_exception', isError: true, tool: tool_name, action_id,
      finding_id: finding.id, nodes_parsed: 0, edges_parsed: 0, ingested: false,
      error: finding.raw_output, parser_exception: finding.raw_output,
      ...quality,
    };
    return finish(result, {
      description: `Parser '${tool_name}' threw an exception`,
      agent_id: finding.agent_id, action_id, event_type: 'parse_output', category: 'finding',
      tool_name, frontier_item_id, frontier_type: frontierType, result_classification: 'failure',
      details: {
        parse_status: 'parser_exception', parse_outcome: 'parser_exception',
        parsed_nodes: 0, parsed_edges: 0, ingested: false, parser_context: durableParserContext, ...quality,
      },
    });
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

  const parserMarkedPartialNode = finding.nodes.some(node => node.partial === true);
  const effectivePartial = opts.partial || finding.partial === true || parserMarkedPartialNode;
  const effectivePartialReason = opts.partial_reason
    ?? finding.partial_reason
    ?? (parserMarkedPartialNode ? 'parser_marked_partial_node' : undefined);
  const findingQuality = {
    ...quality,
    partial: effectivePartial ? true as const : undefined,
    partial_reason: effectivePartial ? effectivePartialReason : undefined,
  };

  if (finding.nodes.length === 0 && finding.edges.length === 0) {
    const result: ParseIngestResult = {
      parsed: false, parse_status: 'no_data', parse_outcome: 'no_data', isError: true, tool: tool_name, action_id,
      finding_id: finding.id, nodes_parsed: 0, edges_parsed: 0, ingested: false,
      warnings: warnings.length > 0 ? warnings : undefined,
      ...findingQuality,
    };
    return finish(result, {
      description: `Output parsed for ${tool_name} but no graph data was extracted`,
      agent_id: finding.agent_id, action_id, event_type: 'parse_output', category: 'finding',
      tool_name, frontier_item_id, frontier_type: frontierType, linked_finding_ids: [finding.id],
      result_classification: 'failure',
      details: { parsed_nodes: 0, parsed_edges: 0, ingested: false, parse_status: 'no_data', parse_outcome: 'no_data', parser_context: durableParserContext, ...findingQuality },
    });
  }

  const prepared = prepareFindingForIngest(finding, nodeId => engine.getNode(nodeId));
  if (prepared.errors.length > 0) {
    const result: ParseIngestResult = {
      parsed: true, parse_status: 'validation_failed', parse_outcome: 'validation_failed', isError: true, tool: tool_name, action_id,
      finding_id: finding.id, nodes_parsed: finding.nodes.length, edges_parsed: finding.edges.length,
      ingested: false, validation_errors: prepared.errors, failure_stage: 'finding_validation',
      warnings: warnings.length > 0 ? warnings : undefined, ...findingQuality,
    };
    return finish(result, {
      description: `Output parse rejected for ${tool_name}: invalid graph mutation`,
      agent_id: finding.agent_id, action_id, event_type: 'parse_output', category: 'finding',
      tool_name, frontier_item_id, frontier_type: frontierType, linked_finding_ids: [finding.id],
      result_classification: 'failure',
      details: {
        parse_status: 'validation_failed', parse_outcome: 'validation_failed',
        failure_stage: 'finding_validation', validation_errors: prepared.errors, parser_context: durableParserContext, ...findingQuality,
      },
    });
  }

  type IngestCounts = {
    new_nodes: string[];
    new_edges: string[];
    inferred_edges: string[];
    campaign_id?: string;
  };
  const buildSuccessResult = (ingestResult?: IngestCounts): ParseIngestResult => ({
    parsed: true,
    parse_status: 'ok',
    parse_outcome: effectivePartial ? 'partial' : 'ok',
    isError: false,
    tool: tool_name,
    action_id,
    finding_id: finding.id,
    nodes_parsed: finding.nodes.length,
    edges_parsed: finding.edges.length,
    campaign_id: ingestResult?.campaign_id,
    ingested: ingestResult
      ? {
          new_nodes: ingestResult.new_nodes.length,
          new_edges: ingestResult.new_edges.length,
          inferred_edges: ingestResult.inferred_edges.length,
        }
      : undefined,
    warnings: warnings.length > 0 ? warnings : undefined,
    ...(finding.parser_details ? { parser_details: finding.parser_details } : {}),
    ...findingQuality,
  });
  const buildSuccessAudit = (
    ingestResult?: IngestCounts,
  ): Parameters<GraphEngine['logActionEvent']>[0] => ({
    description: ingest
      ? `Output parsed and ingested for ${tool_name}`
      : `Output parsed for ${tool_name} without ingest`,
    agent_id: finding.agent_id,
    action_id,
    event_type: 'parse_output',
    category: 'finding',
    tool_name,
    frontier_item_id,
    frontier_type: frontierType,
    linked_finding_ids: [finding.id],
    result_classification: effectivePartial ? 'partial' : ingest ? 'success' : 'neutral',
    details: {
      // `parse_status` predates partial outcomes; retain its successful `ok`
      // value and expose the richer classification through `parse_outcome`.
      parse_status: 'ok',
      parse_outcome: effectivePartial ? 'partial' : 'ok',
      parsed_nodes: finding.nodes.length,
      parsed_edges: finding.edges.length,
      ingested: ingest,
      new_nodes: ingestResult?.new_nodes.length ?? 0,
      new_edges: ingestResult?.new_edges.length ?? 0,
      inferred_edges: ingestResult?.inferred_edges.length ?? 0,
      parser_context: durableParserContext,
      ...findingQuality,
    },
  });

  if (ingest) {
    if (opts.command_completion) {
      let completedResult: ParseIngestResult | undefined;
      engine.ingestFinding(prepared.finding, {
        additional_state_keys: ['command_state'],
        complete: ingestResult => {
          completedResult = buildSuccessResult(ingestResult);
          opts.command_completion!(
            completedResult,
            () => engine.logActionEvent(buildSuccessAudit(ingestResult)),
          );
        },
      });
      if (!completedResult) {
        throw new Error('Finding ingest did not complete its application command.');
      }
      return completedResult;
    }
    const ingestResult = engine.ingestFinding(prepared.finding);
    return finish(
      buildSuccessResult(ingestResult),
      buildSuccessAudit(ingestResult),
    );
  }

  return finish(buildSuccessResult(), buildSuccessAudit());
}
