import type { ActivityLogEntry } from './engine-context.js';
import type { ReportFinding } from './report-generator.js';

export type TrustSignalSeverity = 'error' | 'warning' | 'info';
export type TrustSignalSource = 'activity' | 'finding';

export interface TrustSignalDto {
  id: string;
  severity: TrustSignalSeverity;
  label: string;
  detail?: string;
  action?: string;
  timestamp?: string;
  source: TrustSignalSource;
  source_event?: {
    event_id?: string;
    event_type?: string;
    description?: string;
  };
  action_id?: string;
  frontier_item_id?: string;
  finding_id?: string;
  node_ids?: string[];
}

export interface TrustSignalsResponse {
  generated_at: string;
  total: number;
  counts: Record<TrustSignalSeverity, number>;
  signals: TrustSignalDto[];
}

export function buildTrustSignalsResponse(input: {
  history: ActivityLogEntry[];
  findings: ReportFinding[];
  generatedAt?: string;
  resolveAssetToNode?: (asset: string) => string | null;
  limit?: number;
  nodeId?: string;
  findingId?: string;
  severity?: TrustSignalSeverity;
}): TrustSignalsResponse {
  const generatedAt = input.generatedAt ?? new Date().toISOString();
  const signals = [
    ...input.history.flatMap(entry => extractActivityTrustSignals(entry)),
    ...input.findings.flatMap(finding => extractFindingTrustSignals(finding, generatedAt, input.resolveAssetToNode)),
  ]
    .filter(signal => !input.nodeId || signal.node_ids?.includes(input.nodeId))
    .filter(signal => !input.findingId || signal.finding_id === input.findingId)
    .filter(signal => !input.severity || signal.severity === input.severity)
    .sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || '') || severityRank(a.severity) - severityRank(b.severity));

  const limited = typeof input.limit === 'number' && input.limit > 0 ? signals.slice(0, input.limit) : signals;
  return {
    generated_at: generatedAt,
    total: limited.length,
    counts: {
      error: limited.filter(signal => signal.severity === 'error').length,
      warning: limited.filter(signal => signal.severity === 'warning').length,
      info: limited.filter(signal => signal.severity === 'info').length,
    },
    signals: limited,
  };
}

export function extractActivityTrustSignals(entry: ActivityLogEntry): TrustSignalDto[] {
  const details = asRecord(entry.details) ?? {};
  const parseSummary = asRecord(details.parse_summary);
  const signals: TrustSignalDto[] = [];
  const nodeIds = extractNodeIds(entry, details);

  const parseStatus = stringValue(details.parse_status) || stringValue(parseSummary?.parse_status);
  const parsedNodes = numberValue(details.parsed_nodes) ?? numberValue(parseSummary?.nodes_parsed);
  const parsedEdges = numberValue(details.parsed_edges) ?? numberValue(parseSummary?.edges_parsed);
  const isParseEvent = entry.event_type === 'parse_output';

  if (parseStatus === 'validation_failed' || (isParseEvent && Array.isArray(details.validation_errors))) {
    addActivitySignal(signals, entry, {
      key: 'parse-validation-failed',
      severity: 'error',
      label: 'Parse rejected',
      detail: 'Parsed data or parser context failed validation and was not ingested.',
      action: 'Inspect validation errors and parser format assumptions.',
      nodeIds,
    });
  } else if (parseStatus === 'no_parser') {
    addActivitySignal(signals, entry, {
      key: 'parse-no-parser',
      severity: 'error',
      label: 'Parser unavailable',
      detail: 'No registered parser matched the requested parser name.',
      action: 'Choose a supported parser or ingest the structured result explicitly.',
      nodeIds,
    });
  } else if (parseStatus === 'parser_exception') {
    addActivitySignal(signals, entry, {
      key: 'parse-exception',
      severity: 'error',
      label: 'Parser exception',
      detail: 'The selected parser threw before it could produce graph data.',
      action: 'Inspect the parser error and source format before retrying.',
      nodeIds,
    });
  } else if (parseStatus === 'no_data' || (isParseEvent && !parseStatus && parsedNodes === 0 && parsedEdges === 0)) {
    addActivitySignal(signals, entry, {
      key: 'parse-no-data',
      severity: 'error',
      label: 'No parser data',
      detail: 'The parser ran but extracted zero graph nodes or edges.',
      action: 'Verify the source output before treating this as no finding.',
      nodeIds,
    });
  } else if (isParseEvent && entry.result_classification === 'failure') {
    addActivitySignal(signals, entry, {
      key: 'parse-failed',
      severity: 'error',
      label: 'Parser failed',
      detail: 'The parse event failed; downstream graph state may be incomplete.',
      nodeIds,
    });
  }

  for (const summary of [
    ...ingestSummaries(details.ingest_summary),
    ...ingestSummaries(details.ingest_summaries),
    ...ingestSummaries(parseSummary?.ingest_summary),
  ]) {
    const dropped = numberValue(summary.dropped_records) || 0;
    if (dropped > 0) {
      addActivitySignal(signals, entry, {
        key: `ingest-dropped-${signals.length}`,
        severity: 'warning',
        label: 'Dropped records',
        detail: [`${dropped} dropped record${dropped === 1 ? '' : 's'}`, droppedReasonText(summary)].filter(Boolean).join(': '),
        action: 'Review ingest warnings before relying on absence of paths.',
        nodeIds,
      });
    }
  }

  const analysisStatus = stringValue(details.analysis_status);
  if (analysisStatus === 'analysis_failed') {
    addActivitySignal(signals, entry, {
      key: 'path-analysis-failed',
      severity: 'error',
      label: 'Path analysis failed',
      detail: 'The graph path routine errored; no-path output is not trustworthy for this query.',
      nodeIds,
    });
  } else if (analysisStatus === 'missing_endpoint') {
    addActivitySignal(signals, entry, {
      key: 'path-missing-endpoint',
      severity: 'warning',
      label: 'Endpoint missing',
      detail: 'One or more requested path endpoints were not present in the current graph.',
      nodeIds,
    });
  } else if (analysisStatus === 'no_path') {
    addActivitySignal(signals, entry, {
      key: 'path-no-path',
      severity: 'info',
      label: 'No path found',
      detail: 'Path analysis completed and found no current route.',
      nodeIds,
    });
  }

  if (stringValue(details.decision) === 'indeterminate') {
    addActivitySignal(signals, entry, {
      key: 'iam-indeterminate',
      severity: 'warning',
      label: 'IAM indeterminate',
      detail: 'The permission simulator could not prove allowed or denied.',
      action: 'Verify with live API behavior or a richer policy source.',
      nodeIds,
    });
  }
  if (details.depth_capped === true) {
    addActivitySignal(signals, entry, {
      key: 'iam-depth-capped',
      severity: 'warning',
      label: 'Depth capped',
      detail: 'Assume-role analysis hit the configured depth limit.',
      action: 'Increase IAM assume depth if deeper chains matter here.',
      nodeIds,
    });
  }

  const truncated = details.stdout_truncated === true
    || details.stderr_truncated === true
    || numberValue(details.stdout_dropped_bytes) !== undefined
    || numberValue(details.stderr_dropped_bytes) !== undefined
    || details.partial === true
    || parseSummary?.partial === true;
  if (truncated) {
    addActivitySignal(signals, entry, {
      key: 'output-truncated',
      severity: 'warning',
      label: 'Output truncated',
      detail: stringValue(details.partial_reason) || stringValue(parseSummary?.partial_reason) || 'Captured output or parsed evidence was incomplete.',
      action: 'Open the full evidence artifact before relying on parsed coverage.',
      nodeIds,
    });
  }

  for (const warning of [...stringArray(details.warnings), ...stringArray(parseSummary?.warnings)].slice(0, 3)) {
    addActivitySignal(signals, entry, {
      key: `warning-${warning}`,
      severity: 'warning',
      label: 'Operator warning',
      detail: warning,
      nodeIds,
    });
  }

  return signals;
}

export function extractFindingTrustSignals(
  finding: ReportFinding,
  generatedAt: string,
  resolveAssetToNode?: (asset: string) => string | null,
): TrustSignalDto[] {
  if (!finding.cvss_estimated) return [];
  const nodeIds = resolveAssetToNode
    ? finding.affected_assets.map(resolveAssetToNode).filter((id): id is string => !!id)
    : [];
  return [{
    id: `${finding.id}:cvss-estimated`,
    severity: 'info',
    label: 'Estimated CVSS',
    detail: finding.cvss_vector
      ? `Derived from current graph evidence: ${finding.cvss_vector}`
      : 'Derived from current graph evidence; verify before client reporting.',
    action: 'Treat severity as advisory until corroborated.',
    timestamp: generatedAt,
    source: 'finding',
    finding_id: finding.id,
    node_ids: unique(nodeIds),
  }];
}

function addActivitySignal(
  signals: TrustSignalDto[],
  entry: ActivityLogEntry,
  signal: {
    key: string;
    severity: TrustSignalSeverity;
    label: string;
    detail?: string;
    action?: string;
    nodeIds: string[];
  },
): void {
  const id = `${entry.event_id || entry.action_id || entry.timestamp}:${signal.key}`;
  if (signals.some(existing => existing.id === id)) return;
  signals.push({
    id,
    severity: signal.severity,
    label: signal.label,
    detail: signal.detail,
    action: signal.action,
    timestamp: entry.timestamp,
    source: 'activity',
    source_event: {
      event_id: entry.event_id,
      event_type: entry.event_type,
      description: entry.description,
    },
    action_id: entry.action_id,
    frontier_item_id: entry.frontier_item_id,
    finding_id: entry.linked_finding_ids?.[0],
    node_ids: unique(signal.nodeIds),
  });
}

function extractNodeIds(entry: ActivityLogEntry, details: Record<string, unknown>): string[] {
  const nodeIds = new Set<string>();
  for (const value of [
    ...(entry.target_node_ids || []),
    details.node_id,
    details.target_node,
    details.source_node,
    details.edge_source,
    details.edge_target,
    details.credential_node,
    details.principal_node,
    details.from_node,
    details.to_node,
  ]) {
    if (typeof value === 'string' && value.trim()) nodeIds.add(value.trim());
  }
  return [...nodeIds];
}

function ingestSummaries(value: unknown): Record<string, unknown>[] {
  if (Array.isArray(value)) {
    return value.flatMap(item => {
      const record = asRecord(item);
      return record ? [record] : [];
    });
  }
  const record = asRecord(value);
  return record ? [record] : [];
}

function droppedReasonText(summary: Record<string, unknown>): string | undefined {
  const byReason = asRecord(summary.dropped_by_reason);
  if (!byReason) return undefined;
  const entries = Object.entries(byReason)
    .map(([reason, count]) => [reason, numberValue(count)] as const)
    .filter((entry): entry is readonly [string, number] => typeof entry[1] === 'number' && entry[1] > 0)
    .sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return undefined;
  return entries.slice(0, 3).map(([reason, count]) => `${reason}: ${count}`).join(', ');
}

function severityRank(severity: TrustSignalSeverity): number {
  if (severity === 'error') return 0;
  if (severity === 'warning') return 1;
  return 2;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === 'string' && item.trim().length > 0);
}

function numberValue(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}
