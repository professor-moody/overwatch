import type { FindingDto } from './api';
import type { ActivityEntry } from './types';

export type TrustSignalSeverity = 'error' | 'warning' | 'info';

export interface TrustSignal {
  id: string;
  severity: TrustSignalSeverity;
  label: string;
  detail?: string;
  action?: string;
}

export function extractActivityTrustSignals(entry: ActivityEntry): TrustSignal[] {
  const details = asRecord(entry.details) ?? {};
  const parseSummary = asRecord(details.parse_summary);
  const signals: TrustSignal[] = [];

  const parseStatus = stringValue(details.parse_status) || stringValue(parseSummary?.parse_status);
  const parsedNodes = numberValue(details.parsed_nodes) ?? numberValue(parseSummary?.nodes_parsed);
  const parsedEdges = numberValue(details.parsed_edges) ?? numberValue(parseSummary?.edges_parsed);
  const isParseEvent = entry.event_type === 'parse_output';

  if (parseStatus === 'no_data' || (isParseEvent && parsedNodes === 0 && parsedEdges === 0)) {
    addSignal(signals, {
      id: 'parse-no-data',
      severity: 'error',
      label: 'No parser data',
      detail: 'The parser ran but extracted zero graph nodes or edges.',
      action: 'Verify the source output before treating this as no finding.',
    });
  } else if (parseStatus === 'validation_failed' || (isParseEvent && Array.isArray(details.validation_errors))) {
    addSignal(signals, {
      id: 'parse-validation-failed',
      severity: 'error',
      label: 'Parse rejected',
      detail: 'Parsed data failed graph validation and was not ingested.',
      action: 'Inspect validation errors and parser format assumptions.',
    });
  } else if (isParseEvent && entry.result_classification === 'failure') {
    addSignal(signals, {
      id: 'parse-failed',
      severity: 'error',
      label: 'Parser failed',
      detail: 'The parse event failed; downstream graph state may be incomplete.',
    });
  }

  for (const summary of [
    ...ingestSummaries(details.ingest_summary),
    ...ingestSummaries(details.ingest_summaries),
    ...ingestSummaries(parseSummary?.ingest_summary),
  ]) {
    const dropped = numberValue(summary.dropped_records) || 0;
    if (dropped > 0) {
      addSignal(signals, {
        id: `ingest-dropped-${signals.length}`,
        severity: 'warning',
        label: `${dropped} dropped record${dropped === 1 ? '' : 's'}`,
        detail: droppedReasonText(summary),
        action: 'Review ingest warnings before relying on absence of paths.',
      });
    }
  }

  const analysisStatus = stringValue(details.analysis_status);
  if (analysisStatus === 'analysis_failed') {
    addSignal(signals, {
      id: 'path-analysis-failed',
      severity: 'error',
      label: 'Path analysis failed',
      detail: 'The graph path routine errored; no-path output is not trustworthy for this query.',
    });
  } else if (analysisStatus === 'missing_endpoint') {
    addSignal(signals, {
      id: 'path-missing-endpoint',
      severity: 'warning',
      label: 'Path endpoint missing',
      detail: 'One or more requested path endpoints were not present in the current graph.',
    });
  } else if (analysisStatus === 'no_path') {
    addSignal(signals, {
      id: 'path-no-path',
      severity: 'info',
      label: 'No path found',
      detail: 'Path analysis completed and found no current route.',
    });
  }

  if (stringValue(details.decision) === 'indeterminate') {
    addSignal(signals, {
      id: 'iam-indeterminate',
      severity: 'warning',
      label: 'IAM indeterminate',
      detail: 'The permission simulator could not prove allowed or denied.',
      action: 'Verify with live API behavior or a richer policy source.',
    });
  }
  if (details.depth_capped === true) {
    addSignal(signals, {
      id: 'iam-depth-capped',
      severity: 'warning',
      label: 'Depth capped',
      detail: 'Assume-role analysis hit the configured depth limit.',
      action: 'Increase IAM assume depth if deeper chains matter here.',
    });
  }

  for (const warning of [...stringArray(details.warnings), ...stringArray(parseSummary?.warnings)].slice(0, 3)) {
    addSignal(signals, {
      id: `warning-${warning}`,
      severity: 'warning',
      label: 'Operator warning',
      detail: warning,
    });
  }

  return signals;
}

export function extractFindingTrustSignals(finding: FindingDto): TrustSignal[] {
  const signals: TrustSignal[] = [];
  if (finding.cvss_estimated) {
    addSignal(signals, {
      id: 'cvss-estimated',
      severity: 'info',
      label: 'Estimated CVSS',
      detail: finding.cvss_vector
        ? `Derived from current graph evidence: ${finding.cvss_vector}`
        : 'Derived from current graph evidence; verify before client reporting.',
      action: 'Treat severity as advisory until corroborated.',
    });
  }
  return signals;
}

function addSignal(signals: TrustSignal[], signal: TrustSignal): void {
  if (!signals.some(existing => existing.id === signal.id)) {
    signals.push(signal);
  }
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
