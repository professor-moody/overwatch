import { describe, expect, it } from 'vitest';
import { buildTrustSignalsResponse, extractActivityTrustSignals } from '../trust-signal-summary.js';
import type { ActivityLogEntry } from '../engine-context.js';
import type { ReportFinding } from '../report-generator.js';

function event(partial: Partial<ActivityLogEntry>): ActivityLogEntry {
  return {
    event_id: partial.event_id || 'evt-1',
    timestamp: partial.timestamp || '2026-05-15T10:00:00Z',
    description: partial.description || 'activity',
    event_type: partial.event_type || 'parse_output',
    ...partial,
  };
}

describe('trust signal summary', () => {
  it('extracts parser, ingest, path, IAM, and truncation diagnostics from activity', () => {
    const signals = [
      ...extractActivityTrustSignals(event({ details: { parse_status: 'no_data', parsed_nodes: 0, parsed_edges: 0 } })),
      ...extractActivityTrustSignals(event({ event_id: 'evt-2', details: { ingest_summary: { dropped_records: 2, dropped_by_reason: { missing_id: 2 } } } })),
      ...extractActivityTrustSignals(event({ event_id: 'evt-3', details: { analysis_status: 'analysis_failed' } })),
      ...extractActivityTrustSignals(event({ event_id: 'evt-4', details: { decision: 'indeterminate', depth_capped: true } })),
      ...extractActivityTrustSignals(event({ event_id: 'evt-5', details: { stdout_truncated: true } })),
    ];

    expect(signals.map(signal => signal.label)).toEqual(expect.arrayContaining([
      'No parser data',
      'Dropped records',
      'Path analysis failed',
      'IAM indeterminate',
      'Depth capped',
      'Output truncated',
    ]));
  });

  it('builds filtered counts and links estimated CVSS findings to graph nodes', () => {
    const finding: ReportFinding = {
      id: 'finding-1',
      title: 'Estimated credential path',
      severity: 'high',
      category: 'credential',
      description: 'estimated',
      affected_assets: ['WS01'],
      evidence: [],
      remediation: 'Rotate credential',
      risk_score: 8,
      cvss_score: 7.2,
      cvss_vector: 'CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N',
      cvss_estimated: true,
    };

    const response = buildTrustSignalsResponse({
      history: [event({ details: { analysis_status: 'missing_endpoint' }, target_node_ids: ['host-1'] })],
      findings: [finding],
      generatedAt: '2026-05-15T11:00:00Z',
      resolveAssetToNode: asset => asset === 'WS01' ? 'host-1' : null,
      nodeId: 'host-1',
    });

    expect(response.total).toBe(2);
    expect(response.counts.warning).toBe(1);
    expect(response.counts.info).toBe(1);
    expect(response.signals.map(signal => signal.label)).toEqual(expect.arrayContaining(['Endpoint missing', 'Estimated CVSS']));
  });
});
