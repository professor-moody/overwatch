import { describe, expect, it } from 'vitest';
import { extractActivityTrustSignals, extractFindingTrustSignals, trustSignalsForNode } from '../trust-signals';
import type { FindingDto, TrustSignalDto } from '../api';
import type { ActivityEntry } from '../types';

function activity(partial: Partial<ActivityEntry>): ActivityEntry {
  return {
    id: 'evt-1',
    timestamp: '2026-05-15T10:00:00Z',
    event_type: 'parse_output',
    description: 'parsed output',
    ...partial,
  };
}

describe('dashboard trust signals', () => {
  it('flags parser events that extracted no graph data', () => {
    const signals = extractActivityTrustSignals(activity({
      result_classification: 'failure',
      details: { parse_status: 'no_data', parsed_nodes: 0, parsed_edges: 0, ingested: false },
    }));

    expect(signals.map(signal => signal.id)).toContain('parse-no-data');
    expect(signals.find(signal => signal.id === 'parse-no-data')?.severity).toBe('error');
  });

  it('flags ingest summaries with dropped records', () => {
    const signals = extractActivityTrustSignals(activity({
      event_type: 'parse_output',
      description: 'azurehound ingest',
      details: {
        ingest_summary: [{
          processed_records: 2,
          dropped_records: 1,
          dropped_by_reason: { 'azusers.missing_object_id': 1 },
        }],
      },
    }));

    expect(signals).toEqual(expect.arrayContaining([
      expect.objectContaining({
        severity: 'warning',
        label: 'Dropped records',
        detail: '1 dropped record: azusers.missing_object_id: 1',
      }),
    ]));
  });

  it('distinguishes path analysis failure from a completed no-path result', () => {
    expect(extractActivityTrustSignals(activity({
      event_type: 'find_paths',
      details: { analysis_status: 'analysis_failed' },
    }))).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: 'path-analysis-failed', severity: 'error' }),
    ]));

    expect(extractActivityTrustSignals(activity({
      event_type: 'find_paths',
      details: { analysis_status: 'no_path' },
    }))).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: 'path-no-path', severity: 'info' }),
    ]));
  });

  it('flags indeterminate IAM decisions and depth caps', () => {
    const signals = extractActivityTrustSignals(activity({
      event_type: 'validate_token_credential',
      details: { decision: 'indeterminate', depth_capped: true },
    }));

    expect(signals.map(signal => signal.id)).toEqual(expect.arrayContaining([
      'iam-indeterminate',
      'iam-depth-capped',
    ]));
  });

  it('flags truncated output and partial parse summaries', () => {
    const signals = extractActivityTrustSignals(activity({
      event_type: 'action_completed',
      details: {
        stdout_truncated: true,
        parse_summary: { partial: true, partial_reason: 'bounded_buffer_only' },
      },
    }));

    expect(signals).toEqual(expect.arrayContaining([
      expect.objectContaining({
        id: 'output-truncated',
        severity: 'warning',
        label: 'Output truncated',
      }),
    ]));
  });

  it('marks estimated finding CVSS as advisory', () => {
    const finding: FindingDto = {
      id: 'finding-1',
      title: 'Credential can reach service',
      severity: 'high',
      category: 'credential',
      description: 'Estimated scoring from graph edges',
      affected_assets: ['svc-1'],
      remediation: 'Rotate credential',
      risk_score: 8,
      cvss_score: 7.5,
      cvss_vector: 'CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N',
      cvss_estimated: true,
    };

    expect(extractFindingTrustSignals(finding)).toEqual([
      expect.objectContaining({
        id: 'cvss-estimated',
        severity: 'info',
        label: 'Estimated CVSS',
      }),
    ]);
  });

  it('filters backend trust signals for graph inspector nodes', () => {
    const signals: TrustSignalDto[] = [
      { id: 'node', source: 'activity', severity: 'warning', label: 'Dropped records', node_ids: ['host-1'] },
      { id: 'finding', source: 'finding', severity: 'info', label: 'Estimated CVSS', finding_id: 'finding-1' },
      { id: 'other', source: 'activity', severity: 'error', label: 'No parser data', node_ids: ['host-2'] },
    ];

    expect(trustSignalsForNode(signals, 'host-1', ['finding-1']).map(signal => signal.id)).toEqual(['node', 'finding']);
  });
});
