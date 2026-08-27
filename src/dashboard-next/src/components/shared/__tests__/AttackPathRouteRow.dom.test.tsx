import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { AttackPathRouteRow } from '../AttackPathRouteRow';
import { normalizeComputedAttackPath } from '../../../lib/attack-path-workspace';
import type { DisplayAttackPath } from '../../../lib/attack-path-workspace';
import type { ExportedNode } from '../../../lib/types';

function node(id: string, type: ExportedNode['type'], label = id): ExportedNode {
  return { id, type, label, confidence: 1, discovered_at: '2026-05-15T00:00:00Z' };
}

// A host that can reach a webapp (network -> app boundary) which is vulnerable to a CVE.
function samplePath(): DisplayAttackPath {
  const byId = new Map<string, ExportedNode>([
    ['ws01', node('ws01', 'host', 'WS01.corp.local')],
    ['portal', node('portal', 'webapp', 'Benefits Portal')],
    ['cve', node('cve', 'vulnerability', 'CVE-2024-1337')],
  ]);
  return normalizeComputedAttackPath({
    nodes: ['ws01', 'portal', 'cve'],
    edge_types: ['CAN_REACH', 'VULNERABLE_TO'],
    edge_ids: ['e1', 'e2'],
    total_confidence: 0.8,
    total_opsec_noise: 0.3,
  }, byId)!;
}

describe('AttackPathRouteRow - followable foothold->objective narrative', () => {
  it('renders each hop as an explained step, not a terse edge-type chip strip', () => {
    render(<AttackPathRouteRow path={samplePath()} onInspect={() => {}} />);

    // The starting point is anchored as the foothold.
    expect(screen.getByText('Foothold')).toBeTruthy();

    // Every hop reads as a verb phrase - never the raw SCREAMING_CASE edge type.
    expect(screen.getByText('can reach')).toBeTruthy();
    expect(screen.getByText('is vulnerable to')).toBeTruthy();
    expect(screen.queryByText('CAN_REACH')).toBeNull();
    expect(screen.queryByText('VULNERABLE_TO')).toBeNull();

    // The intermediate node reads by its human label.
    expect(screen.getByText('Benefits Portal')).toBeTruthy();

    // The final hop is marked as the objective, and the tier crossing is called out.
    expect(screen.getByText('objective')).toBeTruthy();
    expect(screen.getByText(/crosses into app/)).toBeTruthy();
  });

  it('opens the route in the graph when Inspect Path is clicked', () => {
    const onInspect = vi.fn();
    const path = samplePath();
    render(<AttackPathRouteRow path={path} onInspect={onInspect} />);

    screen.getByText('Inspect Path').click();
    expect(onInspect).toHaveBeenCalledTimes(1);
    expect(onInspect).toHaveBeenCalledWith(path);
  });
});
