import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { NodeSignificanceCard } from '../NodeSignificanceCard';
import type { ExportedEdge, ExportedGraph, ExportedNode } from '../../../lib/types';

// A foothold host one hop from an objective (DC01) and two from a cloud identity.
function reachGraph(): ExportedGraph {
  const nodes: ExportedNode[] = [
    { id: 'ws01', type: 'host', label: 'WS01', confidence: 1, discovered_at: 'now' },
    { id: 'dc01', type: 'host', label: 'DC01', confidence: 1, discovered_at: 'now', objective_achieved: false },
    { id: 'role', type: 'cloud_identity', label: 'PowerUser', confidence: 1, discovered_at: 'now' },
  ];
  const edges: ExportedEdge[] = [
    { id: 'e1', source: 'ws01', target: 'dc01', type: 'CAN_REACH', confidence: 0.9 } as ExportedEdge,
    { id: 'e2', source: 'dc01', target: 'role', type: 'ADMIN_TO', confidence: 0.9 } as ExportedEdge,
  ];
  return { nodes, edges, coldInventory: [] };
}

describe('NodeSignificanceCard — why this node matters', () => {
  it('leads with the objective role, its description, and whether it is reached', () => {
    render(<NodeSignificanceCard nodeType="objective" props={{
      type: 'objective', objective_description: 'Compromise DC01', objective_achieved: false,
      source_trust: 'observed', confidence: 0.9, discovered_at: '2020-01-01T00:00:00Z',
    }} />);
    expect(screen.getByText('Objective')).toBeTruthy();
    expect(screen.getByText('Compromise DC01')).toBeTruthy();
    expect(screen.getByText('not yet reached')).toBeTruthy();
    expect(screen.getByText('observed')).toBeTruthy();          // source-trust badge
    expect(screen.getByText(/90% confidence/)).toBeTruthy();
  });

  it('marks an achieved objective as reached even on an ordinary node type', () => {
    render(<NodeSignificanceCard nodeType="host" props={{ objective_achieved: true }} />);
    expect(screen.getByText('reached')).toBeTruthy();
  });

  it('surfaces a high-value target with its reason', () => {
    render(<NodeSignificanceCard nodeType="group" props={{ hvt: true, hvt_reason: 'Domain Admins' }} />);
    expect(screen.getByText('High-value target')).toBeTruthy();
    expect(screen.getByText('Domain Admins')).toBeTruthy();
  });

  it('still orients a routine node by type, tier, and provenance', () => {
    render(<NodeSignificanceCard nodeType="host" props={{ confidence: 0.75, discovered_by: 'scanner' }} />);
    expect(screen.getByText('Host')).toBeTruthy();
    expect(screen.getByText('network tier')).toBeTruthy();
    expect(screen.getByText(/75% confidence · by scanner/)).toBeTruthy();
  });

  it('shows how many hops the node sits from the nearest objective', () => {
    render(<NodeSignificanceCard nodeType="host" nodeId="ws01" graph={reachGraph()} props={{}} />);
    expect(screen.getByText(/1 hop to nearest objective/)).toBeTruthy();
    expect(screen.getByText('DC01')).toBeTruthy();          // the nearest target's label
    expect(screen.getByText(/reaches 2 in all/)).toBeTruthy(); // dc01 + role
  });

  it('does not show a path-to-objective line for a node that is itself the objective', () => {
    render(<NodeSignificanceCard nodeType="host" nodeId="dc01" graph={reachGraph()}
      props={{ objective_achieved: true, objective_description: 'Own DC01' }} />);
    expect(screen.getByText('Objective')).toBeTruthy();
    expect(screen.queryByText(/hop.* to nearest objective/)).toBeNull();
  });
});
