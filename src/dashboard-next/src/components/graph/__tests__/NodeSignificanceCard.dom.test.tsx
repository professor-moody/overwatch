import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { NodeSignificanceCard } from '../NodeSignificanceCard';

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
});
