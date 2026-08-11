import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';
import { EvidenceNarrative } from '../EvidenceNarrative';
import type { EvidenceNarrativeItem } from '../../../lib/evidence-narrative';

function item(overrides: Partial<EvidenceNarrativeItem> = {}): EvidenceNarrativeItem {
  return {
    id: 'host-1', node_id: 'host-1', label: 'DC01', count: 2,
    proof: 'Pwn3d!', source_kind: 'command_output', ...overrides,
  };
}

function renderNarrative(items: EvidenceNarrativeItem[]) {
  render(<MemoryRouter><EvidenceNarrative items={items} /></MemoryRouter>);
}

describe('EvidenceNarrative — surfaces how it was found', () => {
  it('renders the exact command and the acting agent', () => {
    renderNarrative([item({ command: 'nxc smb 10.10.10.10', agent_id: 'recon-agent', tool: 'nxc' })]);
    expect(screen.getByText('How it was found')).toBeTruthy();
    expect(screen.getByText(/nxc smb 10\.10\.10\.10/)).toBeTruthy();
    expect(screen.getByText(/agent recon-agent/)).toBeTruthy();
    expect(screen.getByText('nxc')).toBeTruthy();
  });

  it('omits the command block when a finding was derived without one (inferred/imported)', () => {
    renderNarrative([item({ command: undefined, source_kind: 'parsed_result' })]);
    expect(screen.queryByText('How it was found')).toBeNull();
    // The proof snippet still shows so the finding isn't evidence-less.
    expect(screen.getByText('Pwn3d!')).toBeTruthy();
  });

  it('renders the empty state when there is no evidence', () => {
    render(<MemoryRouter><EvidenceNarrative items={[]} /></MemoryRouter>);
    expect(screen.getByText(/No supporting evidence/i)).toBeTruthy();
  });
});
