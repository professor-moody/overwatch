import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EvidenceDebtCard } from '../EvidenceDebtCard';
import * as api from '../../../lib/api';

vi.mock('../../../lib/api', () => ({ getEvidenceDebt: vi.fn() }));

const navigateToGraph = vi.fn();
const navigateToFinding = vi.fn();
const navigateToEvidenceObjective = vi.fn();
vi.mock('../../../hooks/useNavigation', () => ({
  useNavigation: () => ({ navigateToGraph, navigateToFinding, navigateToEvidenceObjective }),
}));

const ITEMS = [
  { kind: 'contradiction', severity: 100, summary: 'OWNS_CRED u→cred: promoted refuted, but its evidence is positive', node_id: 'u', edge_id: 'e1' },
  { kind: 'lapsed_objective', severity: 90, summary: 'Objective "Domain Admin" was reached, but its supporting access has decayed', objective_id: 'obj-da' },
  { kind: 'unsupported_critical', severity: 85, summary: 'critical finding without captured proof: SMB signing disabled', finding_id: 'find-1' },
];

describe('EvidenceDebtCard', () => {
  beforeEach(() => {
    navigateToGraph.mockClear();
    navigateToFinding.mockClear();
    navigateToEvidenceObjective.mockClear();
    vi.mocked(api.getEvidenceDebt).mockResolvedValue({ items: ITEMS, total: ITEMS.length } as never);
  });
  afterEach(() => vi.clearAllMocks());

  it('renders the ranked debt items with their kind labels', async () => {
    render(<EvidenceDebtCard />);
    await waitFor(() => expect(screen.getByText(/promoted refuted/)).toBeTruthy());
    expect(screen.getByText('Contradiction')).toBeTruthy();
    expect(screen.getByText('Lapsed objective')).toBeTruthy();
    expect(screen.getByText('Unsupported')).toBeTruthy();
  });

  it('drills down to the right target per item kind', async () => {
    render(<EvidenceDebtCard />);
    await waitFor(() => expect(screen.getByText(/promoted refuted/)).toBeTruthy());

    fireEvent.click(screen.getByText(/promoted refuted/));       // contradiction → node graph
    expect(navigateToGraph).toHaveBeenCalledWith('u', 2);

    fireEvent.click(screen.getByText(/Domain Admin/));           // lapsed → objective evidence
    expect(navigateToEvidenceObjective).toHaveBeenCalledWith('obj-da');

    fireEvent.click(screen.getByText(/SMB signing disabled/));   // unsupported → finding
    expect(navigateToFinding).toHaveBeenCalledWith('find-1');
  });

  it('shows a clean state when there is no debt', async () => {
    vi.mocked(api.getEvidenceDebt).mockResolvedValue({ items: [], total: 0 } as never);
    render(<EvidenceDebtCard />);
    await waitFor(() => expect(screen.getByText(/No open evidence debt/)).toBeTruthy());
  });
});
