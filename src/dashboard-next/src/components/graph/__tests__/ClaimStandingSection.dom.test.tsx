import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ClaimStandingSection } from '../NodeDetailDrawer';
import * as api from '../../../lib/api';

vi.mock('../../../lib/api', () => ({ getClaimImpact: vi.fn(), promoteClaim: vi.fn(), withdrawClaim: vi.fn() }));

const IMPACT_NO_PROMO = {
  target_kind: 'node', target_id: 'n1', claim_state: 'observed',
  promotion: null, history: [],
  supports_objectives: [{ id: 'obj-da', description: 'Domain Admin', achieved: true, currently_satisfied: true }],
};
const IMPACT_WITH_PROMO = {
  target_kind: 'edge', target_id: 'e1', claim_state: 'refuted',
  promotion: { state: 'refuted', by_kind: 'operator', at: '2026-08-18T00:00:00Z', reason: 'disproved it' },
  history: [
    { state: 'validated', by_kind: 'operator', at: '2026-08-17T00:00:00Z', reason: 'first verdict' },
    { state: 'refuted', by_kind: 'operator', at: '2026-08-18T00:00:00Z', reason: 'disproved it' },
  ],
  supports_objectives: [],
};

describe('ClaimStandingSection - claim judgment workflow', () => {
  beforeEach(() => {
    vi.mocked(api.getClaimImpact).mockResolvedValue(IMPACT_NO_PROMO as never);
    vi.mocked(api.promoteClaim).mockResolvedValue({ target_kind: 'node', target_id: 'n1', claim_state: 'refuted' } as never);
    vi.mocked(api.withdrawClaim).mockResolvedValue({ target_kind: 'edge', target_id: 'e1', claim_state: 'observed', withdrew: 'refuted' } as never);
  });
  afterEach(() => vi.clearAllMocks());

  it('shows the derived state + no-promotion note, and hides Withdraw when there is no active promotion', async () => {
    render(<ClaimStandingSection target={{ node_id: 'n1' }} />);
    await waitFor(() => expect(screen.getByText(/No explicit promotion/)).toBeTruthy());
    expect(api.getClaimImpact).toHaveBeenCalledWith({ node_id: 'n1' });
    expect(screen.getByText('observed')).toBeTruthy(); // derived-state pill
    expect(screen.queryByRole('button', { name: 'Withdraw' })).toBeNull();
  });

  it('applies the selected state + reason in one action (single Apply)', async () => {
    render(<ClaimStandingSection target={{ node_id: 'n1' }} />);
    await waitFor(() => expect(screen.getByText(/No explicit promotion/)).toBeTruthy());
    fireEvent.click(screen.getByRole('button', { name: 'Refuted' }));
    fireEvent.change(screen.getByLabelText('Claim judgment reason'), { target: { value: 'tested, access denied' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply refuted' }));
    await waitFor(() => expect(api.promoteClaim).toHaveBeenCalledWith({ state: 'refuted', reason: 'tested, access denied', node_id: 'n1' }));
  });

  it('previews the objective impact only for a negative verdict on a supporting element', async () => {
    render(<ClaimStandingSection target={{ node_id: 'n1' }} />);
    await waitFor(() => expect(screen.getByText(/No explicit promotion/)).toBeTruthy());
    // default 'validated' → no impact warning
    expect(screen.queryByText(/will revoke|will lapse/)).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Refuted' }));
    expect(screen.getByText(/will revoke/)).toBeTruthy();
    expect(screen.getByText(/Domain Admin/)).toBeTruthy();
  });

  it('shows the active promotion + collapsible history and offers Withdraw only then', async () => {
    vi.mocked(api.getClaimImpact).mockResolvedValue(IMPACT_WITH_PROMO as never);
    render(<ClaimStandingSection target={{ edge_id: 'e1' }} />);
    await waitFor(() => expect(screen.getByText(/disproved it/)).toBeTruthy()); // active promotion reason
    expect(api.getClaimImpact).toHaveBeenCalledWith({ edge_id: 'e1' });

    // History is collapsible.
    fireEvent.click(screen.getByRole('button', { name: /history \(2\)/ }));
    expect(screen.getByText(/first verdict/)).toBeTruthy();

    // Withdraw is available (a promotion exists) and requires a reason.
    fireEvent.change(screen.getByLabelText('Claim judgment reason'), { target: { value: 'reinstating' } });
    fireEvent.click(screen.getByRole('button', { name: 'Withdraw' }));
    await waitFor(() => expect(api.withdrawClaim).toHaveBeenCalledWith({ reason: 'reinstating', edge_id: 'e1' }));
  });
});
