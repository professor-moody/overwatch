import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ClaimStandingSection } from '../NodeDetailDrawer';
import * as api from '../../../lib/api';

// Only the two claim mutations are exercised here; other api exports are unused by this component.
vi.mock('../../../lib/api', () => ({
  promoteClaim: vi.fn(),
  withdrawClaim: vi.fn(),
}));

describe('ClaimStandingSection — operator claim correction', () => {
  beforeEach(() => {
    vi.mocked(api.promoteClaim).mockResolvedValue({ target_kind: 'node', target_id: 'n1', claim_state: 'refuted' } as never);
    vi.mocked(api.withdrawClaim).mockResolvedValue({ target_kind: 'node', target_id: 'n1', claim_state: 'observed', withdrew: 'refuted' } as never);
  });
  afterEach(() => vi.clearAllMocks());

  it('disables every action until a reason is entered (auditability)', () => {
    render(<ClaimStandingSection target={{ node_id: 'n1' }} />);
    const refute = screen.getByRole('button', { name: 'Refuted' }) as HTMLButtonElement;
    const withdraw = screen.getByRole('button', { name: 'Withdraw' }) as HTMLButtonElement;
    expect(refute.disabled).toBe(true);
    expect(withdraw.disabled).toBe(true);
    fireEvent.click(refute); // a disabled button must not fire
    expect(api.promoteClaim).not.toHaveBeenCalled();
  });

  it('promotes a NODE with the chosen state + typed reason', async () => {
    render(<ClaimStandingSection target={{ node_id: 'n1' }} />);
    fireEvent.change(screen.getByLabelText('Claim judgment reason'), { target: { value: 'tested, access denied' } });
    fireEvent.click(screen.getByRole('button', { name: 'Refuted' }));
    await waitFor(() => expect(api.promoteClaim).toHaveBeenCalledWith({ state: 'refuted', reason: 'tested, access denied', node_id: 'n1' }));
    expect(api.withdrawClaim).not.toHaveBeenCalled();
  });

  it('withdraws an EDGE claim, passing edge_id (the canonical access-edge case)', async () => {
    render(<ClaimStandingSection target={{ edge_id: 'user-a->cred-da:OWNS_CRED' }} />);
    fireEvent.change(screen.getByLabelText('Claim judgment reason'), { target: { value: 'reinstating' } });
    fireEvent.click(screen.getByRole('button', { name: 'Withdraw' }));
    await waitFor(() => expect(api.withdrawClaim).toHaveBeenCalledWith({ reason: 'reinstating', edge_id: 'user-a->cred-da:OWNS_CRED' }));
    expect(api.promoteClaim).not.toHaveBeenCalled();
  });
});
