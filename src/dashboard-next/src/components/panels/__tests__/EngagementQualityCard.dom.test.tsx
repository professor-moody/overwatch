import { render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EngagementQualityCard } from '../EngagementQualityCard';
import * as api from '../../../lib/api';

vi.mock('../../../lib/api', () => ({ getScorecard: vi.fn() }));

const SCORECARD = {
  verification: { by_state: {}, total: 10, verified: 6, unverified: 2, refuted: 1, stale: 1, verified_share: 0.75 },
  findings: { total: 5, proof_ready: 3, proof_ready_share: 0.6, unverified_cve_candidates: 0 },
  objectives: { total: 2, achieved: 2, currently_satisfied: 1, proof_ready: 1 },
  inventory: { total: 8, observed: 5, coverage: 0.625 },
  attack_paths: { total: 5, validated: 4, validation_share: 0.8 },
  unsupported_critical_claims: 2,
  contradicted_claims: 1,
  contradictions: [{ target_kind: 'edge', target_id: 'e1', target_ref: 'OWNS_CRED a→b', kind: 'refuted_but_evidence_positive', promoted_state: 'refuted', reason: 'looked wrong' }],
  refutation: { tested: 3, refuted: 1, coverage: 0.3 },
};

describe('EngagementQualityCard', () => {
  beforeEach(() => vi.mocked(api.getScorecard).mockResolvedValue(SCORECARD as never));
  afterEach(() => vi.clearAllMocks());

  it('renders the split quality dimensions from the live scorecard', async () => {
    render(<EngagementQualityCard />);
    await waitFor(() => expect(screen.getByText('75%')).toBeTruthy()); // verified share
    expect(screen.getByText('Attack path validated')).toBeTruthy();
    expect(screen.getByText('80%')).toBeTruthy(); // attack-path validation share
    expect(screen.getByText('Proof-ready findings')).toBeTruthy();
  });

  it('flags lapsed milestones (currently_satisfied below achieved)', async () => {
    render(<EngagementQualityCard />);
    // achieved 2, currently_satisfied 1 → 1 lapsed
    await waitFor(() => expect(screen.getByText(/1 lapsed — re-validate/)).toBeTruthy());
    expect(screen.getByText('1/2')).toBeTruthy(); // satisfied/total
  });

  it('surfaces an actionable contradiction with its reason', async () => {
    render(<EngagementQualityCard />);
    await waitFor(() => expect(screen.getByText(/OWNS_CRED a→b: promoted refuted/)).toBeTruthy());
    expect(screen.getByText(/looked wrong/)).toBeTruthy();
  });
});
