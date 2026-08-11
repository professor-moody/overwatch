import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { FindingsPanel } from '../FindingsPanel';
import { useEngagementStore } from '../../../stores/engagement-store';
import { POLL } from '../../../lib/polling';
import * as api from '../../../lib/api';

// Partial mock: keep the real api module, override only the two the poll drives.
vi.mock('../../../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../lib/api')>()),
  getFindings: vi.fn(),
  listReports: vi.fn(),
}));

describe('FindingsPanel — poll gated on the WS connected flag', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.mocked(api.getFindings).mockResolvedValue({ findings: [] } as never);
    vi.mocked(api.listReports).mockResolvedValue({ reports: [] } as never);
    useEngagementStore.setState({ connected: true });
  });
  afterEach(() => {
    vi.clearAllMocks();
    vi.useRealTimers();
    useEngagementStore.setState({ connected: false });
  });

  function renderPanel() {
    render(<MemoryRouter><FindingsPanel /></MemoryRouter>);
  }

  it('re-polls findings on the interval while connected', async () => {
    renderPanel();
    await vi.advanceTimersByTimeAsync(0); // flush the initial mount load
    const initial = vi.mocked(api.getFindings).mock.calls.length;
    await vi.advanceTimersByTimeAsync(POLL.FINDINGS_MS);
    expect(vi.mocked(api.getFindings).mock.calls.length).toBeGreaterThan(initial);
  });

  it('stops polling while disconnected (no API hammering on a dropped socket)', async () => {
    useEngagementStore.setState({ connected: false });
    renderPanel();
    await vi.advanceTimersByTimeAsync(0);
    const initial = vi.mocked(api.getFindings).mock.calls.length; // initial mount load only
    await vi.advanceTimersByTimeAsync(POLL.FINDINGS_MS * 2);
    expect(vi.mocked(api.getFindings).mock.calls.length).toBe(initial);
  });
});
