import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ReportsList } from '../ReportsList';
import * as api from '../../../lib/api';

vi.mock('../../../lib/api', () => ({
  deleteReport: vi.fn(),
  reportOpenUrl: vi.fn(() => '/api/reports/report-1?disposition=inline'),
  reportDownloadUrl: vi.fn(() => '/api/reports/report-1'),
}));

vi.mock('../../../lib/dashboard-transport', () => ({
  downloadDashboardResource: vi.fn(),
  openDashboardResource: vi.fn(),
}));

const report = {
  id: '11111111-1111-4111-8111-111111111111',
  generated_at: '2026-07-17T00:00:00.000Z',
  format: 'markdown' as const,
  redaction_mode: 'operator' as const,
  filename: '11111111-1111-4111-8111-111111111111.md',
  size_bytes: 42,
  content_sha256: 'a'.repeat(64),
  options: {},
};

describe('ReportsList deletion durability', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('keeps an operator-visible warning when deletion durability or checkpointing is incomplete', async () => {
    vi.stubGlobal('confirm', vi.fn(() => true));
    vi.mocked(api.deleteReport).mockResolvedValue({
      deleted: true,
      cleanup_complete: false,
      commit_durability: 'uncertain',
      reference_persisted: false,
      warning: 'Synthetic recovery warning.',
    });
    const refresh = vi.fn();
    const { rerender } = render(<ReportsList reports={[report]} onRefresh={refresh} />);

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('filesystem durability was not confirmed');
    expect(alert).toHaveTextContent('durable state reference was not checkpointed');
    expect(alert).toHaveTextContent('archive cleanup remains pending');
    expect(alert).toHaveTextContent('Synthetic recovery warning');
    expect(refresh).toHaveBeenCalledTimes(1);

    // Parent refreshes the now-empty archive; the warning remains mounted.
    rerender(<ReportsList reports={[]} onRefresh={refresh} />);
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());
  });
});
