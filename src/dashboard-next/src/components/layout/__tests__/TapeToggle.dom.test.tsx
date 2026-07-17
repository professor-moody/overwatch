import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { getTapeStatus } from '../../../lib/api';
import { TapeToggle } from '../TapeToggle';

vi.mock('../../../lib/api', () => ({
  getTapeStatus: vi.fn(),
  toggleTape: vi.fn(),
}));

describe('TapeToggle operator status', () => {
  afterEach(() => vi.clearAllMocks());

  it('renders writer failure and dropped frames instead of an ordinary off state', async () => {
    vi.mocked(getTapeStatus).mockResolvedValue({
      enabled: false,
      path: '/tmp/failed-tape.jsonl',
      frame_count: 8,
      accepted_frame_count: 10,
      dropped_frame_count: 2,
      error: 'ENOSPC: no space left',
    });

    render(<TapeToggle />);
    const button = await screen.findByRole('button', { name: /Tape error · 2 dropped/i });
    expect(button).toHaveAttribute('title', expect.stringContaining('ENOSPC'));
    expect(button).toHaveClass('text-warning');
  });

  it('surfaces dropped frames even when no frame was committed and no writer error was retained', async () => {
    vi.mocked(getTapeStatus).mockResolvedValue({
      enabled: false,
      frame_count: 0,
      accepted_frame_count: 3,
      dropped_frame_count: 3,
    });

    render(<TapeToggle />);
    const button = await screen.findByRole('button', { name: /Tape · 3 dropped/i });
    expect(button).toHaveAttribute('title', expect.stringContaining('0 written, 3 dropped'));
  });

  it('surfaces live-session drops in both the pill and tooltip', async () => {
    vi.mocked(getTapeStatus).mockResolvedValue({
      enabled: true,
      path: '/tmp/live-tape.jsonl',
      frame_count: 4,
      accepted_frame_count: 6,
      dropped_frame_count: 2,
      started_by: 'dashboard',
    });

    render(<TapeToggle />);
    const button = await screen.findByRole('button', { name: /Tape dashboard ● 4 · 2 dropped/i });
    expect(button).toHaveAttribute('title', expect.stringContaining('4 written, 2 dropped'));
  });
});
