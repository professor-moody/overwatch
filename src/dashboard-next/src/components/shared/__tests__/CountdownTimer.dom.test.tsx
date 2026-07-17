import { act, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CountdownTimer } from '../CountdownTimer';

describe('CountdownTimer DOM lifecycle', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-07-17T00:00:00.000Z'));
  });

  afterEach(() => vi.useRealTimers());

  it('expires an already elapsed target once without a timer initialization crash', () => {
    const onExpire = vi.fn();
    render(<CountdownTimer targetIso="2026-07-16T23:59:59.000Z" onExpire={onExpire} />);
    expect(screen.getByText('auto-approving…')).toBeInTheDocument();
    expect(onExpire).toHaveBeenCalledTimes(1);
    act(() => vi.advanceTimersByTime(5_000));
    expect(onExpire).toHaveBeenCalledTimes(1);
  });

  it('ticks into the urgent state and clears its interval on unmount', () => {
    const onExpire = vi.fn();
    const clear = vi.spyOn(globalThis, 'clearInterval');
    const rendered = render(
      <CountdownTimer targetIso="2026-07-17T00:00:31.000Z" onExpire={onExpire} />,
    );
    expect(screen.getByText('31s')).toBeInTheDocument();
    act(() => vi.advanceTimersByTime(2_000));
    expect(screen.getByText('29s')).toHaveClass('text-destructive');
    rendered.unmount();
    expect(clear).toHaveBeenCalled();
    expect(onExpire).not.toHaveBeenCalled();
  });
});
