import { describe, expect, it, vi } from 'vitest';
import { createToolbarActionHandler } from '../../components/graph/GraphToolbar';
import { computeGraphCameraFit, safeCameraDuration } from '../graph-camera';

describe('graph controls', () => {
  it('does not forward DOM events into toolbar actions', () => {
    const action = vi.fn();
    const handler = createToolbarActionHandler(action);

    handler({ type: 'click' } as never);

    expect(action).toHaveBeenCalledOnce();
    expect(action).toHaveBeenCalledWith();
  });

  it('guards camera animation duration against DOM events and invalid values', () => {
    expect(safeCameraDuration(125)).toBe(125);
    expect(safeCameraDuration({ type: 'click' })).toBe(300);
    expect(safeCameraDuration(Number.NaN)).toBe(300);
    expect(safeCameraDuration('300')).toBe(300);
    expect(safeCameraDuration(undefined, 200)).toBe(200);
  });

  it('computes a focused camera fit inside reserved dashboard chrome', () => {
    const fit = computeGraphCameraFit(
      [
        { x: 0.2, y: 0.2 },
        { x: 0.8, y: 0.6 },
      ],
      { width: 1200, height: 800 },
      {
        padding: { top: 96, right: 448, bottom: 152, left: 112 },
        minRatio: 0.05,
        maxRatio: 1.6,
      },
    );

    expect(fit).not.toBeNull();
    expect(fit?.ratio).toBeGreaterThanOrEqual(0.05);
    expect(fit?.ratio).toBeLessThanOrEqual(1.6);
    expect(fit?.x).toBeGreaterThan(0.5);
    expect(fit?.y).toBeGreaterThan(0.4);
  });

  it('handles single-node focused fits without producing an unusable zoom', () => {
    const fit = computeGraphCameraFit(
      [{ x: 0.42, y: 0.55 }],
      { width: 500, height: 300 },
      { minRatio: 0.08, maxRatio: 0.22 },
    );

    expect(fit).toEqual({ x: 0.42, y: 0.55, ratio: 0.08 });
  });
});
