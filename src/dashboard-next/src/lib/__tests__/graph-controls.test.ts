import { describe, expect, it, vi } from 'vitest';
import { createToolbarActionHandler } from '../../components/graph/GraphToolbar';
import { safeCameraDuration } from '../graph-camera';

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
});
