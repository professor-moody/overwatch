import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Graph from 'graphology';
import { NodeDetailDrawer } from '../NodeDetailDrawer';
import { POLL } from '../../../lib/polling';
import * as api from '../../../lib/api';

// Mutable WS state so a single mock can serve both the connected and disconnected cases.
const { wsState } = vi.hoisted(() => ({ wsState: { connected: true } }));
vi.mock('../../../providers/ws-provider', () => ({ useWs: () => wsState }));
vi.mock('../../../lib/api', () => ({
  getFindings: vi.fn(),
  getTrustSignals: vi.fn(),
  getEvidenceChains: vi.fn(),
  evidenceImageUrl: vi.fn(() => ''),
  dispatchAgent: vi.fn(),
}));

function graphWithNode() {
  const g = new Graph();
  g.addNode('node-1', { nodeType: 'host', _props: { ip: '10.0.0.1' }, label: 'host-1' });
  return g;
}

describe('NodeDetailDrawer - silent auto-refresh of the open node', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    wsState.connected = true;
    vi.mocked(api.getFindings).mockResolvedValue({ findings: [] } as never);
    vi.mocked(api.getTrustSignals).mockResolvedValue({ signals: [] } as never);
    vi.mocked(api.getEvidenceChains).mockResolvedValue({ node_id: 'node-1', chains: [], count: 0 } as never);
  });
  afterEach(() => {
    vi.clearAllMocks();
    vi.useRealTimers();
  });

  function renderDrawer() {
    render(
      <MemoryRouter>
        <NodeDetailDrawer graph={graphWithNode()} nodeId="node-1" onClose={() => {}} />
      </MemoryRouter>,
    );
  }

  it('re-fetches the open node on the poll interval while connected - no re-open needed', async () => {
    renderDrawer();
    await vi.advanceTimersByTimeAsync(0); // flush the initial mount fetch
    expect(api.getEvidenceChains).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(POLL.NODE_DRAWER_MS);
    expect(api.getEvidenceChains).toHaveBeenCalledTimes(2); // the silent refetch fired
    expect(api.getTrustSignals).toHaveBeenCalledTimes(2);
  });

  it('does not poll while disconnected (gated on the WS connected flag)', async () => {
    wsState.connected = false;
    renderDrawer();
    await vi.advanceTimersByTimeAsync(0);
    expect(api.getEvidenceChains).toHaveBeenCalledTimes(1); // initial mount fetch only
    await vi.advanceTimersByTimeAsync(POLL.NODE_DRAWER_MS * 2);
    expect(api.getEvidenceChains).toHaveBeenCalledTimes(1); // no background refetch
  });
});
