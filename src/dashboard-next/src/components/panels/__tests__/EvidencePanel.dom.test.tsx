import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { EvidencePanel } from '../EvidencePanel';
import * as api from '../../../lib/api';

vi.mock('../../../lib/api', () => ({
  getEvidenceChains: vi.fn(),
  getFindings: vi.fn(),
}));

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(next => { resolve = next; });
  return { promise, resolve };
}

function NextEvidence() {
  const navigate = useNavigate();
  return <button onClick={() => navigate('/evidence?node=node-b')}>Open B</button>;
}

function response(nodeId: string) {
  return {
    node_id: nodeId,
    node_props: { type: 'host', label: nodeId === 'node-a' ? 'Node A' : 'Node B' },
    chains: [],
    count: 0,
  } as never;
}

describe('EvidencePanel deep-link request ordering', () => {
  it('does not let an older node request overwrite a newer deep link', async () => {
    const first = deferred<never>();
    const second = deferred<never>();
    vi.mocked(api.getFindings).mockResolvedValue({ findings: [] } as never);
    vi.mocked(api.getEvidenceChains).mockImplementation((nodeId: string) => (
      nodeId === 'node-a' ? first.promise : second.promise
    ));

    render(
      <MemoryRouter initialEntries={['/evidence?node=node-a']}>
        <NextEvidence />
        <Routes>
          <Route path="/evidence" element={<EvidencePanel />} />
        </Routes>
      </MemoryRouter>,
    );
    await userEvent.click(screen.getByRole('button', { name: 'Open B' }));
    await act(async () => {
      second.resolve(response('node-b'));
      await second.promise;
    });
    expect((await screen.findAllByText('Node B')).length).toBeGreaterThan(0);
    await act(async () => {
      first.resolve(response('node-a'));
      await first.promise;
    });
    await waitFor(() => {
      expect(screen.getAllByText('Node B').length).toBeGreaterThan(0);
      expect(screen.queryAllByText('Node A')).toHaveLength(0);
    });
  });
});
