import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router';
import { describe, expect, it } from 'vitest';
import {
  WorkspaceInspectorRegistry,
  resolveInspectorTab,
  type WorkspaceInspectorAdapters,
} from '../WorkspaceInspectorRegistry';

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{location.pathname}{location.search}</output>;
}

function renderRegistry(path: string, adapters: WorkspaceInspectorAdapters) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="*" element={<><WorkspaceInspectorRegistry adapters={adapters} /><LocationProbe /></>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('WorkspaceInspectorRegistry', () => {
  it('selects the default supported tab and detects invalid requested tabs', () => {
    const adapter = { tabs: [{ value: 'summary', label: 'Summary' }, { value: 'proof', label: 'Proof' }], defaultTab: 'summary' };
    expect(resolveInspectorTab(null, adapter)).toEqual({ tab: 'summary', invalidRequestedTab: false });
    expect(resolveInspectorTab('proof', adapter)).toEqual({ tab: 'proof', invalidRequestedTab: false });
    expect(resolveInspectorTab('secrets', adapter)).toEqual({ tab: 'summary', invalidRequestedTab: true });
  });

  it('canonicalizes an unsupported tab without disturbing filters or drawer state', async () => {
    renderRegistry('/review?view=readiness&kind=finding&item=f-1&tab=secrets&readiness=draft&drawer=run&drawerItem=act-1', {
      finding: {
        tabs: [{ value: 'summary', label: 'Summary' }, { value: 'proof', label: 'Proof' }],
        defaultTab: 'summary',
        render: ({ tab, setTab }) => <button type="button" onClick={() => setTab('proof')}>Tab {tab}</button>,
      },
    });

    await waitFor(() => expect(screen.getByTestId('location').textContent).toBe('/review?view=readiness&kind=finding&item=f-1&readiness=draft&drawer=run&drawerItem=act-1'));
    fireEvent.click(screen.getByRole('button', { name: 'Tab summary' }));
    await waitFor(() => expect(screen.getByTestId('location').textContent).toContain('tab=proof'));
  });

  it('recovers a deleted registered selection while preserving the surrounding workspace and drawer', async () => {
    renderRegistry('/operate?view=active&kind=agent&item=gone&drawer=activity&drawerItem=evt-1', {
      agent: { resolved: true, available: false, render: () => null },
    });

    await waitFor(() => expect(screen.getByTestId('location').textContent).toBe('/operate?view=active&drawer=activity&drawerItem=evt-1'));
  });

  it('leaves selections owned by another workflow untouched', async () => {
    renderRegistry('/operate?view=active&kind=node&item=host-1&drawer=activity', {});
    await waitFor(() => expect(screen.getByTestId('location').textContent).toBe('/operate?view=active&kind=node&item=host-1&drawer=activity'));
  });
});
