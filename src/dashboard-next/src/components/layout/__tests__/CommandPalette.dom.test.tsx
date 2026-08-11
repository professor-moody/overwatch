import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { CommandPalette } from '../CommandPalette';
import type { PanelCommandDef } from '../../../lib/command-palette';
import type { AgentInfo } from '../../../lib/types';

const panels: PanelCommandDef[] = [
  { id: 'agents', label: 'Console', group: 'Console' },
  { path: '/graph', label: 'Graph', group: 'Investigate' },
  { id: 'findings', label: 'Findings', group: 'Investigate' },
];
const agents = [
  { id: 'task-1', agent_id: 'recon-agent', status: 'running' } as unknown as AgentInfo,
];

function renderPalette(overrides: Partial<React.ComponentProps<typeof CommandPalette>> = {}) {
  const onSelect = vi.fn();
  const onClose = vi.fn();
  render(<CommandPalette open panels={panels} agents={agents} onSelect={onSelect} onClose={onClose} {...overrides} />);
  return { onSelect, onClose };
}

describe('CommandPalette', () => {
  it('renders nothing when closed', () => {
    const { container } = render(
      <CommandPalette open={false} panels={panels} agents={agents} onSelect={() => {}} onClose={() => {}} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it('lists panels + agents and filters by query', () => {
    renderPalette();
    expect(screen.getByRole('option', { name: /Graph/i })).toBeTruthy();
    expect(screen.getByRole('option', { name: /recon-agent/i })).toBeTruthy();
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'graph' } });
    expect(screen.getByRole('option', { name: /Graph/i })).toBeTruthy();
    expect(screen.queryByRole('option', { name: /Findings/i })).toBeNull();
  });

  it('selects the highlighted item on Enter (keyboard flow) and closes', () => {
    const { onSelect, onClose } = renderPalette();
    const input = screen.getByRole('textbox');
    fireEvent.change(input, { target: { value: 'graph' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ label: 'Graph', path: '/graph' }));
    expect(onClose).toHaveBeenCalled();
  });

  it('ArrowDown moves the highlight before Enter', () => {
    const { onSelect } = renderPalette();
    const input = screen.getByRole('textbox');
    // No query → built order is [Console, Graph, Findings, recon-agent]; ArrowDown → Graph.
    fireEvent.keyDown(input, { key: 'ArrowDown' });
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ label: 'Graph' }));
  });

  it('clicking an agent selects it (jump straight to that agent) and closes', () => {
    const { onSelect, onClose } = renderPalette();
    fireEvent.click(screen.getByRole('option', { name: /recon-agent/i }));
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ taskId: 'task-1', kind: 'agent' }));
    expect(onClose).toHaveBeenCalled();
  });

  it('Escape closes', () => {
    const { onClose } = renderPalette();
    fireEvent.keyDown(screen.getByRole('textbox'), { key: 'Escape' });
    expect(onClose).toHaveBeenCalled();
  });
});
