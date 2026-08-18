import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { describe, it, expect } from 'vitest';
import { Sidebar, NAV_GROUPS } from '../Sidebar';

describe('Sidebar', () => {
  it('scrolls its nav-items region (min-h-0 + overflow-y-auto) so a full destination list never pushes the collapse control off a short viewport', () => {
    render(
      <MemoryRouter>
        <Sidebar activePanel="agents" onPanelChange={() => {}} expanded onExpandedChange={() => {}} />
      </MemoryRouter>,
    );
    const nav = screen.getByRole('navigation');
    // The first child of <nav> is the scrollable items region; the collapse <button> is a pinned sibling.
    const itemsRegion = nav.querySelector('div');
    expect(itemsRegion?.className).toContain('min-h-0');       // lets the flex child shrink…
    expect(itemsRegion?.className).toContain('overflow-y-auto'); // …so it actually scrolls
    expect(itemsRegion?.className).toContain('flex-1');

    // The collapse control is OUTSIDE the scroll region, so it stays reachable at the bottom.
    const collapse = screen.getByRole('button', { name: /collapse/i });
    expect(itemsRegion?.contains(collapse)).toBe(false);
  });

  it('renders enough destinations to warrant scrolling', () => {
    const total = NAV_GROUPS.reduce((n, g) => n + g.items.length, 0);
    expect(total).toBeGreaterThanOrEqual(15);
  });
});
