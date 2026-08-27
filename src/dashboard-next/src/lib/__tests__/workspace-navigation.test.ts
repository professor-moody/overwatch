import { describe, expect, it } from 'vitest';
import {
  clearSelectionParams,
  drawerFromParams,
  legacyPathToWorkspacePath,
  selectionFromParams,
  setDrawerParams,
  setSelectionParams,
  transitionDrawer,
} from '../workspace-navigation';

describe('workspace navigation', () => {
  it.each([
    ['/overview', '/operate'],
    ['/agents', '/operate?view=active&kind=agent'],
    ['/frontier', '/operate?view=ready&kind=frontier'],
    ['/sessions', '/operate?drawer=sessions'],
    ['/analysis', '/operate?drawer=run'],
    ['/graph', '/investigate?lens=topology'],
    ['/recon', '/investigate?lens=assets'],
    ['/identity', '/investigate?lens=identity'],
    ['/credentials', '/investigate?lens=credentials'],
    ['/paths', '/investigate?lens=paths'],
    ['/findings', '/review?view=readiness'],
    ['/evidence', '/review?view=proof'],
    ['/engagements', '/manage?section=engagement'],
    ['/settings', '/manage?section=settings'],
    ['/smoke', '/manage?section=diagnostics'],
  ])('translates %s to %s', (legacy, canonical) => {
    expect(legacyPathToWorkspacePath(legacy)).toBe(canonical);
  });

  it('preserves graph targeting parameters while adding the topology lens', () => {
    const result = legacyPathToWorkspacePath('/graph', new URLSearchParams({
      node: 'host-1', hops: '2', filter: 'host',
    }));
    expect(result).toBe('/investigate?node=host-1&hops=2&filter=host&lens=topology');
  });

  it('sends contextual evidence to a proof inspector without losing context', () => {
    const result = legacyPathToWorkspacePath('/evidence', new URLSearchParams({
      node: 'host-1', objective: 'obj-1',
    }));
    const url = new URL(result, 'https://overwatch.invalid');
    expect(url.pathname).toBe('/investigate');
    expect(Object.fromEntries(url.searchParams)).toMatchObject({
      node: 'host-1',
      objective: 'obj-1',
      lens: 'topology',
      tab: 'proof',
      entity: 'node',
      item: 'host-1',
      context: 'evidence',
    });
  });

  it('round-trips selection and targeted drawer state independently', () => {
    let params = new URLSearchParams({ view: 'active', filter: 'running' });
    params = setSelectionParams(params, { kind: 'agent', id: 'task/one' });
    params = setDrawerParams(params, { kind: 'run', item: 'act/one' });
    expect(selectionFromParams(params)).toEqual({ kind: 'agent', id: 'task/one' });
    expect(drawerFromParams(params)).toEqual({ kind: 'run', item: 'act/one' });
    expect(Object.fromEntries(clearSelectionParams(params))).toEqual({
      view: 'active',
      filter: 'running',
      drawer: 'run',
      drawerItem: 'act/one',
    });
  });

  it('clears legacy graph selection state without discarding filters or drawer context', () => {
    const params = new URLSearchParams({
      lens: 'topology', context: 'node', node: 'host-1', entity: 'node', item: 'host-1',
      filter: 'reachable', hops: '2', objective: 'obj-1', drawer: 'run', drawerItem: 'act-1',
    });

    expect(clearSelectionParams(params).toString()).toBe(
      'lens=topology&filter=reachable&hops=2&objective=obj-1&drawer=run&drawerItem=act-1',
    );
  });

  it('ignores unknown selection and drawer discriminants', () => {
    const params = new URLSearchParams({ kind: 'credential_value', item: 'secret', drawer: 'terminal' });
    expect(selectionFromParams(params)).toBeNull();
    expect(drawerFromParams(params)).toBeNull();
  });

  it('preserves action selections between Activity and Runs, including fixture IDs', () => {
    expect(transitionDrawer({ kind: 'activity', item: 'act_run-1' }, 'run')).toEqual({ kind: 'run', item: 'act_run-1' });
    expect(transitionDrawer({ kind: 'activity', item: 'a11ca7e0005' }, 'run')).toEqual({ kind: 'run', item: 'a11ca7e0005' });
    expect(transitionDrawer({ kind: 'run', item: 'arbitrary-deep-linked-action' }, 'activity')).toEqual({ kind: 'activity', item: 'arbitrary-deep-linked-action' });
  });

  it('clears event and session selections when drawer destinations are incompatible', () => {
    expect(transitionDrawer({ kind: 'activity', item: 'evt-system-1' }, 'run')).toEqual({ kind: 'run' });
    expect(transitionDrawer({ kind: 'activity', item: 'act_run-1' }, 'sessions')).toEqual({ kind: 'sessions' });
    expect(transitionDrawer({ kind: 'sessions', item: 'sess-1' }, 'activity')).toEqual({ kind: 'activity' });
  });
});
