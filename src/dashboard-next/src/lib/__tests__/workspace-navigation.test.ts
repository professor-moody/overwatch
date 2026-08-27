import { describe, expect, it } from 'vitest';
import {
  buildWorkspacePath,
  clearSelectionParams,
  drawerFromParams,
  legacyPathToWorkspacePath,
  selectionFromParams,
  setDrawerParams,
  setSelectionParams,
  transitionDrawer,
} from '../workspace-navigation';

describe('workspace navigation', () => {
  it('serializes canonical workspace selection, drawer, and graph context without legacy panel IDs', () => {
    expect(buildWorkspacePath({
      workspace: 'investigate',
      lens: 'topology',
      selection: { kind: 'edge', id: 'edge/one' },
      tab: 'proof',
      drawer: { kind: 'run', item: 'act/one' },
      context: { source: 'host one', target: 'host/two', hops: 2 },
    })).toBe('/investigate?lens=topology&kind=edge&item=edge%2Fone&tab=proof&drawer=run&drawerItem=act%2Fone&source=host+one&target=host%2Ftwo&hops=2');
  });

  it('serializes each workspace primary state through the typed route model', () => {
    expect(buildWorkspacePath({ workspace: 'operate', view: 'campaigns' })).toBe('/operate?view=campaigns');
    expect(buildWorkspacePath({ workspace: 'review', view: 'readiness', readiness: 'draft' })).toBe('/review?view=readiness&readiness=draft');
    expect(buildWorkspacePath({ workspace: 'manage', section: 'diagnostics' })).toBe('/manage?section=diagnostics');
  });

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

  it.each([
    ['/agents', 'item=task-1', '/operate', { item: 'task-1', view: 'active', kind: 'agent' }],
    ['/frontier', 'node=host-1', '/operate', { item: 'host-1', view: 'ready', kind: 'frontier' }],
    ['/actions', 'item=approval-1', '/operate', { item: 'approval-1', view: 'attention', kind: 'approval' }],
    ['/campaigns', 'item=campaign-1', '/operate', { item: 'campaign-1', view: 'campaigns', kind: 'campaign' }],
    ['/sessions', 'item=session-1', '/operate', { drawer: 'sessions', drawerItem: 'session-1' }],
    ['/activity', 'item=event-1', '/operate', { drawer: 'activity', drawerItem: 'event-1' }],
    ['/analysis', 'item=act-1', '/operate', { drawer: 'run', drawerItem: 'act-1' }],
    ['/recon', 'item=host-1', '/investigate', { item: 'host-1', lens: 'assets', kind: 'node' }],
    ['/identity', 'item=principal-1', '/investigate', { item: 'principal-1', lens: 'identity', kind: 'node' }],
    ['/credentials', 'item=credential-1', '/investigate', { item: 'credential-1', lens: 'credentials', kind: 'credential' }],
    ['/paths', 'item=path-1&nodes=a%2Cb&edges=e-1', '/investigate', { item: 'path-1', nodes: 'a,b', edges: 'e-1', lens: 'paths', kind: 'path' }],
    ['/findings', 'item=finding-1', '/review', { item: 'finding-1', view: 'readiness', kind: 'finding' }],
    ['/evidence', 'item=evidence-1', '/review', { item: 'evidence-1', view: 'proof', kind: 'evidence' }],
  ] as const)('preserves the selected item when translating %s?%s', (legacy, query, pathname, expected) => {
    const result = new URL(legacyPathToWorkspacePath(legacy, new URLSearchParams(query)), 'https://overwatch.invalid');
    expect(result.pathname).toBe(pathname);
    expect(Object.fromEntries(result.searchParams)).toEqual(expected);
  });

  it('preserves independent filters, inspector tabs, and drawers through legacy translation', () => {
    const result = new URL(legacyPathToWorkspacePath('/findings', new URLSearchParams({
      item: 'finding-1', readiness: 'draft', tab: 'proof', drawer: 'run', drawerItem: 'act-1',
    })), 'https://overwatch.invalid');
    expect(Object.fromEntries(result.searchParams)).toEqual({
      item: 'finding-1', readiness: 'draft', tab: 'proof', drawer: 'run', drawerItem: 'act-1',
      view: 'readiness', kind: 'finding',
    });
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

  it('recognizes graph edges as first-class shared inspector selections', () => {
    expect(selectionFromParams(new URLSearchParams({ entity: 'edge', item: 'edge-1' })))
      .toEqual({ kind: 'edge', id: 'edge-1' });
  });

  it('derives inspector selections from retained graph bookmark context', () => {
    expect(selectionFromParams(new URLSearchParams({ node: 'node-1', hops: '2' })))
      .toEqual({ kind: 'node', id: 'node-1' });
    expect(selectionFromParams(new URLSearchParams({ context: 'edge', edge: 'edge-1', source: 'a', target: 'b' })))
      .toEqual({ kind: 'edge', id: 'edge-1' });
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
