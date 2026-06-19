import { describe, it, expect } from 'vitest';
import { interpretQuery, executeQuery, NODE_TYPE_ALIASES } from '../query-interpreter.js';
import { NODE_TYPES } from '../../types.js';
import type { GraphEngine } from '../graph-engine.js';

// Fixed clock so relative/clock time parsing is deterministic. Tests run under
// the host TZ; named/clock times are computed in UTC (setUTCHours), so the
// expected ISO values below are TZ-independent.
const NOW = new Date('2026-06-18T15:00:00.000Z');
const iq = (t: string) => interpretQuery(t, NOW);

describe('interpretQuery — mutation guard', () => {
  it.each([
    'pause the recon agent',
    'resume web',
    'stop all',
    'halt scanning',
    'tell recon to list hosts',
    'instruct agent to count services',
    'scan 10.0.0.0/24',
    'add scope example.com',
    'add to scope 10.0.0.5',
    'target the DC',
    'approve action-7',
    'deny credentials',
    'deny action-7 stale history',
  ])('yields null for mutation lead: %s', (input) => {
    expect(iq(input)).toBeNull();
  });
});

describe('interpretQuery — only claims concrete queries (never starves the planner)', () => {
  // Unrecognized free text — including questions — must fall through to null so
  // the existing mutation grammar / headless planner runs unchanged.
  it.each([
    'focus everyone on credentials',
    'escalate on web01',
    "what's the riskiest unapproved action",
    'what should I do next',
    'where should I focus the agents?',
    'can you pause the recon agent?',
    'how do I get domain admin',
  ])('falls through to null: %s', (input) => {
    expect(iq(input)).toBeNull();
  });
});

describe('interpretQuery — changes_since', () => {
  it('bare "what changed" → no explicit window', () => {
    expect(iq('what changed')).toEqual({ kind: 'changes_since', since: undefined });
  });
  it('"what\'s new" / "anything new?" → changes_since', () => {
    expect(iq("what's new")).toMatchObject({ kind: 'changes_since' });
    expect(iq('anything new?')).toMatchObject({ kind: 'changes_since' });
  });
  it('relative window → resolved ISO since', () => {
    expect(iq('what changed in the last 15 minutes')).toEqual({ kind: 'changes_since', since: '2026-06-18T14:45:00.000Z' });
    expect(iq("what's happened in the past hour")).toEqual({ kind: 'changes_since', since: '2026-06-18T14:00:00.000Z' });
    expect(iq('anything new in the last 2h')).toEqual({ kind: 'changes_since', since: '2026-06-18T13:00:00.000Z' });
    expect(iq('what changed over the last half hour')).toEqual({ kind: 'changes_since', since: '2026-06-18T14:30:00.000Z' });
  });
  it('absolute ISO window passes through normalized', () => {
    expect(iq('changes since 2026-06-18T10:00:00Z')).toEqual({ kind: 'changes_since', since: '2026-06-18T10:00:00.000Z' });
  });
  it('named/clock windows resolve in UTC', () => {
    // today/midnight → start of UTC day (always <= now, never excludes everything)
    expect(iq('what changed today')).toEqual({ kind: 'changes_since', since: '2026-06-18T00:00:00.000Z' });
    expect(iq("what's new since 10am")).toEqual({ kind: 'changes_since', since: '2026-06-18T10:00:00.000Z' });
  });
  it('vague "since I last looked" → no window', () => {
    expect(iq('what happened since I last looked')).toEqual({ kind: 'changes_since', since: undefined });
    expect(iq('recap since last check')).toMatchObject({ kind: 'changes_since', since: undefined });
  });
  it('terse recap synonyms', () => {
    expect(iq('catch me up')).toMatchObject({ kind: 'changes_since' });
    expect(iq('any updates')).toMatchObject({ kind: 'changes_since' });
    expect(iq('fill me in')).toMatchObject({ kind: 'changes_since' });
  });
  it('"(any) new findings" routes to changes_since, not finding_readiness', () => {
    expect(iq('any new findings')).toMatchObject({ kind: 'changes_since' });
    expect(iq('new findings since last check')).toMatchObject({ kind: 'changes_since' });
  });
});

describe('interpretQuery — timeline', () => {
  it('bare timeline / history', () => {
    expect(iq('timeline')).toEqual({ kind: 'timeline', entity_id: undefined, entity_kind: undefined, since: undefined, at: undefined, limit: undefined });
    expect(iq('show me the timeline')).toMatchObject({ kind: 'timeline' });
    expect(iq('history')).toMatchObject({ kind: 'timeline' });
  });
  it('entity-scoped (ref kept raw; resolved at execute time)', () => {
    expect(iq('timeline for 10.0.0.5')).toMatchObject({ kind: 'timeline', entity_id: '10.0.0.5' });
    expect(iq('history of dc01.corp.local')).toMatchObject({ kind: 'timeline', entity_id: 'dc01.corp.local' });
    expect(iq('what happened to 10.0.0.5')).toMatchObject({ kind: 'timeline', entity_id: '10.0.0.5' });
    expect(iq('when did we find 10.0.0.5')).toMatchObject({ kind: 'timeline', entity_id: '10.0.0.5' });
  });
  it('kind / limit / since', () => {
    expect(iq('edge timeline')).toMatchObject({ kind: 'timeline', entity_kind: 'edge' });
    expect(iq('node history for host-1')).toMatchObject({ kind: 'timeline', entity_kind: 'node', entity_id: 'host-1' });
    expect(iq('timeline limit 50')).toMatchObject({ kind: 'timeline', limit: 50 });
    expect(iq('timeline last 24h')).toMatchObject({ kind: 'timeline', since: '2026-06-17T15:00:00.000Z' });
  });
  it('numeric window/limit clauses are NOT leaked as entity_id', () => {
    const win = iq('timeline last 24h') as { entity_id?: string; since?: string };
    expect(win.entity_id).toBeUndefined();
    expect(win.since).toBe('2026-06-17T15:00:00.000Z');
    const lim = iq('timeline limit 50') as { entity_id?: string; limit?: number };
    expect(lim.entity_id).toBeUndefined();
    expect(lim.limit).toBe(50);
    expect((iq('timeline 5 most recent') as { entity_id?: string }).entity_id).toBeUndefined();
  });
  it('entity + window together: keeps the entity AND the window', () => {
    expect(iq('timeline for 10.0.0.5 last 24h')).toMatchObject({ kind: 'timeline', entity_id: '10.0.0.5', since: '2026-06-17T15:00:00.000Z' });
  });
  it('point-in-time "at" does NOT also set since (no exact-instant collapse)', () => {
    const r = iq('history at noon') as { since?: string; at?: string };
    expect(r.at).toBe('2026-06-18T12:00:00.000Z');
    expect(r.since).toBeUndefined();
  });
  it('a date clause is a time window, NOT an entity id', () => {
    const r = iq('timeline on 2026-06-15') as { entity_id?: string; at?: string };
    expect(r.entity_id).toBeUndefined();
    expect(r.at).toBe('2026-06-15T00:00:00.000Z');
  });
  it('"what was true at <ts>" → at; bare "what was true" → not a timeline', () => {
    expect(iq('what was true at 2026-06-15T12:00:00Z')).toMatchObject({ kind: 'timeline', at: '2026-06-15T12:00:00.000Z' });
    expect(iq('what was true')?.kind).not.toBe('timeline');
  });
});

describe('interpretQuery — list_nodes', () => {
  it('list/show with type', () => {
    expect(iq('list hosts')).toEqual({ kind: 'list_nodes', node_type: 'host', count_only: false, limit: 25 });
    expect(iq('show all credentials')).toMatchObject({ kind: 'list_nodes', node_type: 'credential', count_only: false });
    expect(iq('list all the hosts')).toMatchObject({ kind: 'list_nodes', node_type: 'host' }); // stacked determiners
    expect(iq('list cert templates')).toMatchObject({ kind: 'list_nodes', node_type: 'cert_template' });
    expect(iq('vulns')).toMatchObject({ kind: 'list_nodes', node_type: 'vulnerability', count_only: false });
  });
  it('count intent', () => {
    expect(iq('how many services')).toMatchObject({ kind: 'list_nodes', node_type: 'service', count_only: true });
    expect(iq('count creds')).toMatchObject({ kind: 'list_nodes', node_type: 'credential', count_only: true });
    expect(iq('how many hosts are there')).toMatchObject({ kind: 'list_nodes', node_type: 'host', count_only: true });
  });
  it('explicit limit / generic graph', () => {
    expect(iq('show me the top 10 hosts')).toMatchObject({ kind: 'list_nodes', node_type: 'host', limit: 10 });
    const nodes = iq('how many nodes');
    expect(nodes).toMatchObject({ kind: 'list_nodes', count_only: true });
    expect((nodes as { node_type?: string }).node_type).toBeUndefined();
    const graph = iq('list everything');
    expect(graph).toMatchObject({ kind: 'list_nodes' });
    expect((graph as { node_type?: string }).node_type).toBeUndefined();
  });
  it('unresolved type → null (no guess); agents/campaigns are not node types', () => {
    expect(iq('list flrbts')).toBeNull();
    expect(iq('list agents')).toBeNull();
    expect(iq('show campaigns')).toBeNull();
  });
});

describe('interpretQuery — finding_readiness', () => {
  it('readiness filters', () => {
    expect(iq('what is client ready')).toMatchObject({ kind: 'finding_readiness', readiness: 'client_ready' });
    expect(iq('are any findings ready to report')).toMatchObject({ kind: 'finding_readiness', readiness: 'client_ready' });
    expect(iq('findings that need validation')).toMatchObject({ kind: 'finding_readiness', readiness: 'needs_validation' });
    expect(iq('list draft findings')).toMatchObject({ kind: 'finding_readiness', readiness: 'draft' });
  });
  it('gaps / lacks evidence', () => {
    expect(iq('which findings lack evidence')).toMatchObject({ kind: 'finding_readiness', gaps_only: true });
    expect(iq('show me findings missing evidence')).toMatchObject({ kind: 'finding_readiness', gaps_only: true });
    expect(iq('what gaps does finding f-9 have')).toMatchObject({ kind: 'finding_readiness', finding_id: 'f-9', gaps_only: true });
  });
  it('bare topic + single finding', () => {
    expect(iq('finding readiness')).toMatchObject({ kind: 'finding_readiness', finding_id: undefined, readiness: undefined, gaps_only: undefined });
    expect(iq('proof readiness')).toMatchObject({ kind: 'finding_readiness' });
    expect(iq('is finding f-12 ready')).toMatchObject({ kind: 'finding_readiness', finding_id: 'f-12' });
  });
});

describe('interpretQuery — find_paths (narrow: concrete refs / objective / symbolic DC only)', () => {
  it('symbolic DC + IP single tokens resolve', () => {
    expect(iq('paths to the DC')).toMatchObject({ kind: 'find_paths', to_ref: 'dc', optimize: 'confidence' });
    expect(iq('path to the domain controller')).toMatchObject({ kind: 'find_paths', to_ref: 'domain controller' });
    expect(iq('how do I reach 10.0.0.5')).toMatchObject({ kind: 'find_paths', to_ref: '10.0.0.5' });
  });
  it('from/to + between with concrete single-token refs', () => {
    expect(iq('attack path from web01 to dc01')).toMatchObject({ kind: 'find_paths', from_ref: 'web01', to_ref: 'dc01' });
    expect(iq('paths between web01 and dc01')).toMatchObject({ kind: 'find_paths', from_ref: 'web01', to_ref: 'dc01' });
    expect(iq('attack path from the bastion to the dc')).toMatchObject({ kind: 'find_paths', from_ref: 'bastion', to_ref: 'dc' });
  });
  it('"to <target> from <node>" order resolves correctly (no self-path)', () => {
    expect(iq('path to the dc from web01')).toMatchObject({ kind: 'find_paths', from_ref: 'web01', to_ref: 'dc' });
  });
  it('objective intent + explicit objective id', () => {
    expect(iq('show paths to the objective')).toMatchObject({ kind: 'find_paths', objective_intent: true });
    expect(iq('paths to objective obj-1')).toMatchObject({ kind: 'find_paths', objective_id: 'obj-1' });
  });
  it('optimize + max_paths', () => {
    expect(iq('stealthiest path to the DC')).toMatchObject({ kind: 'find_paths', to_ref: 'dc', optimize: 'stealth' });
    expect(iq('fastest path to the objective')).toMatchObject({ kind: 'find_paths', optimize: 'confidence', objective_intent: true });
    expect(iq('top 3 paths to dc01')).toMatchObject({ kind: 'find_paths', max_paths: 3 });
  });
  it('bare "show attack paths" → no refs (fans out to objectives at execute time)', () => {
    const r = iq('show attack paths') as { kind: string; from_ref?: string; to_ref?: string; hint?: string };
    expect(r.kind).toBe('find_paths');
    expect(r.from_ref).toBeUndefined();
    expect(r.to_ref).toBeUndefined();
    expect(r.hint).toBeUndefined();
  });
  it('hyphenated node names containing an optimize word are NOT corrupted', () => {
    expect(iq('path to fast-db')).toMatchObject({ kind: 'find_paths', to_ref: 'fast-db', optimize: 'confidence' });
    expect(iq('path to balanced-node')).toMatchObject({ kind: 'find_paths', to_ref: 'balanced-node', optimize: 'confidence' });
    expect(iq('path to quiet-host01')).toMatchObject({ kind: 'find_paths', to_ref: 'quiet-host01', optimize: 'confidence' });
    expect(iq('path from web01 to fast-api-gw')).toMatchObject({ kind: 'find_paths', from_ref: 'web01', to_ref: 'fast-api-gw' });
  });
  it('single-token target after "into" resolves; a node named like an objective is a node', () => {
    expect(iq('path into the dmz')).toMatchObject({ kind: 'find_paths', to_ref: 'dmz' });
    const r = iq('paths to goal-tracker') as { to_ref?: string; objective_intent?: boolean };
    expect(r.to_ref).toBe('goal-tracker');
    expect(r.objective_intent).toBeUndefined();
  });
  it('cedes count/changed-led phrasings even when "path" appears', () => {
    expect(iq('what changed on the path')).toMatchObject({ kind: 'changes_since' });
    expect(iq('how many paths exist')).toBeNull();
  });
  it('free-form multi-word / hop / locative targets are REJECTED with a hint (never a wrong-node path)', () => {
    const reject = (s: string) => {
      const r = iq(s) as { kind: string; to_ref?: string; from_ref?: string; hint?: string };
      expect(r.kind).toBe('find_paths');
      expect(r.hint).toBeTruthy();
      expect(r.to_ref).toBeUndefined();
      expect(r.from_ref).toBeUndefined();
    };
    reject('path to the file server');            // multi-word free-form
    reject('path to dc via web01');               // bare hop word
    reject('path to dc via 10.0.0.1');            // IP hop must NOT be extracted (was wrong-node)
    reject('path to dc via web01.corp.local');    // FQDN hop must NOT be extracted
    reject('path to the file server in vlan10');  // locative digit token
    reject('path to web app v2');                 // version token
    reject('path to host 10.0.0.9');              // IP buried in a multi-word phrase → name it directly
  });
});

describe('interpretQuery — retrospective', () => {
  it.each([
    'run a retrospective',
    'retrospective',
    'retro',
    'what worked',
    'what wasted time',
    'lessons learned',
    'what should the next operator do',
    'post-mortem',
  ])('claims retrospective phrasing: %s', (input) => {
    expect(iq(input)).toEqual({ kind: 'retrospective' });
  });
});

describe('NODE_TYPE_ALIASES never drifts from NODE_TYPES', () => {
  it('every alias maps to a real NodeType', () => {
    const valid = new Set<string>(NODE_TYPES);
    for (const [alias, t] of Object.entries(NODE_TYPE_ALIASES)) {
      expect(valid.has(t), `alias "${alias}" → "${t}" is not a NodeType`).toBe(true);
    }
  });
});

// ---- executeQuery with lightweight mock engines ----

function mockEngine(overrides: Partial<Record<keyof GraphEngine, unknown>>): GraphEngine {
  return overrides as unknown as GraphEngine;
}

describe('executeQuery — changes_since', () => {
  it('summarizes findings + completed agents since the window', () => {
    const engine = mockEngine({
      getFullHistory: () => [
        { event_id: 'e1', timestamp: '2026-06-18T14:50:00Z', description: 'x', category: 'finding' },
        { event_id: 'e2', timestamp: '2026-06-18T14:51:00Z', description: 'y', event_type: 'agent_transcript_submitted', agent_id: 'recon-1' },
        { event_id: 'e0', timestamp: '2026-06-18T10:00:00Z', description: 'old', category: 'finding' },
      ],
    });
    const ans = executeQuery(engine, { kind: 'changes_since', since: '2026-06-18T14:45:00.000Z' }, { now: NOW });
    expect(ans.kind).toBe('changes_since');
    expect(ans.rows?.some(r => r.includes('1 new finding'))).toBe(true);
    expect(ans.rows?.some(r => r.includes('recon-1'))).toBe(true);
  });
  it('falls back to a 15-min window when no since given', () => {
    const engine = mockEngine({ getFullHistory: () => [] });
    const ans = executeQuery(engine, { kind: 'changes_since' }, { now: NOW });
    expect(ans.summary).toContain('last 15 min');
  });
});

describe('executeQuery — list_nodes (exact counts from graph_summary)', () => {
  const engine = mockEngine({
    getState: () => ({ graph_summary: { total_nodes: 7, nodes_by_type: { host: 2, service: 0 } } }),
    queryGraph: (q: { node_type?: string }) => ({
      nodes: q.node_type === 'host'
        ? [{ id: 'h1', properties: { label: 'web01', ip: '10.0.0.5' } }, { id: 'h2', properties: { label: 'dc01', ip: '10.0.0.6' } }]
        : [],
      edges: [],
    }),
  });
  it('count_only reports the exact total (not a capped probe)', () => {
    const ans = executeQuery(engine, { kind: 'list_nodes', node_type: 'host', count_only: true, limit: 25 });
    expect(ans.summary).toBe('2 hosts');
    expect(ans.total).toBe(2);
  });
  it('generic node count uses total_nodes', () => {
    const ans = executeQuery(engine, { kind: 'list_nodes', count_only: true, limit: 25 });
    expect(ans.summary).toBe('7 nodes');
  });
  it('list renders node rows', () => {
    const ans = executeQuery(engine, { kind: 'list_nodes', node_type: 'host', count_only: false, limit: 25 });
    expect(ans.rows).toEqual(['web01 (10.0.0.5)', 'dc01 (10.0.0.6)']);
  });
  it('empty type → friendly message', () => {
    const ans = executeQuery(engine, { kind: 'list_nodes', node_type: 'service', count_only: false, limit: 25 });
    expect(ans.summary).toContain('No services');
    expect(ans.rows).toEqual([]);
  });
});

describe('executeQuery — timeline (resolves entity ref to node id)', () => {
  const nodes = [{ id: 'host-10-0-0-5', properties: { label: 'web01', ip: '10.0.0.5' } }];
  it('resolves a bare IP to the node id before querying', () => {
    let askedEntity: string | undefined;
    const engine = mockEngine({
      queryGraph: () => ({ nodes, edges: [] }),
      getTimeline: (q: { entity_id?: string }) => {
        askedEntity = q.entity_id;
        return [{ entity_id: 'host-10-0-0-5', kind: 'node', became_true_at: '2026-06-18T14:00:00Z', evidence_refs: [] }];
      },
    });
    const ans = executeQuery(engine, { kind: 'timeline', entity_id: '10.0.0.5' });
    expect(askedEntity).toBe('host-10-0-0-5'); // resolved, not the raw '10.0.0.5'
    expect(ans.summary).toContain('for 10.0.0.5');
    expect(ans.rows?.[0]).toContain('host-10-0-0-5');
  });
  it('unresolvable entity → no-match message, no timeline query', () => {
    const engine = mockEngine({ queryGraph: () => ({ nodes: [], edges: [] }), getTimeline: () => [] });
    const ans = executeQuery(engine, { kind: 'timeline', entity_id: 'nope' });
    expect(ans.summary).toContain('No node matches');
  });
  it('engagement-wide timeline (no entity) needs no resolution', () => {
    const engine = mockEngine({ getTimeline: () => [] });
    const ans = executeQuery(engine, { kind: 'timeline' });
    expect(ans.summary).toContain('No timeline entries');
  });
  it('exact IP wins over a longer-IP sibling (10.0.0.5 vs 10.0.0.50)', () => {
    let askedEntity: string | undefined;
    const engine = mockEngine({
      queryGraph: () => ({
        nodes: [
          { id: 'host-10-0-0-5', properties: { label: 'a', ip: '10.0.0.5' } },
          { id: 'host-10-0-0-50', properties: { label: 'b', ip: '10.0.0.50' } },
        ],
        edges: [],
      }),
      getTimeline: (q: { entity_id?: string }) => { askedEntity = q.entity_id; return []; },
    });
    const ans = executeQuery(engine, { kind: 'timeline', entity_id: '10.0.0.5' });
    expect(askedEntity).toBe('host-10-0-0-5'); // not ambiguous
    expect(ans.summary).not.toContain('be specific');
  });
});

describe('executeQuery — find_paths', () => {
  const NODES = [
    { id: 'host-web01', properties: { label: 'web01', ip: '10.0.0.5' } },
    { id: 'host-dc01', properties: { label: 'DC01', hostname: 'dc01.corp.local' } },
  ];
  const path = (nodes: string[]) => ({ nodes, total_confidence: 0.8, total_opsec_noise: 1.5 });

  it('explicit objective_id → findPathsToObjective', () => {
    let askedObj: string | undefined;
    const engine = mockEngine({ findPathsToObjective: (id: string) => { askedObj = id; return [path(['a', 'b'])]; } });
    const ans = executeQuery(engine, { kind: 'find_paths', objective_id: 'obj-1', optimize: 'confidence' });
    expect(askedObj).toBe('obj-1');
    expect(ans.summary).toContain('1 path');
  });

  it('from + to resolved → findPathsDetailed', () => {
    let args: [string, string] | undefined;
    const engine = mockEngine({
      queryGraph: () => ({ nodes: NODES, edges: [] }),
      findPathsDetailed: (f: string, t: string) => { args = [f, t]; return { paths: [path(['host-web01', 'host-dc01'])], analysis_status: 'found' }; },
    });
    const ans = executeQuery(engine, { kind: 'find_paths', from_ref: 'web01', to_ref: 'dc01', optimize: 'confidence' });
    expect(args).toEqual(['host-web01', 'host-dc01']);
    expect(ans.rows?.[0]).toContain('host-web01 → host-dc01');
  });

  it('to-only ("paths to the DC") fans out from compromised footholds (resolved by label)', () => {
    const fromArgs: string[] = [];
    const engine = mockEngine({
      queryGraph: () => ({ nodes: NODES, edges: [] }),
      getState: () => ({ objectives: [], access_summary: { compromised_hosts: ['web01'] } }),
      findPaths: (f: string) => { fromArgs.push(f); return [path(['host-web01', 'host-dc01'])]; },
    });
    const ans = executeQuery(engine, { kind: 'find_paths', to_ref: 'dc', optimize: 'confidence' });
    expect(fromArgs).toEqual(['host-web01']); // foothold label 'web01' resolved to its node id
    expect(ans.summary).toContain('1 path');
  });

  it('to-only with no foothold → guidance, not a crash', () => {
    const engine = mockEngine({
      queryGraph: () => ({ nodes: NODES, edges: [] }),
      getState: () => ({ objectives: [], access_summary: { compromised_hosts: [] } }),
    });
    const ans = executeQuery(engine, { kind: 'find_paths', to_ref: 'dc', optimize: 'confidence' });
    expect(ans.summary).toContain('No foothold');
  });

  it('ambiguous target ref → be specific (no path attempt)', () => {
    const engine = mockEngine({
      queryGraph: () => ({ nodes: [{ id: 'host-1', properties: { label: 'svc-a' } }, { id: 'host-2', properties: { label: 'svc-b' } }], edges: [] }),
    });
    const ans = executeQuery(engine, { kind: 'find_paths', to_ref: 'svc', optimize: 'confidence' });
    expect(ans.summary).toMatch(/matches 2 node|No target node/);
  });

  it('symbolic "the dc" with no real DC → no-match, NOT a substring wrong-node', () => {
    // graph has a "cdc-archive" node that merely contains "dc" but is not a DC
    const engine = mockEngine({
      queryGraph: () => ({ nodes: [{ id: 'db-cdc', properties: { label: 'cdc-archive' } }], edges: [] }),
      getState: () => ({ objectives: [], access_summary: { compromised_hosts: [] } }),
      findPaths: () => { throw new Error('must not path to a non-DC'); },
    });
    const ans = executeQuery(engine, { kind: 'find_paths', to_ref: 'dc', optimize: 'confidence' });
    expect(ans.summary).toMatch(/No target node matches|matches/);
  });

  it('objective intent (no from) → findPathsToObjective per unachieved objective', () => {
    const objIds: string[] = [];
    const engine = mockEngine({
      queryGraph: () => ({ nodes: NODES, edges: [] }),
      getState: () => ({ objectives: [{ id: 'obj-1', description: 'DA', achieved: false }, { id: 'obj-2', description: 'done', achieved: true }], access_summary: { compromised_hosts: [] } }),
      findPathsToObjective: (id: string) => { objIds.push(id); return [path(['x', 'y'])]; },
    });
    const ans = executeQuery(engine, { kind: 'find_paths', objective_intent: true, optimize: 'confidence' });
    expect(objIds).toEqual(['obj-1']); // only the unachieved objective
    expect(ans.summary).toContain('path');
  });
});

describe('executeQuery — retrospective', () => {
  const engine = mockEngine({
    getConfig: () => ({
      id: 'eng-1', name: 'Test Engagement', created_at: '2026-06-18T00:00:00Z',
      objectives: [{ achieved: true }, { achieved: false }],
      opsec: { name: 'default', max_noise: 0.5, blacklisted_techniques: [] },
      scope: { cidrs: [], domains: [], exclusions: [], url_patterns: [], aws_accounts: [], azure_subscriptions: [], gcp_projects: [] },
    }),
    exportGraph: () => ({ nodes: [], edges: [] }),
    getFullHistory: () => [],
    getInferenceRules: () => [],
    getAllAgents: () => [],
  });
  it('summarizes the retrospective digest and degrades without skills', () => {
    const ans = executeQuery(engine, { kind: 'retrospective' }, { skills: null });
    expect(ans.kind).toBe('retrospective');
    expect(ans.summary).toContain('inference suggestion');
    // digest carries the engagement line; never throws when skills are absent
    expect(ans.rows?.some(r => r.includes('Test Engagement'))).toBe(true);
  });
  it('reads skill names when a skill index is provided', () => {
    let asked = false;
    const skills = { listSkills: () => { asked = true; return [{ name: 'recon', tags: ['discovery'] }]; } };
    executeQuery(engine, { kind: 'retrospective' }, { skills });
    expect(asked).toBe(true);
  });
});
