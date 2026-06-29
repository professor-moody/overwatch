import { describe, it, expect } from 'vitest';
import { registerEngagementTools } from '../engagement.js';
import type { EngagementManager, EngagementSummary } from '../../services/engagement-manager.js';
import type { GraphEngine } from '../../services/graph-engine.js';

// Capture the tool handlers registered against a fake MCP server.
function register(mgr: Partial<EngagementManager>, engine: Partial<GraphEngine> = {}) {
  const handlers: Record<string, (args: any) => Promise<any>> = {};
  const server = {
    registerTool(name: string, _cfg: unknown, cb: (args: any) => Promise<any>) {
      handlers[name] = cb;
      return { enable() {}, disable() {}, enabled: true };
    },
  } as any;
  registerEngagementTools(server, engine as GraphEngine, mgr as EngagementManager);
  return handlers;
}

const parse = async (cb: (a: any) => Promise<any>, args: any) => JSON.parse((await cb(args)).content[0].text);

const fakeSummary = (id: string): EngagementSummary => ({
  id, name: 'X', scope_cidrs: [], scope_domains: [], exclusions_count: 0,
  objectives_count: 0, phases_count: 0, config_path: `/tmp/engagements/${id}.json`,
  state_path: `/tmp/state-${id}.json`, is_active: false,
});

describe('create_engagement tool', () => {
  it('dry_run builds the config without persisting', async () => {
    let created = false;
    const h = register({ createEngagement: () => { created = true; return fakeSummary('x'); } });
    const out = await parse(h.create_engagement, { name: 'Recon Lab', cidrs: ['10.10.10.0/24'], dry_run: true });
    expect(created).toBe(false);
    expect(out.dry_run).toBe(true);
    expect(out.config.name).toBe('Recon Lab');
    expect(out.config.scope.cidrs).toEqual(['10.10.10.0/24']);
    expect(out.config.engagement_nonce).toMatch(/^[0-9a-f]{64}$/);
  });

  it('persists + returns an activation handoff (create-then-start)', async () => {
    let receivedInput: any;
    const h = register({ createEngagement: (input) => { receivedInput = input; return fakeSummary('recon-lab-abc'); } });
    const out = await parse(h.create_engagement, { name: 'Recon Lab', cidrs: ['10.10.10.0/24'], opsec_profile: 'quiet', objectives: [{ description: 'Get DA' }] });
    expect(out.created).toBe(true);
    expect(out.engagement.id).toBe('recon-lab-abc');
    expect(out.activation.status).toBe('not_active');
    expect(out.activation.steps.join(' ')).toMatch(/OVERWATCH_CONFIG/);
    expect(out.activation.steps.join(' ')).toMatch(/[Rr]estart/);
    // input was mapped to CreateEngagementInput shape
    expect(receivedInput.opsec_profile).toBe('quiet');
    expect(receivedInput.objectives[0].description).toBe('Get DA');
  });

  it('list_engagements returns the roster + active id', async () => {
    const h = register({
      listEngagements: () => [fakeSummary('a'), { ...fakeSummary('b'), is_active: true }],
      getActiveId: () => 'b',
    });
    const out = await parse(h.list_engagements, {});
    expect(out.active_id).toBe('b');
    expect(out.engagements).toHaveLength(2);
  });
});

describe('add_objective tool', () => {
  it('adds an objective to the active engine', async () => {
    let added: any;
    const h = register({}, { addObjective: (o: any) => { added = o; return { id: 'obj-1', ...o, achieved: false }; } } as any);
    const out = await parse(h.add_objective, { description: 'Get DA', target_node_type: 'credential' });
    expect(added.description).toBe('Get DA');
    expect(out.added).toBe(true);
    expect(out.objective.id).toBe('obj-1');
  });
});

describe('set_opsec tool', () => {
  const fakeEngine = (opsec: any) => {
    let persisted = false; const events: any[] = [];
    const engine = {
      getConfig: () => ({ opsec }),
      persist: () => { persisted = true; },
      logActionEvent: (e: any) => { events.push(e); },
    } as any;
    return { engine, opsec, persisted: () => persisted, events };
  };

  it('dry-run returns a before/after diff + weakening warning, does NOT persist', async () => {
    const f = fakeEngine({ name: 'pentest', enabled: true, max_noise: 0.5, approval_mode: 'approve-critical' });
    const h = register({}, f.engine);
    const out = await parse(h.set_opsec, { max_noise: 0.9, reason: 'go loud' });
    expect(out.mode).toBe('preview');
    expect(out.before.max_noise).toBe(0.5);
    expect(out.after.max_noise).toBe(0.9);
    expect(out.weakening_warnings.join(' ')).toMatch(/max_noise raised/);
    expect(f.persisted()).toBe(false);
    expect(f.opsec.max_noise).toBe(0.5); // unchanged
  });

  it('confirm applies in place, persists, and logs the reason', async () => {
    const f = fakeEngine({ name: 'pentest', enabled: true, max_noise: 0.5, approval_mode: 'approve-critical' });
    const h = register({}, f.engine);
    const out = await parse(h.set_opsec, { enabled: false, approval_mode: 'auto-approve', reason: 'lab, no gate', confirm: true });
    expect(out.applied).toBe(true);
    expect(f.opsec.enabled).toBe(false);
    expect(f.opsec.approval_mode).toBe('auto-approve');
    expect(f.persisted()).toBe(true);
    expect(f.events[0].description).toMatch(/lab, no gate/);
    expect(out.weakening_warnings.length).toBeGreaterThanOrEqual(2); // disabled + auto-approve
  });
});
