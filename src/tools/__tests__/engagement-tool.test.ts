import { describe, it, expect } from 'vitest';
import { registerEngagementTools } from '../engagement.js';
import type { EngagementManager, EngagementSummary } from '../../services/engagement-manager.js';

// Capture the tool handlers registered against a fake MCP server.
function register(mgr: Partial<EngagementManager>) {
  const handlers: Record<string, (args: any) => Promise<any>> = {};
  const server = {
    registerTool(name: string, _cfg: unknown, cb: (args: any) => Promise<any>) {
      handlers[name] = cb;
      return { enable() {}, disable() {}, enabled: true };
    },
  } as any;
  registerEngagementTools(server, mgr as EngagementManager);
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
