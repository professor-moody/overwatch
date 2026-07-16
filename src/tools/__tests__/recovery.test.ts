import { afterEach, describe, expect, it } from 'vitest';
import { appendFileSync, mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { EngagementConfig } from '../../types.js';
import { GraphEngine } from '../../services/graph-engine.js';
import {
  withConfigMetadata,
  writeJsonAtomicDurable,
} from '../../services/engagement-config-service.js';
import { registerRecoveryTools } from '../recovery.js';

function config(): EngagementConfig {
  return {
    id: 'recovery-tools-test',
    name: 'Recovery tools test',
    created_at: '2026-07-15T00:00:00.000Z',
    scope: { cidrs: ['10.20.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

describe('recovery tools', () => {
  const engines: GraphEngine[] = [];
  const dirs: string[] = [];

  afterEach(() => {
    for (const engine of engines.splice(0)) engine.dispose();
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  function register(engine: GraphEngine) {
    const handlers: Record<string, (args: any) => Promise<any>> = {};
    const definitions: Record<string, any> = {};
    const server = {
      registerTool(name: string, definition: unknown, handler: (args: any) => Promise<any>) {
        definitions[name] = definition;
        handlers[name] = handler;
      },
    } as unknown as McpServer;
    registerRecoveryTools(server, engine);
    return { handlers, definitions };
  }

  function createDivergedEngine(): GraphEngine {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-recovery-tools-'));
    dirs.push(dir);
    const statePath = join(dir, 'state.json');
    const configPath = join(dir, 'engagement.json');
    const initial = withConfigMetadata(config(), 1);
    writeJsonAtomicDurable(configPath, initial);

    const first = new GraphEngine(initial, statePath, configPath);
    first.flushNow();
    first.dispose();

    const changed = withConfigMetadata({
      ...initial,
      name: 'File changed out of band',
    }, 2);
    writeJsonAtomicDurable(configPath, changed);
    const engine = new GraphEngine(changed, statePath, configPath);
    engines.push(engine);
    return engine;
  }

  it('registers a read-only status tool and a narrowly scoped reconciliation tool', () => {
    const engine = createDivergedEngine();
    const { definitions } = register(engine);

    expect(definitions.get_recovery_status.annotations).toMatchObject({
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
    });
    expect(definitions.resolve_config_divergence.annotations).toMatchObject({
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
    });
  });

  it('returns recovery status while configuration is read-only', async () => {
    const engine = createDivergedEngine();
    const { handlers } = register(engine);

    const result = await handlers.get_recovery_status({});
    const payload = JSON.parse(result.content[0].text);

    expect(result.isError).toBeUndefined();
    expect(payload.recovery).toMatchObject({
      writable: false,
      config_recovery: {
        status: 'diverged',
        resolution_required: true,
      },
    });
  });

  it('reports an actual malformed-WAL gate without changing the retained bytes', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'overwatch-recovery-wal-tool-'));
    dirs.push(dir);
    const statePath = join(dir, 'state.json');
    const configPath = join(dir, 'engagement.json');
    const initial = withConfigMetadata({ ...config(), engagement_nonce: 'f'.repeat(64) }, 1);
    writeJsonAtomicDurable(configPath, initial);

    const first = new GraphEngine(initial, statePath, configPath);
    first.addNode({
      id: 'host-before-malformed-wal',
      type: 'host',
      label: 'retained host',
      discovered_at: '2026-07-15T00:00:01.000Z',
      confidence: 1,
    });
    first.persistImmediate();
    const firstContext = (first as unknown as {
      ctx: { mutationJournal: { getPath(): string } | null };
    }).ctx;
    const walPath = firstContext.mutationJournal!.getPath();
    appendFileSync(walPath, '{"seq":999,"broken"');
    const walBefore = readFileSync(walPath);
    first.dispose();

    const degraded = new GraphEngine(initial, statePath, configPath);
    engines.push(degraded);
    const { handlers } = register(degraded);
    const result = await handlers.get_recovery_status({});
    const payload = JSON.parse(result.content[0].text);

    expect(result.isError).toBeUndefined();
    expect(payload.recovery).toMatchObject({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      journal: { enabled: true, malformed: true, preserved: true },
      config_recovery: { resolution_required: false },
    });
    expect(payload.recovery.reason).toMatch(/unterminated|malformed/i);
    expect(readFileSync(walPath)).toEqual(walBefore);
  });

  it('resolves with durable-state authority using the inspected hashes', async () => {
    const engine = createDivergedEngine();
    const { handlers } = register(engine);
    const recovery = engine.getConfigRecoveryStatus();

    const result = await handlers.resolve_config_divergence({
      resolution: 'use_state',
      expected_file_hash: recovery.file_hash,
      expected_state_hash: recovery.state_hash,
    });
    const payload = JSON.parse(result.content[0].text);

    expect(result.isError).toBeUndefined();
    expect(payload).toMatchObject({
      resolved: true,
      mode: 'use_state',
      recovery: { status: 'recovered', resolution_required: false },
      command_id: expect.any(String),
      replayed: false,
    });
    expect(engine.isPersistenceWritable()).toBe(true);

    const repeated = await handlers.resolve_config_divergence({
      resolution: 'use_state',
      expected_file_hash: recovery.file_hash,
      expected_state_hash: recovery.state_hash,
    });
    expect(repeated.isError).toBeUndefined();
    expect(JSON.parse(repeated.content[0].text)).toMatchObject({
      resolved: true,
      mode: 'use_state',
      command_id: payload.command_id,
      replayed: true,
    });
  });

  it('fails closed for stale hashes and when no divergence remains', async () => {
    const engine = createDivergedEngine();
    const { handlers } = register(engine);
    const recovery = engine.getConfigRecoveryStatus();

    const stale = await handlers.resolve_config_divergence({
      resolution: 'use_file',
      expected_file_hash: '0'.repeat(64),
      expected_state_hash: recovery.state_hash,
    });
    expect(stale).toMatchObject({ isError: true });
    const stalePayload = JSON.parse(stale.content[0].text);
    expect(stalePayload).toMatchObject({
      code: 'CONFIG_HASH_CONFLICT',
      error: expect.stringContaining('refresh recovery status'),
    });

    await handlers.resolve_config_divergence({
      resolution: 'use_state',
      expected_file_hash: recovery.file_hash,
      expected_state_hash: recovery.state_hash,
    });
    const repeated = await handlers.resolve_config_divergence({
      resolution: 'use_state',
      expected_file_hash: recovery.state_hash,
      expected_state_hash: recovery.state_hash,
    });
    expect(repeated).toMatchObject({ isError: true });
    expect(JSON.stringify(repeated)).toContain('No active configuration divergence');
  });
});
