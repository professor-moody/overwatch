import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { EngagementConfig } from '../../types.js';
import {
  withApplicationCommandInvocation,
} from '../application-command-service.js';
import { GraphCorrectionCommandService } from '../graph-correction-command-service.js';
import { GraphEngine } from '../graph-engine.js';

function config(): EngagementConfig {
  return {
    id: 'graph-correction-command',
    name: 'Graph correction command',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: ['10.0.0.0/24'], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7, enabled: true },
  };
}

describe('GraphCorrectionCommandService', () => {
  let directory: string;
  let statePath: string;
  let engine: GraphEngine;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-graph-command-'));
    statePath = join(directory, 'state.json');
    engine = new GraphEngine(config(), statePath);
    engine.addNode({
      id: 'host-correct',
      type: 'host',
      label: 'old label',
      ip: '10.0.0.20',
      discovered_at: '2026-07-16T00:00:01.000Z',
      confidence: 1,
    });
  });

  afterEach(() => {
    engine.dispose();
    rmSync(directory, { recursive: true, force: true });
  });

  it('patches once and returns the original outcome on retry', () => {
    const service = new GraphCorrectionCommandService(engine);
    const correct = () => withApplicationCommandInvocation({
      transport: 'dashboard',
      command_id: 'graph-patch-command',
      idempotency_key: 'graph-patch-retry',
    }, () => service.correct({
      reason: 'Fix the label',
      operations: [{
        kind: 'patch_node',
        node_id: 'host-correct',
        set_properties: { label: 'correct label' },
      }],
    }));

    const first = correct();
    const second = correct();

    expect(engine.getNode('host-correct')?.label).toBe('correct label');
    expect(first.result).toMatchObject({
      patched_nodes: ['host-correct'],
    });
    expect(second).toMatchObject({
      command_id: first.command_id,
      replayed: true,
      result: first.result,
    });
    expect(engine.getFullHistory().filter(
      event => event.event_type === 'graph_corrected',
    )).toHaveLength(1);
  });

  it('replays a destructive node drop after restart without dropping again', () => {
    const invoke = () => withApplicationCommandInvocation({
      transport: 'mcp',
      command_id: 'graph-drop-command',
      idempotency_key: 'graph-drop-retry',
    }, () => new GraphCorrectionCommandService(engine).correct({
      reason: 'Remove stale node',
      operations: [{ kind: 'drop_node', node_id: 'host-correct' }],
    }));
    const first = invoke();
    expect(engine.getNode('host-correct')).toBeNull();
    engine.flushNow();
    engine.dispose();

    engine = new GraphEngine(config(), statePath);
    const replay = invoke();
    expect(replay).toMatchObject({
      command_id: first.command_id,
      replayed: true,
      result: first.result,
    });
    expect(engine.getNode('host-correct')).toBeNull();
  });

  it('binds a failed correction key so later state changes cannot reinterpret it', () => {
    const service = new GraphCorrectionCommandService(engine);
    const invoke = () => withApplicationCommandInvocation({
      transport: 'mcp',
      command_id: 'graph-failed-command',
      idempotency_key: 'graph-failed-retry',
    }, () => service.correct({
      reason: 'Drop a missing node',
      operations: [{ kind: 'drop_node', node_id: 'host-later' }],
    }));

    expect(invoke).toThrow('Node does not exist in graph: host-later');
    expect(engine.getApplicationCommandById('graph-failed-command'))
      .toMatchObject({ status: 'failed' });
    engine.addNode({
      id: 'host-later',
      type: 'host',
      label: 'later host',
      ip: '10.0.0.21',
      discovered_at: '2026-07-16T00:00:02.000Z',
      confidence: 1,
    });

    expect(invoke).toThrow('Node does not exist in graph: host-later');
    expect(engine.getNode('host-later')).not.toBeNull();
    expect(engine.listApplicationCommands().filter(command =>
      command.command_id === 'graph-failed-command')).toHaveLength(1);
  });
});
