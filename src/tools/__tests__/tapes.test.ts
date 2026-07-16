import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { rmSync, writeFileSync, mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GraphEngine } from '../../services/graph-engine.js';
import { registerTapeTools } from '../tapes.js';
import type { EngagementConfig } from '../../types.js';


function makeConfig(): EngagementConfig {
  return {
    id: 'test-tapes',
    name: 'register_tape_session test',
    created_at: new Date().toISOString(),
    scope: { cidrs: ['10.10.10.0/24'], domains: ['test.local'], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function parse(result: any): any {
  return JSON.parse(result.content[0].text);
}

describe('register_tape_session', () => {
  let engine: GraphEngine;
  let handlers: Record<string, (args: any) => Promise<any>>;
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'overwatch-tapes-'));
    engine = new GraphEngine(makeConfig(), join(tmp, 'state.json'));
    handlers = {};
    const fakeServer = {
      registerTool(name: string, _config: unknown, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
      },
    } as unknown as McpServer;
    registerTapeTools(fakeServer, engine);
  });

  afterEach(() => {
    engine.dispose();
    rmSync(tmp, { recursive: true, force: true });
  });

  it('registers a tape and emits a tape_session_started event', async () => {
    const tapePath = join(tmp, 'tape.jsonl');
    writeFileSync(tapePath, [
      '{"jsonrpc":"2.0","method":"tools/list","id":1}',
      '{"jsonrpc":"2.0","id":1,"result":{}}',
    ].join('\n') + '\n');

    const result = await handlers.register_tape_session({
      tape_path: tapePath,
      session_id: 'recon-2026-05-04',
      upstream_command: 'node ./dist/index.js',
      notes: 'first capture',
    });
    const payload = parse(result);
    expect(payload.registered).toBe(true);
    expect(payload.tape_line_count).toBe(2);
    expect(payload.session_id).toBe('recon-2026-05-04');
    expect(payload.event_id).toBeTruthy();

    const events = engine.getFullHistory().filter(e => e.event_type === 'tape_session_started');
    expect(events.length).toBe(1);
    expect(events[0].provenance).toBe('operator');
    expect(events[0].category).toBe('system');
    const details = events[0].details as any;
    expect(details.session_id).toBe('recon-2026-05-04');
    expect(details.tape_line_count).toBe(2);
    expect(details.upstream_command).toBe('node ./dist/index.js');
    expect(details.notes).toBe('first capture');
  });

  it('returns isError when tape file is missing', async () => {
    const result = await handlers.register_tape_session({
      tape_path: join(tmp, 'does-not-exist.jsonl'),
      session_id: 'missing',
    });
    expect(result.isError).toBe(true);
    const payload = parse(result);
    expect(payload.registered).toBe(false);
    expect(payload.error).toBe('tape_not_found');
  });

  it('counts only non-empty lines', async () => {
    const tapePath = join(tmp, 'tape-blank.jsonl');
    writeFileSync(tapePath, '{"a":1}\n\n{"b":2}\n\n');
    const result = await handlers.register_tape_session({
      tape_path: tapePath,
      session_id: 's',
    });
    const payload = parse(result);
    expect(payload.tape_line_count).toBe(2);
  });
});
