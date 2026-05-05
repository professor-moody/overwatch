import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, existsSync, unlinkSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import { InProcessTapeController } from '../in-process-tape.js';
import { GraphEngine } from '../graph-engine.js';
import type { EngagementConfig } from '../../types.js';

const TEST_STATE_FILE = './state-test-tape.json';

function makeConfig(): EngagementConfig {
  return {
    id: 'test-tape',
    name: 'Tape Test',
    created_at: '2026-03-20T00:00:00Z',
    scope: { cidrs: [], domains: [], exclusions: [] },
    objectives: [],
    opsec: { name: 'pentest', max_noise: 0.7 },
  };
}

function cleanupState() {
  if (existsSync(TEST_STATE_FILE)) unlinkSync(TEST_STATE_FILE);
}

class FakeTransport implements Transport {
  public sent: JSONRPCMessage[] = [];
  onmessage?: Transport['onmessage'];
  onclose?: Transport['onclose'];
  onerror?: Transport['onerror'];
  sessionId?: string;
  startCount = 0;
  closeCount = 0;
  async start(): Promise<void> { this.startCount++; }
  async close(): Promise<void> { this.closeCount++; this.onclose?.(); }
  async send(message: JSONRPCMessage): Promise<void> { this.sent.push(message); }
  /** Simulate a frame arriving from the client. */
  emit(message: JSONRPCMessage): void { this.onmessage?.(message); }
}

describe('InProcessTapeController', () => {
  let tmpDir: string;
  let engine: GraphEngine;

  beforeEach(() => {
    cleanupState();
    tmpDir = mkdtempSync(join(tmpdir(), 'ow-tape-'));
    engine = new GraphEngine(makeConfig(), TEST_STATE_FILE);
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    cleanupState();
  });

  it('starts disabled and reports zero frames', () => {
    const c = new InProcessTapeController(engine, { defaultDir: tmpDir });
    const s = c.getStatus();
    expect(s.enabled).toBe(false);
    expect(s.frame_count).toBe(0);
    expect(s.path).toBeUndefined();
  });

  it('passes frames through transparently when disabled', async () => {
    const c = new InProcessTapeController(engine, { defaultDir: tmpDir });
    const fake = new FakeTransport();
    const wrapped = c.wrapTransport(fake);

    const received: JSONRPCMessage[] = [];
    wrapped.onmessage = (m) => { received.push(m); };

    fake.emit({ jsonrpc: '2.0', id: 1, method: 'ping', params: {} });
    await wrapped.send({ jsonrpc: '2.0', id: 1, result: {} });

    expect(received).toHaveLength(1);
    expect(fake.sent).toHaveLength(1);
    expect(c.getStatus().frame_count).toBe(0);
  });

  it('records both directions when enabled and writes to disk', async () => {
    const c = new InProcessTapeController(engine, { defaultDir: tmpDir });
    const fake = new FakeTransport();
    const wrapped = c.wrapTransport(fake);
    wrapped.onmessage = () => {};

    const status = c.enable();
    expect(status.enabled).toBe(true);
    expect(status.path).toBeDefined();

    fake.emit({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    await wrapped.send({ jsonrpc: '2.0', id: 1, result: { tools: [] } });
    fake.emit({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'x' } });

    const stopped = await c.disable();
    expect(stopped.enabled).toBe(false);

    const lines = readFileSync(status.path!, 'utf-8').trim().split('\n');
    expect(lines).toHaveLength(3);
    const recs = lines.map((l) => JSON.parse(l));
    expect(recs[0].direction).toBe('client_to_server');
    expect(recs[1].direction).toBe('server_to_client');
    expect(recs[2].direction).toBe('client_to_server');
    expect(recs[0].parsed.method).toBe('tools/list');
  });

  it('emits paired tape_session_started / tape_session_stopped activity events', async () => {
    const c = new InProcessTapeController(engine, { defaultDir: tmpDir });
    const before = engine.getFullHistory().length;
    c.enable();
    await c.disable();
    const after = engine.getFullHistory().length;
    expect(after - before).toBeGreaterThanOrEqual(2);

    const recent = engine.getFullHistory().slice(-2);
    expect(recent[0].event_type).toBe('tape_session_started');
    expect(recent[1].event_type).toBe('tape_session_stopped');
    expect(recent[1].details?.frame_count).toBe(0);
  });

  it('rotates to a fresh file across enable/disable cycles', async () => {
    const c = new InProcessTapeController(engine, { defaultDir: tmpDir });
    const s1 = c.enable();
    await c.disable();
    // Bump clock representation to avoid collision in the auto-named path.
    await new Promise((r) => setTimeout(r, 5));
    const s2 = c.enable();
    await c.disable();
    expect(s1.path).not.toEqual(s2.path);
  });

  it('honors an explicit file path', async () => {
    const explicit = join(tmpDir, 'fixed.jsonl');
    const c = new InProcessTapeController(engine, { defaultDir: tmpDir });
    const s = c.enable({ file: explicit });
    expect(s.path).toBe(explicit);
    await c.disable();
    expect(existsSync(explicit)).toBe(true);
  });
});
