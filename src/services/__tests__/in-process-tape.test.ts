import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import { InProcessTapeController } from '../in-process-tape.js';
import { GraphEngine } from '../graph-engine.js';
import type { EngagementConfig } from '../../types.js';

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
    tmpDir = mkdtempSync(join(tmpdir(), 'ow-tape-'));
    engine = new GraphEngine(makeConfig(), join(tmpDir, 'state.json'));
  });

  afterEach(() => {
    engine.dispose();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('starts disabled and reports zero frames', () => {
    const c = new InProcessTapeController(engine, { defaultDir: tmpDir });
    const s = c.getStatus();
    expect(s.enabled).toBe(false);
    expect(s.frame_count).toBe(0);
    expect(s.path).toBeUndefined();
  });

  it('surfaces a writer stream error in getStatus (silent tape loss is observable)', () => {
    const c = new InProcessTapeController(engine, { defaultDir: tmpDir });
    c.enable();
    // Simulate the underlying WriteStream failing mid-session (e.g. ENOSPC).
    const writer = (c as unknown as { writer: { stream: { emit: (e: string, err: Error) => boolean } } }).writer;
    writer.stream.emit('error', new Error('ENOSPC: no space left'));
    expect(c.getStatus().error).toContain('ENOSPC');
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

  it('records start attribution in status and activity events', async () => {
    const c = new InProcessTapeController(engine, { defaultDir: tmpDir });
    const status = c.enable({ startedBy: 'config' });
    expect(status.started_by).toBe('config');
    await c.disable();

    const recent = engine.getFullHistory().slice(-2);
    expect(recent[0].details?.started_by).toBe('config');
    expect(recent[1].details?.started_by).toBe('config');
  });

  it('rolls back a newly created tape when the start audit event fails', async () => {
    const path = join(tmpDir, 'failed-start.jsonl');
    vi.spyOn(engine, 'logActionEvent').mockImplementationOnce(() => {
      throw new Error('audit append failed');
    });
    const c = new InProcessTapeController(engine, { file: path });

    expect(() => c.enable()).toThrow('audit append failed');
    expect(c.getStatus()).toMatchObject({ enabled: false, frame_count: 0 });
    await new Promise(resolve => setImmediate(resolve));
    expect(existsSync(path)).toBe(false);
  });

  it('clears active metadata even when the writer fails to close', async () => {
    const c = new InProcessTapeController(engine, { defaultDir: tmpDir });
    c.enable();
    const writer = (c as unknown as { writer: { close: () => Promise<void> } }).writer;
    const closeSpy = vi.spyOn(writer, 'close').mockRejectedValueOnce(new Error('synthetic close failure'));

    await expect(c.disable({ audit: false })).rejects.toThrow('synthetic close failure');
    expect(c.getStatus()).toMatchObject({ enabled: false, frame_count: 0 });
    expect(c.getStatus().path).toBeUndefined();
    expect(c.getStatus().session_id).toBeUndefined();

    closeSpy.mockRestore();
    await writer.close();
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

  it('tags frames with session_id so a multiplexed daemon tape can be demuxed per actor', async () => {
    // Two MCP sessions (primary + a sub-agent) feed ONE tape. Each frame must
    // carry its session id so the merged tape is attributable.
    const c = new InProcessTapeController(engine, { defaultDir: tmpDir });
    const primary = new FakeTransport(); primary.sessionId = 'sess-primary';
    const sub = new FakeTransport(); sub.sessionId = 'sess-subagent';
    const wp = c.wrapTransport(primary); wp.onmessage = () => {};
    const ws = c.wrapTransport(sub); ws.onmessage = () => {};

    const status = c.enable();
    primary.emit({ jsonrpc: '2.0', id: 1, method: 'get_state' });
    await wp.send({ jsonrpc: '2.0', id: 1, result: {} });
    sub.emit({ jsonrpc: '2.0', id: 7, method: 'report_finding' });
    await c.disable();

    const recs = readFileSync(status.path!, 'utf-8').trim().split('\n').map((l) => JSON.parse(l));
    const bySession = new Set(recs.map((r) => r.session_id));
    expect(bySession).toEqual(new Set(['sess-primary', 'sess-subagent']));
    // Demux: each actor's frames are recoverable by session_id.
    expect(recs.filter((r) => r.session_id === 'sess-primary')).toHaveLength(2);
    expect(recs.filter((r) => r.session_id === 'sess-subagent')).toHaveLength(1);
  });
});
