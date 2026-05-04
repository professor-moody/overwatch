import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { splitFrames, buildRecord, processChunk, TapeWriter } from '../tape-recorder.js';

describe('tape-recorder splitFrames', () => {
  it('splits a single complete frame', () => {
    const r = splitFrames('', '{"a":1}\n');
    expect(r.frames).toEqual(['{"a":1}']);
    expect(r.remainder).toBe('');
  });

  it('carries a partial frame as remainder', () => {
    const r = splitFrames('', '{"a":1}\n{"b":');
    expect(r.frames).toEqual(['{"a":1}']);
    expect(r.remainder).toBe('{"b":');
  });

  it('joins prior buffer with new chunk', () => {
    const r = splitFrames('{"b":', '2}\n{"c":3}\n');
    expect(r.frames).toEqual(['{"b":2}', '{"c":3}']);
    expect(r.remainder).toBe('');
  });

  it('handles \\r\\n line endings', () => {
    const r = splitFrames('', '{"a":1}\r\n{"b":2}\r\n');
    expect(r.frames).toEqual(['{"a":1}', '{"b":2}']);
    expect(r.remainder).toBe('');
  });

  it('returns no frames for an empty chunk', () => {
    const r = splitFrames('', '');
    expect(r.frames).toEqual([]);
    expect(r.remainder).toBe('');
  });

  it('handles multi-frame burst', () => {
    const r = splitFrames('', '{"a":1}\n{"b":2}\n{"c":3}\n');
    expect(r.frames).toEqual(['{"a":1}', '{"b":2}', '{"c":3}']);
    expect(r.remainder).toBe('');
  });
});

describe('tape-recorder buildRecord', () => {
  const fixedNow = (): Date => new Date('2026-05-04T00:00:00.000Z');

  it('parses valid JSON-RPC frame', () => {
    const rec = buildRecord('client_to_server', '{"jsonrpc":"2.0","method":"tools/list","id":1}', fixedNow);
    expect(rec.direction).toBe('client_to_server');
    expect(rec.parsed).toEqual({ jsonrpc: '2.0', method: 'tools/list', id: 1 });
    expect(rec.raw).toBeUndefined();
    expect(rec.parse_error).toBeUndefined();
    expect(rec.ts).toBe('2026-05-04T00:00:00.000Z');
  });

  it('captures malformed frames with parse_error', () => {
    const rec = buildRecord('server_to_client', '{not-json', fixedNow);
    expect(rec.parsed).toBeUndefined();
    expect(rec.raw).toBe('{not-json');
    expect(rec.parse_error).toBeTruthy();
  });

  it('handles empty frames defensively', () => {
    const rec = buildRecord('server_to_client', '', fixedNow);
    expect(rec.raw).toBe('');
    expect(rec.parse_error).toBe('empty_frame');
  });
});

describe('tape-recorder TapeWriter + processChunk', () => {
  let tmp: string;
  let tapePath: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'overwatch-tape-'));
    tapePath = join(tmp, 'sub', 'tape.jsonl');
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('creates parent directories and appends JSONL', async () => {
    const w = new TapeWriter(tapePath);
    w.write({ ts: 't', direction: 'client_to_server', parsed: { id: 1 } });
    w.write({ ts: 't', direction: 'server_to_client', parsed: { id: 1, result: 'ok' } });
    expect(w.count).toBe(2);
    await w.close();

    const lines = readFileSync(tapePath, 'utf-8').trim().split('\n');
    expect(lines.length).toBe(2);
    expect(JSON.parse(lines[0]).parsed).toEqual({ id: 1 });
    expect(JSON.parse(lines[1]).parsed).toEqual({ id: 1, result: 'ok' });
  });

  it('processChunk integrates split + record + write across boundary', async () => {
    const w = new TapeWriter(tapePath);
    let buf = '';
    buf = processChunk(w, 'client_to_server', buf, '{"id":1}\n{"id":');
    expect(buf).toBe('{"id":');
    expect(w.count).toBe(1);
    buf = processChunk(w, 'client_to_server', buf, '2}\n');
    expect(buf).toBe('');
    expect(w.count).toBe(2);
    await w.close();

    const lines = readFileSync(tapePath, 'utf-8').trim().split('\n');
    expect(lines.length).toBe(2);
    expect(JSON.parse(lines[0]).parsed).toEqual({ id: 1 });
    expect(JSON.parse(lines[1]).parsed).toEqual({ id: 2 });
  });

  it('skips blank keepalive lines but still records bad JSON', async () => {
    const w = new TapeWriter(tapePath);
    let buf = '';
    buf = processChunk(w, 'server_to_client', buf, '\n{"good":1}\n{bad}\n');
    expect(buf).toBe('');
    expect(w.count).toBe(2); // blank skipped; good + bad written
    await w.close();
    const lines = readFileSync(tapePath, 'utf-8').trim().split('\n');
    const recs = lines.map(l => JSON.parse(l));
    expect(recs[0].parsed).toEqual({ good: 1 });
    expect(recs[1].parse_error).toBeTruthy();
    expect(recs[1].raw).toBe('{bad}');
  });

  it('write after close is a no-op', async () => {
    const w = new TapeWriter(tapePath);
    w.write({ ts: 't', direction: 'client_to_server', parsed: { id: 1 } });
    await w.close();
    w.write({ ts: 't', direction: 'client_to_server', parsed: { id: 2 } }); // should silently no-op
    const lines = readFileSync(tapePath, 'utf-8').trim().split('\n');
    expect(lines.length).toBe(1);
  });
});
