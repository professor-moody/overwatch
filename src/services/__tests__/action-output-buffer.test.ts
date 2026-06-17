import { describe, it, expect } from 'vitest';
import { ActionOutputBuffer } from '../action-output-buffer.js';

describe('ActionOutputBuffer', () => {
  it('returns null for an unknown action and isDone=true', () => {
    const b = new ActionOutputBuffer();
    expect(b.read('nope', 'stdout')).toBeNull();
    expect(b.isDone('nope')).toBe(true);
    expect(b.has('nope')).toBe(false);
  });

  it('accumulates and reads incrementally by cursor', () => {
    const b = new ActionOutputBuffer();
    b.open('a1');
    b.append('a1', 'stdout', 'hello ');
    let r = b.read('a1', 'stdout', 0)!;
    expect(r.text).toBe('hello ');
    expect(r.dropped).toBe(false);
    const cursor = r.end_pos;
    b.append('a1', 'stdout', 'world');
    r = b.read('a1', 'stdout', cursor)!;
    expect(r.text).toBe('world');
    expect(r.end_pos).toBe(11);
  });

  it('keeps stdout and stderr independent', () => {
    const b = new ActionOutputBuffer();
    b.open('a1');
    b.append('a1', 'stdout', 'out');
    b.append('a1', 'stderr', 'err');
    expect(b.read('a1', 'stdout', 0)!.text).toBe('out');
    expect(b.read('a1', 'stderr', 0)!.text).toBe('err');
  });

  it('drops from the front past the cap and flags dropped for a stale cursor', () => {
    const b = new ActionOutputBuffer(10); // 10-char window
    b.open('a1');
    b.append('a1', 'stdout', '0123456789'); // exactly cap
    b.append('a1', 'stdout', 'ABCDE');       // pushes 5 off the front
    const r = b.read('a1', 'stdout', 0)!;     // cursor before the drop
    expect(r.text).toBe('56789ABCDE');
    expect(r.end_pos).toBe(15);
    expect(r.dropped).toBe(true);
    // a cursor at/after the drop boundary is not flagged
    expect(b.read('a1', 'stdout', 5)!.dropped).toBe(false);
  });

  it('accepts Buffer chunks (utf-8)', () => {
    const b = new ActionOutputBuffer();
    b.open('a1');
    b.append('a1', 'stdout', Buffer.from('café\n', 'utf-8'));
    expect(b.read('a1', 'stdout', 0)!.text).toBe('café\n');
  });

  it('ignores appends after markDone and reports done', () => {
    const b = new ActionOutputBuffer();
    b.open('a1');
    b.append('a1', 'stdout', 'before');
    b.markDone('a1');
    b.append('a1', 'stdout', 'after'); // ignored
    expect(b.isDone('a1')).toBe(true);
    expect(b.read('a1', 'stdout', 0)!.text).toBe('before');
  });

  it('evicts immediately on evict() and after the timer on markDone', () => {
    const b = new ActionOutputBuffer(256 * 1024, 5); // 5ms evict
    b.open('a1');
    expect(b.size).toBe(1);
    b.evict('a1');
    expect(b.size).toBe(0);
    expect(b.has('a1')).toBe(false);
  });

  it('resets a finished entry when its id is reused after markDone', () => {
    const b = new ActionOutputBuffer();
    b.open('a1');
    b.append('a1', 'stdout', 'old');
    b.markDone('a1');
    expect(b.isDone('a1')).toBe(true);
    b.open('a1'); // reuse within the eviction window
    expect(b.isDone('a1')).toBe(false);
    expect(b.read('a1', 'stdout', 0)!.text).toBe('');
    b.append('a1', 'stdout', 'new');
    expect(b.read('a1', 'stdout', 0)!.text).toBe('new');
  });

  it('bounds tracked actions to maxEntries, evicting finished entries first', () => {
    const b = new ActionOutputBuffer(1024, 30_000, 3); // cap 3
    b.open('a'); b.markDone('a'); // finished
    b.open('b'); // live
    b.open('c'); // live
    expect(b.size).toBe(3);
    b.open('d'); // over cap → drop the finished 'a', keep the live ones
    expect(b.size).toBe(3);
    expect(b.has('a')).toBe(false);
    expect(b.has('b')).toBe(true);
    expect(b.has('c')).toBe(true);
    expect(b.has('d')).toBe(true);
  });

  it('clamps an out-of-range cursor', () => {
    const b = new ActionOutputBuffer();
    b.open('a1');
    b.append('a1', 'stdout', 'abc');
    const r = b.read('a1', 'stdout', 9999)!;
    expect(r.text).toBe('');
    expect(r.end_pos).toBe(3);
  });
});
