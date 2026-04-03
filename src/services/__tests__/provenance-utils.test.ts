import { describe, it, expect } from 'vitest';
import {
  getNodeFirstSeenAt,
  getNodeLastSeenAt,
  getNodeSources,
  normalizeNodeProvenance,
} from '../provenance-utils.js';
import type { NodeProperties } from '../../types.js';

function makeNode(overrides: Partial<NodeProperties> = {}): NodeProperties {
  return { id: 'n1', label: 'n1', confidence: 1.0, ...overrides } as NodeProperties;
}

describe('getNodeFirstSeenAt', () => {
  it('returns first_seen_at when present', () => {
    const node = makeNode({ first_seen_at: '2026-01-01T00:00:00Z' });
    expect(getNodeFirstSeenAt(node)).toBe('2026-01-01T00:00:00Z');
  });

  it('falls back to discovered_at', () => {
    const node = makeNode({ discovered_at: '2026-02-01T00:00:00Z' });
    expect(getNodeFirstSeenAt(node)).toBe('2026-02-01T00:00:00Z');
  });

  it('prefers first_seen_at over discovered_at', () => {
    const node = makeNode({
      first_seen_at: '2026-01-01T00:00:00Z',
      discovered_at: '2026-02-01T00:00:00Z',
    });
    expect(getNodeFirstSeenAt(node)).toBe('2026-01-01T00:00:00Z');
  });

  it('returns undefined when neither field is set', () => {
    expect(getNodeFirstSeenAt(makeNode())).toBeUndefined();
  });
});

describe('getNodeLastSeenAt', () => {
  it('returns last_seen_at when present', () => {
    const node = makeNode({ last_seen_at: '2026-03-01T00:00:00Z' });
    expect(getNodeLastSeenAt(node)).toBe('2026-03-01T00:00:00Z');
  });

  it('falls back to first_seen_at', () => {
    const node = makeNode({ first_seen_at: '2026-01-01T00:00:00Z' });
    expect(getNodeLastSeenAt(node)).toBe('2026-01-01T00:00:00Z');
  });

  it('falls back through to discovered_at', () => {
    const node = makeNode({ discovered_at: '2026-02-01T00:00:00Z' });
    expect(getNodeLastSeenAt(node)).toBe('2026-02-01T00:00:00Z');
  });

  it('returns undefined when no timestamps exist', () => {
    expect(getNodeLastSeenAt(makeNode())).toBeUndefined();
  });
});

describe('getNodeSources', () => {
  it('returns sources array as-is', () => {
    const node = makeNode({ sources: ['nmap', 'masscan'] });
    expect(getNodeSources(node)).toEqual(['nmap', 'masscan']);
  });

  it('appends discovered_by when not already in sources', () => {
    const node = makeNode({ sources: ['nmap'], discovered_by: 'masscan' });
    expect(getNodeSources(node)).toEqual(['nmap', 'masscan']);
  });

  it('does not duplicate discovered_by if already in sources', () => {
    const node = makeNode({ sources: ['nmap'], discovered_by: 'nmap' });
    expect(getNodeSources(node)).toEqual(['nmap']);
  });

  it('returns discovered_by alone when sources is empty', () => {
    const node = makeNode({ sources: [], discovered_by: 'nmap' });
    expect(getNodeSources(node)).toEqual(['nmap']);
  });

  it('returns discovered_by alone when sources is missing', () => {
    const node = makeNode({ discovered_by: 'nmap' });
    expect(getNodeSources(node)).toEqual(['nmap']);
  });

  it('returns empty array when neither sources nor discovered_by exist', () => {
    expect(getNodeSources(makeNode())).toEqual([]);
  });

  it('returns empty array when sources is not an array', () => {
    const node = makeNode({ sources: 'nmap' as any });
    expect(getNodeSources(node)).toEqual([]);
  });

  it('returns a copy, not the original array', () => {
    const sources = ['nmap'];
    const node = makeNode({ sources });
    const result = getNodeSources(node);
    result.push('extra');
    expect(node.sources).toEqual(['nmap']);
  });
});

describe('normalizeNodeProvenance', () => {
  it('populates all fields from a fully specified node', () => {
    const node = makeNode({
      first_seen_at: '2026-01-01T00:00:00Z',
      last_seen_at: '2026-03-01T00:00:00Z',
      discovered_at: '2026-01-01T00:00:00Z',
      discovered_by: 'nmap',
      sources: ['nmap'],
    });
    expect(normalizeNodeProvenance(node)).toEqual({
      first_seen_at: '2026-01-01T00:00:00Z',
      last_seen_at: '2026-03-01T00:00:00Z',
      discovered_at: '2026-01-01T00:00:00Z',
      discovered_by: 'nmap',
      sources: ['nmap'],
    });
  });

  it('sets discovered_at from first_seen_at when discovered_at is missing', () => {
    const node = makeNode({ first_seen_at: '2026-01-01T00:00:00Z' });
    const result = normalizeNodeProvenance(node);
    expect(result.discovered_at).toBe('2026-01-01T00:00:00Z');
  });

  it('sets sources to undefined when empty', () => {
    const result = normalizeNodeProvenance(makeNode());
    expect(result.sources).toBeUndefined();
  });

  it('mirrors first_seen_at into last_seen_at when last_seen_at is absent', () => {
    const node = makeNode({ first_seen_at: '2026-01-01T00:00:00Z' });
    const result = normalizeNodeProvenance(node);
    expect(result.last_seen_at).toBe('2026-01-01T00:00:00Z');
  });

  it('handles a completely empty node', () => {
    const result = normalizeNodeProvenance(makeNode());
    expect(result).toEqual({
      first_seen_at: undefined,
      last_seen_at: undefined,
      discovered_at: undefined,
      discovered_by: undefined,
      sources: undefined,
    });
  });
});
