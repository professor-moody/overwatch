import { describe, it, expect } from 'vitest';
import {
  ColdStore,
  classifyNodeTemperature,
  toColdRecord,
  type ColdNodeRecord,
} from '../cold-store.js';
import type { NodeProperties } from '../../types.js';

const now = '2026-04-01T00:00:00Z';
const later = '2026-04-02T00:00:00Z';
const earlier = '2026-03-31T00:00:00Z';

function makeRecord(overrides: Partial<ColdNodeRecord> = {}): ColdNodeRecord {
  return {
    id: 'host-1',
    type: 'host',
    label: '10.0.0.1',
    ip: '10.0.0.1',
    discovered_at: now,
    last_seen_at: now,
    subnet_cidr: '10.0.0.0/24',
    alive: true,
    ...overrides,
  };
}

describe('ColdStore', () => {
  describe('add / get / has', () => {
    it('advances a process-local revision only when inventory operations change state', () => {
      const cs = new ColdStore();
      const initial = cs.getRevision();
      cs.add(makeRecord());
      const afterAdd = cs.getRevision();
      cs.promote('missing');
      expect(cs.getRevision()).toBe(afterAdd);
      cs.promote('host-1');
      expect(initial).toBe(0);
      expect(afterAdd).toBe(1);
      expect(cs.getRevision()).toBe(2);
    });

    it('does not advance the revision for a semantically identical add', () => {
      const cs = new ColdStore();
      cs.add(makeRecord());
      const revision = cs.getRevision();
      cs.add({ ...makeRecord() });
      expect(cs.getRevision()).toBe(revision);
    });

    it('stores and retrieves a record', () => {
      const cs = new ColdStore();
      const rec = makeRecord();
      cs.add(rec);

      expect(cs.has('host-1')).toBe(true);
      expect(cs.get('host-1')).toEqual(rec);
      expect(cs.count()).toBe(1);
    });

    it('merges on duplicate add — keeps earliest discovered_at and latest last_seen_at', () => {
      const cs = new ColdStore();
      cs.add(makeRecord({ discovered_at: now, last_seen_at: now }));
      cs.add(makeRecord({
        discovered_at: earlier,
        last_seen_at: later,
        provenance: 'agent-2',
      }));

      const merged = cs.get('host-1')!;
      expect(merged.discovered_at).toBe(earlier);
      expect(merged.last_seen_at).toBe(later);
      expect(merged.provenance).toBe('agent-2');
    });

    it('merge keeps later discovered_at from existing if existing is earlier', () => {
      const cs = new ColdStore();
      cs.add(makeRecord({ discovered_at: earlier, last_seen_at: earlier }));
      cs.add(makeRecord({ discovered_at: now, last_seen_at: earlier }));

      expect(cs.get('host-1')!.discovered_at).toBe(earlier);
    });

    it('merge keeps later last_seen_at from existing if existing is later', () => {
      const cs = new ColdStore();
      cs.add(makeRecord({ discovered_at: now, last_seen_at: later }));
      cs.add(makeRecord({ discovered_at: now, last_seen_at: now }));

      expect(cs.get('host-1')!.last_seen_at).toBe(later);
    });
  });

  describe('import', () => {
    it('does not advance the revision for identical inventory in another order', () => {
      const cs = new ColdStore();
      const first = makeRecord({ id: 'host-1' });
      const second = makeRecord({ id: 'host-2', ip: '10.0.0.2', label: '10.0.0.2' });
      cs.import([first, second]);
      const revision = cs.getRevision();
      cs.import([{ ...second }, { ...first }]);
      expect(cs.getRevision()).toBe(revision);
    });

    it('advances the revision when imported inventory changes', () => {
      const cs = new ColdStore();
      cs.import([makeRecord()]);
      const revision = cs.getRevision();
      cs.import([makeRecord({ last_seen_at: later })]);
      expect(cs.getRevision()).toBe(revision + 1);
    });
  });

  describe('promote', () => {
    it('removes the record and returns it', () => {
      const cs = new ColdStore();
      cs.add(makeRecord());

      const promoted = cs.promote('host-1');
      expect(promoted).toBeDefined();
      expect(promoted!.id).toBe('host-1');
      expect(cs.has('host-1')).toBe(false);
      expect(cs.count()).toBe(0);
    });

    it('is idempotent — second promote returns undefined', () => {
      const cs = new ColdStore();
      cs.add(makeRecord());

      cs.promote('host-1');
      expect(cs.promote('host-1')).toBeUndefined();
    });

    it('returns undefined for a key that was never added', () => {
      const cs = new ColdStore();
      expect(cs.promote('nonexistent')).toBeUndefined();
    });
  });

  describe('bounded rollback snapshots', () => {
    it('restores an updated entry and its exact prior revision', () => {
      const cs = new ColdStore();
      cs.add(makeRecord());
      const snapshot = cs.captureEntrySnapshot('host-1');
      cs.add(makeRecord({ last_seen_at: later, provenance: 'agent-2' }));
      expect(cs.getRevision()).toBe(snapshot.revision + 1);

      cs.restoreEntrySnapshot(snapshot);

      expect(cs.get('host-1')).toEqual(makeRecord());
      expect(cs.getRevision()).toBe(snapshot.revision);
    });

    it('restores promoted and newly added entries without advancing revision', () => {
      const cs = new ColdStore();
      cs.add(makeRecord());
      const existing = cs.captureEntrySnapshot('host-1');
      const missing = cs.captureEntrySnapshot('host-2');
      cs.promote('host-1');
      cs.add(makeRecord({ id: 'host-2', label: '10.0.0.2', ip: '10.0.0.2' }));

      cs.restoreEntrySnapshot(missing);
      cs.restoreEntrySnapshot(existing);

      expect(cs.has('host-2')).toBe(false);
      expect(cs.get('host-1')).toEqual(makeRecord());
      expect(cs.getRevision()).toBe(existing.revision);
    });

    it('returns a detached record snapshot', () => {
      const cs = new ColdStore();
      cs.add(makeRecord());
      const snapshot = cs.captureEntrySnapshot('host-1');
      snapshot.record!.label = 'changed outside the store';
      expect(cs.get('host-1')?.label).toBe('10.0.0.1');
    });
  });

  describe('countBySubnet', () => {
    it('groups counts by subnet_cidr', () => {
      const cs = new ColdStore();
      cs.add(makeRecord({ id: 'h1', subnet_cidr: '10.0.0.0/24' }));
      cs.add(makeRecord({ id: 'h2', subnet_cidr: '10.0.0.0/24' }));
      cs.add(makeRecord({ id: 'h3', subnet_cidr: '10.0.1.0/24' }));

      expect(cs.countBySubnet()).toEqual({
        '10.0.0.0/24': 2,
        '10.0.1.0/24': 1,
      });
    });

    it('uses "unknown" for records without subnet_cidr', () => {
      const cs = new ColdStore();
      cs.add(makeRecord({ id: 'h1', subnet_cidr: undefined }));

      expect(cs.countBySubnet()).toEqual({ unknown: 1 });
    });
  });

  describe('export / import round-trip', () => {
    it('exports all records and imports them into a fresh store', () => {
      const cs1 = new ColdStore();
      cs1.add(makeRecord({ id: 'h1', ip: '10.0.0.1' }));
      cs1.add(makeRecord({ id: 'h2', ip: '10.0.0.2' }));

      const exported = cs1.export();
      expect(exported).toHaveLength(2);

      const cs2 = new ColdStore();
      cs2.import(exported);

      expect(cs2.count()).toBe(2);
      expect(cs2.get('h1')).toEqual(cs1.get('h1'));
      expect(cs2.get('h2')).toEqual(cs1.get('h2'));
    });

    it('import clears previous data', () => {
      const cs = new ColdStore();
      cs.add(makeRecord({ id: 'old' }));
      cs.import([makeRecord({ id: 'new' })]);

      expect(cs.has('old')).toBe(false);
      expect(cs.has('new')).toBe(true);
      expect(cs.count()).toBe(1);
    });
  });
});

describe('classifyNodeTemperature', () => {
  it('non-host types are always hot', () => {
    expect(classifyNodeTemperature(
      { id: 'svc-1', type: 'service' as any, alive: true, hostname: undefined, os: undefined },
      false,
    )).toBe('hot');
  });

  it('host not confirmed alive is hot', () => {
    expect(classifyNodeTemperature(
      { id: 'h1', type: 'host' as any, alive: false, hostname: undefined, os: undefined },
      false,
    )).toBe('hot');
  });

  it('host with alive=undefined is hot', () => {
    expect(classifyNodeTemperature(
      { id: 'h1', type: 'host' as any, alive: undefined, hostname: undefined, os: undefined },
      false,
    )).toBe('hot');
  });

  it('alive host with hostname is hot', () => {
    expect(classifyNodeTemperature(
      { id: 'h1', type: 'host' as any, alive: true, hostname: 'dc01', os: undefined },
      false,
    )).toBe('hot');
  });

  it('alive host with OS is hot', () => {
    expect(classifyNodeTemperature(
      { id: 'h1', type: 'host' as any, alive: true, hostname: undefined, os: 'Linux' },
      false,
    )).toBe('hot');
  });

  it('alive host with interesting edge is hot', () => {
    expect(classifyNodeTemperature(
      { id: 'h1', type: 'host' as any, alive: true, hostname: undefined, os: undefined },
      true,
    )).toBe('hot');
  });

  it('alive host with no hostname, no OS, no interesting edges is cold', () => {
    expect(classifyNodeTemperature(
      { id: 'h1', type: 'host' as any, alive: true, hostname: undefined, os: undefined },
      false,
    )).toBe('cold');
  });
});

describe('toColdRecord', () => {
  it('maps NodeProperties to ColdNodeRecord', () => {
    const node: NodeProperties = {
      id: 'h1',
      type: 'host' as any,
      label: '10.0.0.5',
      ip: '10.0.0.5',
      hostname: undefined,
      discovered_at: now,
      last_seen_at: later,
      discovered_by: 'agent-1',
      confidence: 1.0,
      alive: true,
    };

    const rec = toColdRecord(node, '10.0.0.0/24');

    expect(rec).toEqual({
      id: 'h1',
      type: 'host',
      label: '10.0.0.5',
      ip: '10.0.0.5',
      hostname: undefined,
      discovered_at: now,
      last_seen_at: later,
      subnet_cidr: '10.0.0.0/24',
      provenance: 'agent-1',
      alive: true,
      confidence: 1.0,
    });
  });

  it('falls back to discovered_at when last_seen_at is missing', () => {
    const node: NodeProperties = {
      id: 'h2',
      type: 'host' as any,
      label: '10.0.0.6',
      discovered_at: now,
      confidence: 1.0,
    };

    const rec = toColdRecord(node);
    expect(rec.last_seen_at).toBe(now);
    expect(rec.subnet_cidr).toBeUndefined();
  });

  it('F04: passes through finding_id and action_id from context', () => {
    const node: NodeProperties = {
      id: 'h3',
      type: 'host' as any,
      label: '10.0.0.7',
      ip: '10.0.0.7',
      discovered_at: now,
      confidence: 1.0,
    };

    const rec = toColdRecord(node, '10.0.0.0/24', { finding_id: 'f-123', action_id: 'a-456' });
    expect(rec.finding_id).toBe('f-123');
    expect(rec.action_id).toBe('a-456');
  });

  it('F04: context is optional — no finding_id/action_id when omitted', () => {
    const node: NodeProperties = {
      id: 'h4',
      type: 'host' as any,
      label: '10.0.0.8',
      discovered_at: now,
      confidence: 1.0,
    };

    const rec = toColdRecord(node, '10.0.0.0/24');
    expect(rec.finding_id).toBeUndefined();
    expect(rec.action_id).toBeUndefined();
  });
});
