import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  buildCompatibilityManifest,
  COMPATIBILITY_ENTRIES,
  OVERWATCH_RELEASE_VERSION,
} from '../compatibility-release.js';

describe('compatibility release contract', () => {
  const semver = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
  const compare = (left: string, right: string) => {
    const leftParts = left.split(/[+-]/, 1)[0].split('.').map(Number);
    const rightParts = right.split(/[+-]/, 1)[0].split('.').map(Number);
    for (let index = 0; index < 3; index += 1) {
      if (leftParts[index] !== rightParts[index]) return leftParts[index] - rightParts[index];
    }
    return 0;
  };

  it('matches package metadata and emits a stable checksummed manifest', () => {
    const packageJson = JSON.parse(
      readFileSync(resolve('package.json'), 'utf8'),
    ) as { version: string };
    const checkedIn = JSON.parse(
      readFileSync(resolve('docs/reference/compatibility-manifest.json'), 'utf8'),
    );

    expect(packageJson.version).toBe(OVERWATCH_RELEASE_VERSION);
    expect(checkedIn).toEqual(buildCompatibilityManifest());
    expect(checkedIn.manifest_sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('uses unique stable IDs and never treats migration readers as timed aliases', () => {
    const ids = COMPATIBILITY_ENTRIES.map(entry => entry.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids.every(id => /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(id))).toBe(true);

    const checkIds = new Set<string>();
    for (const entry of COMPATIBILITY_ENTRIES) {
      expect(entry.compatibility.trim()).not.toBe('');
      expect(entry.canonical.trim()).not.toBe('');
      expect(entry.reason.trim()).not.toBe('');
      if (entry.removal_not_before) expect(entry.removal_not_before).toMatch(semver);
      if (entry.retired_in) expect(entry.retired_in).toMatch(semver);
      if (entry.status === 'migration_required') {
        expect(entry.removal_not_before).toBeUndefined();
        expect(entry.retired_in).toBeUndefined();
        expect(entry.retirement_evidence?.length).toBeGreaterThan(0);
      }
      if (entry.status === 'retired') {
        expect(entry.retired_in).toBeDefined();
        expect(compare(entry.retired_in!, OVERWATCH_RELEASE_VERSION)).toBeLessThanOrEqual(0);
        if (entry.removal_not_before) {
          expect(compare(entry.retired_in!, entry.removal_not_before)).toBeGreaterThanOrEqual(0);
        }
        expect(entry.retirement_evidence?.length).toBeGreaterThan(0);
        expect(entry.evidence_checks?.length).toBeGreaterThan(0);
        expect(new Set(entry.evidence_checks?.map(evidence => evidence.claim))).toEqual(
          new Set(entry.retirement_evidence),
        );
      } else {
        expect(entry.retired_in).toBeUndefined();
      }
      if (entry.status === 'retained' && entry.removal_not_before) {
        expect(compare(OVERWATCH_RELEASE_VERSION, entry.removal_not_before)).toBeLessThan(0);
      }
      for (const evidence of entry.evidence_checks ?? []) {
        expect(checkIds.has(evidence.id), evidence.id).toBe(false);
        checkIds.add(evidence.id);
        expect(entry.retirement_evidence, evidence.id).toContain(evidence.claim);
        const path = resolve(evidence.path);
        expect(existsSync(path), evidence.path).toBe(true);
        expect(readFileSync(path, 'utf8'), evidence.id).toContain(evidence.contains);
      }
    }
  });

  it('has no production call to the retired abortByAgent wrapper', () => {
    const sourceFiles: string[] = [];
    const visit = (directory: string) => {
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const path = resolve(directory, entry.name);
        if (entry.isDirectory()) {
          if (entry.name !== '__tests__') visit(path);
        } else if (/\.(?:ts|tsx)$/.test(entry.name) && entry.name !== 'compatibility-release.ts') {
          sourceFiles.push(path);
        }
      }
    };
    visit(resolve('src'));
    expect(sourceFiles.filter(path => readFileSync(path, 'utf8').includes('.abortByAgent('))).toEqual([]);
  });

  it('retains public identity, parser, playbook, WebSocket, and state migration paths in 0.2', () => {
    const status = new Map(COMPATIBILITY_ENTRIES.map(entry => [entry.id, entry.status]));
    for (const id of [
      'agent-identity-aliases',
      'agent-identity-v1-fields',
      'agent-work-v1-fallback',
      'coordination-owner-aliases',
      'parser-response-aliases',
      'playbook-projection-aliases',
      'dashboard-websocket-v1',
      'state-v0-journal-v1-readers',
      'legacy-playbook-placeholders',
      'session-v1-rollback-lifecycle',
      'dashboard-hash-deep-links',
    ]) {
      expect(status.get(id), id).not.toBe('retired');
    }
  });
});
