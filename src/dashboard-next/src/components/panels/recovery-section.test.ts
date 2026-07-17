import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { PersistenceRecoveryStatus } from '../../lib/types';
import { RecoverySection } from './SettingsPanel';

function recovery(
  overrides: Partial<PersistenceRecoveryStatus> = {},
): PersistenceRecoveryStatus {
  return {
    outcome: 'incomplete',
    source: 'state',
    complete: false,
    writable: false,
    base_checkpoint: 0,
    highest_allocated_seq: 0,
    highest_on_disk_seq: 0,
    highest_contiguous_applied_seq: 0,
    consecutive_persistence_failures: 0,
    journal: {
      enabled: true,
      format_version: 1,
      read: 0,
      attempted: 0,
      applied: 0,
      skipped: 0,
      failed: 0,
      malformed: false,
      preserved: true,
    },
    ...overrides,
  };
}

function render(value: PersistenceRecoveryStatus): string {
  return renderToStaticMarkup(createElement(RecoverySection, {
    recovery: value,
    error: '',
    resolvingMode: null,
    onResolve: async () => {},
  }));
}

describe('RecoverySection', () => {
  it('renders a blocked future state and observed invalid journal version', () => {
    const html = render(recovery({
      state_migration: {
        status: 'blocked',
        supported_state_version: 1,
        supported_journal_version: 1,
        observed_state_version: 2,
        observed_journal_version: 0,
        migration_required: false,
        reason: 'future state version',
      },
    }));

    expect(html).toContain('State format');
    expect(html).toContain('2 / supported 1');
    expect(html).toContain('Journal format');
    expect(html).toContain('0 / supported 1');
    expect(html).toContain('blocked');
  });

  it('renders a completed migration backup and manifest digest', () => {
    const digest = 'a'.repeat(64);
    const html = render(recovery({
      outcome: 'recovered',
      complete: true,
      writable: true,
      state_migration: {
        status: 'migrated',
        supported_state_version: 1,
        supported_journal_version: 1,
        observed_state_version: 0,
        observed_journal_version: 1,
        migration_required: false,
        backup_path: '/tmp/.migration-backups/state-v0-to-v1',
        backup_manifest_sha256: digest,
      },
    }));

    expect(html).toContain('migrated');
    expect(html).toContain('/tmp/.migration-backups/state-v0-to-v1');
    expect(html).toContain('aaaaaaaaaaaa…aaaaaaaa');
  });

  it('renders each unresolved runtime run with its PID and recovery reason', () => {
    const html = render(recovery({
      outcome: 'clean',
      complete: true,
      writable: true,
      runtime_ownership_warnings: [{
        run_id: 'run-reused',
        pid: 4242,
        lifecycle: 'unknown',
        message: 'The recorded PID belongs to a different process.',
      }],
    }));

    expect(html).toContain('Runtime ownership needs review');
    expect(html).toContain('run-reused');
    expect(html).toContain('PID 4242');
    expect(html).toContain('belongs to a different process');
  });

  it('renders ambiguous report IDs and external generation repair warnings', () => {
    const html = render(recovery({
      outcome: 'clean',
      complete: true,
      writable: true,
      artifact_recovery: {
        reports: {
          writable: false,
          uncertain_deletion_ids: ['report-ambiguous'],
          reason: 'ambiguous deletion tombstone',
        },
        generation_warnings: [{
          root: '/tmp/operator-reports',
          namespace: 'report',
          message: 'mirror refresh pending',
        }],
      },
    }));

    expect(html).toContain('Artifact recovery needs review');
    expect(html).toContain('report-ambiguous');
    expect(html).toContain('/tmp/operator-reports');
    expect(html).toContain('mirror refresh pending');
  });
});
