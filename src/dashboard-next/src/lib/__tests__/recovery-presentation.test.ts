import { describe, expect, it } from 'vitest';
import type { PersistenceRecoveryStatus } from '../types';
import { recoveryPresentation } from '../recovery-presentation';

function recovery(overrides: Partial<PersistenceRecoveryStatus> = {}): PersistenceRecoveryStatus {
  return {
    outcome: 'clean',
    source: 'state',
    complete: true,
    writable: true,
    base_checkpoint: 4,
    highest_allocated_seq: 4,
    highest_on_disk_seq: 4,
    highest_contiguous_applied_seq: 4,
    consecutive_persistence_failures: 0,
    journal: {
      enabled: true,
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

const diverged = {
  status: 'diverged' as const,
  resolution_required: true,
  intent_present: false,
  file_valid: true,
  file_hash: 'a'.repeat(64),
  state_hash: 'b'.repeat(64),
  allowed_resolutions: ['use_file', 'use_state'] as Array<'use_file' | 'use_state'>,
};

describe('recovery presentation', () => {
  it('hides healthy recovery state', () => {
    expect(recoveryPresentation(recovery())).toBeNull();
  });

  it('keeps config-only divergence reconcilable despite the combined write gate', () => {
    const view = recoveryPresentation(recovery({
      outcome: 'incomplete',
      complete: false,
      writable: false,
      config_recovery: diverged,
    }));
    expect(view).toMatchObject({ tone: 'warning', canUseFile: true, canUseState: true });
  });

  it('offers only durable-state authority when file authority is unsafe', () => {
    const view = recoveryPresentation(recovery({
      outcome: 'incomplete', complete: false, writable: false,
      config_recovery: { ...diverged, file_valid: false, allowed_resolutions: ['use_state'] },
    }));
    expect(view).toMatchObject({ canUseFile: false, canUseState: true });
  });

  it('requires restart for an interrupted write and exposes no authority buttons', () => {
    const view = recoveryPresentation(recovery({
      outcome: 'incomplete', complete: false, writable: false,
      config_recovery: {
        ...diverged,
        status: 'write_incomplete',
        intent_present: true,
      },
    }));
    expect(view).toMatchObject({ tone: 'critical', restartRequired: true, canUseFile: false, canUseState: false });
  });

  it('prioritizes an underlying persistence failure over config reconciliation', () => {
    const view = recoveryPresentation(recovery({
      outcome: 'incomplete', complete: false, writable: false,
      reason: 'sequence gap; config differs',
      persistence_reason: 'sequence gap',
      config_recovery: diverged,
    }));
    expect(view).toMatchObject({ tone: 'critical', canUseFile: false, canUseState: false, blockedReason: 'sequence gap' });
  });

  it('disables both resolutions when optimistic-concurrency hashes are missing', () => {
    const view = recoveryPresentation(recovery({
      outcome: 'incomplete', complete: false, writable: false,
      config_recovery: { ...diverged, file_hash: undefined },
    }));
    expect(view).toMatchObject({ canUseFile: false, canUseState: false });
    expect(view?.blockedReason).toContain('hashes');
  });

  it('shows unresolved runtime ownership without claiming durable writes are blocked', () => {
    const view = recoveryPresentation(recovery({
      runtime_ownership_warnings: [{
        run_id: 'run-unknown',
        pid: 4242,
        lifecycle: 'unknown',
        message: 'PID was reused.',
      }],
    }));
    expect(view).toMatchObject({
      tone: 'warning',
      title: 'Runtime ownership needs review',
      restartRequired: false,
    });
    expect(view?.message).toContain('could not be safely reclaimed');
  });
});
