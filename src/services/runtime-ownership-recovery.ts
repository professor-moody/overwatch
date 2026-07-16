import type { GraphEngine } from './graph-engine.js';
import type { PersistedRuntimeRunV1 } from './persisted-state.js';
import {
  defaultProcessIdentityObserver,
  signalVerifiedRuntimeProcess,
  verifyRuntimeProcessIdentity,
  type ProcessIdentityObserver,
  type ProcessIdentityVerification,
} from './process-identity.js';

export interface RuntimeOwnershipRecoveryOptions {
  observer?: ProcessIdentityObserver;
  signal?: (
    run: PersistedRuntimeRunV1,
    signal: NodeJS.Signals,
    observer: ProcessIdentityObserver,
  ) => ProcessIdentityVerification;
  wait?: (milliseconds: number) => void;
  termGraceMs?: number;
  killGraceMs?: number;
}

export interface RuntimeOwnershipRecoverySummary {
  examined: number;
  terminated: number;
  interrupted: number;
  unresolved: number;
}

const TERMINAL = new Set<PersistedRuntimeRunV1['lifecycle']>([
  'completed',
  'failed',
  'interrupted',
  'unknown',
]);

function blockingWait(milliseconds: number): void {
  if (milliseconds <= 0) return;
  const cell = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(cell, 0, 0, milliseconds);
}

export function reconcileRuntimeOwnershipOnStartup(
  engine: GraphEngine,
  options: RuntimeOwnershipRecoveryOptions = {},
): RuntimeOwnershipRecoverySummary {
  const observer = options.observer ?? defaultProcessIdentityObserver;
  const signal = options.signal ?? ((run, sig, identityObserver) =>
    signalVerifiedRuntimeProcess(run, sig, identityObserver));
  const wait = options.wait ?? blockingWait;
  const termGraceMs = options.termGraceMs ?? 250;
  const killGraceMs = options.killGraceMs ?? 250;
  const summary: RuntimeOwnershipRecoverySummary = {
    examined: 0,
    terminated: 0,
    interrupted: 0,
    unresolved: 0,
  };

  if (!engine.isPersistenceWritable()) return summary;
  for (const run of engine.getRuntimeRuns()) {
    if (TERMINAL.has(run.lifecycle)) continue;
    summary.examined++;
    if (!run.pid) {
      const reservedWithoutIdentity = run.lifecycle === 'reserved' && !run.ownership_acknowledged_at;
      engine.reconcileRuntimeRunOnStartup({
        run_id: run.run_id,
        outcome: reservedWithoutIdentity ? 'interrupted' : 'unknown',
        reason: reservedWithoutIdentity
          ? 'the durable reservation never received a supervisor identity, so no managed target could be acknowledged'
          : 'the durable runtime record has no supervisor pid',
        ...(reservedWithoutIdentity
          ? {}
          : { recovery_warning: 'Runtime ownership cannot be verified because the supervisor pid is missing.' }),
      });
      if (reservedWithoutIdentity) summary.interrupted++;
      else summary.unresolved++;
      continue;
    }
    if (run.ownership_mode !== 'managed_supervisor' || run.signal_scope === 'none') {
      const warning = run.ownership_mode === 'external_adopted'
        ? 'The process was adopted from outside the managed supervisor and cannot be safely signaled after restart.'
        : 'The legacy runtime record does not prove managed supervisor ownership and cannot be safely signaled.';
      engine.reconcileRuntimeRunOnStartup({
        run_id: run.run_id,
        outcome: 'unknown',
        reason: warning,
        recovery_warning: warning,
      });
      summary.unresolved++;
      continue;
    }

    let verification = verifyRuntimeProcessIdentity(run, observer);
    if (verification.status === 'verified') {
      try {
        verification = signal(run, 'SIGTERM', observer);
      } catch (error) {
        verification = verifyRuntimeProcessIdentity(run, observer);
        if (verification.status !== 'not_running') {
          const warning = `The recorded supervisor could not be signaled safely: ${
            error instanceof Error ? error.message : String(error)
          }`;
          engine.reconcileRuntimeRunOnStartup({
            run_id: run.run_id,
            outcome: 'unknown',
            reason: warning,
            recovery_warning: warning,
          });
          summary.unresolved++;
          continue;
        }
      }
      if (verification.status === 'verified') {
        wait(termGraceMs);
        verification = verifyRuntimeProcessIdentity(run, observer);
      }
      if (verification.status === 'verified') {
        try {
          verification = signal(run, 'SIGKILL', observer);
        } catch (error) {
          verification = verifyRuntimeProcessIdentity(run, observer);
          if (verification.status !== 'not_running') {
            const warning = `The recorded supervisor could not be force-terminated safely: ${
              error instanceof Error ? error.message : String(error)
            }`;
            engine.reconcileRuntimeRunOnStartup({
              run_id: run.run_id,
              outcome: 'unknown',
              reason: warning,
              recovery_warning: warning,
            });
            summary.unresolved++;
            continue;
          }
        }
        if (verification.status === 'verified') {
          wait(killGraceMs);
          verification = verifyRuntimeProcessIdentity(run, observer);
        }
      }
      if (verification.status === 'not_running') {
        engine.reconcileRuntimeRunOnStartup({
          run_id: run.run_id,
          outcome: 'interrupted',
          reason: 'the verified orphan process group was terminated before target execution resumed',
        });
        summary.terminated++;
        summary.interrupted++;
        continue;
      }
    }

    if (verification.status === 'not_running') {
      engine.reconcileRuntimeRunOnStartup({
        run_id: run.run_id,
        outcome: 'interrupted',
        reason: 'the previously owned supervisor is no longer running',
      });
      summary.interrupted++;
      continue;
    }
    const warning = verification.status === 'pid_reused'
      ? 'The recorded supervisor PID now belongs to a different physical process; it was not signaled.'
      : 'The recorded supervisor is alive but its physical process identity cannot be verified; it was not signaled.';
    engine.reconcileRuntimeRunOnStartup({
      run_id: run.run_id,
      outcome: 'unknown',
      reason: warning,
      recovery_warning: warning,
    });
    summary.unresolved++;
  }
  return summary;
}
