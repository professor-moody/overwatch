import type { PersistenceRecoveryStatus } from './types';

export interface RecoveryPresentation {
  tone: 'warning' | 'critical';
  title: string;
  message: string;
  canUseFile: boolean;
  canUseState: boolean;
  restartRequired: boolean;
  blockedReason?: string;
}

export function recoveryPresentation(
  recovery: PersistenceRecoveryStatus | null | undefined,
): RecoveryPresentation | null {
  if (!recovery) return null;
  const config = recovery.config_recovery;
  const persistenceReason = recovery.persistence_reason;
  const persistenceOnlyBlocked = (!recovery.complete || !recovery.writable)
    && !config?.resolution_required;

  if (persistenceReason || persistenceOnlyBlocked) {
    const reason = persistenceReason ?? recovery.reason ?? 'Persistence recovery is incomplete.';
    return {
      tone: 'critical',
      title: 'Durable writes are paused',
      message: `${reason} Target execution and durable mutations remain disabled until recovery completes.`,
      canUseFile: false,
      canUseState: false,
      restartRequired: true,
      blockedReason: reason,
    };
  }

  if (config?.status === 'write_incomplete' || config?.intent_present) {
    const reason = config.reason ?? 'A known configuration write was interrupted.';
    return {
      tone: 'critical',
      title: 'Configuration write recovery is incomplete',
      message: `${reason} Restart Overwatch to complete the recorded write intent; do not choose an authority manually.`,
      canUseFile: false,
      canUseState: false,
      restartRequired: true,
      blockedReason: reason,
    };
  }

  if (config?.status === 'diverged' && config.resolution_required) {
    const hashesAvailable = Boolean(config.file_hash && config.state_hash);
    const canUseFile = hashesAvailable
      && config.file_valid === true
      && config.allowed_resolutions?.includes('use_file') === true;
    const canUseState = hashesAvailable
      && config.allowed_resolutions?.includes('use_state') === true;
    const blockedReason = !hashesAvailable
      ? 'Fresh file and state hashes are required before reconciliation.'
      : !canUseFile && !canUseState
        ? 'No safe reconciliation mode is currently available.'
        : undefined;
    return {
      tone: 'warning',
      title: 'Configuration reconciliation required',
      message: config.reason
        ?? 'The active file, runtime, and durable configuration do not share one revision.',
      canUseFile,
      canUseState,
      restartRequired: false,
      ...(blockedReason ? { blockedReason } : {}),
    };
  }

  const reportRecovery = recovery.artifact_recovery?.reports;
  const generationWarnings = recovery.artifact_recovery?.generation_warnings ?? [];
  if (reportRecovery?.writable === false || generationWarnings.length > 0) {
    const parts: string[] = [];
    if (reportRecovery?.writable === false) {
      parts.push(reportRecovery.reason
        ?? 'The report archive is read-only until its recovery metadata is reconciled.');
    }
    if (generationWarnings.length > 0) {
      parts.push(`${generationWarnings.length} external artifact generation${generationWarnings.length === 1 ? '' : 's'} still need compatibility-mirror repair; their generation pointers remain authoritative.`);
    }
    return {
      tone: 'warning',
      title: 'Artifact recovery needs review',
      message: parts.join(' '),
      canUseFile: false,
      canUseState: false,
      restartRequired: false,
    };
  }

  if (recovery.runtime_ownership_warnings?.length) {
    const count = recovery.runtime_ownership_warnings.length;
    return {
      tone: 'warning',
      title: 'Runtime ownership needs review',
      message: `${count} runtime run${count === 1 ? '' : 's'} could not be safely reclaimed. No unverifiable or reused process was signaled.`,
      canUseFile: false,
      canUseState: false,
      restartRequired: false,
    };
  }

  return null;
}
