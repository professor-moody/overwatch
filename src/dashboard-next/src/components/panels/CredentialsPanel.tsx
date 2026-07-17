import { useState, useMemo } from 'react';
import { useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useEngagementStore } from '../../stores/engagement-store';
import { useNavigation } from '../../hooks/useNavigation';
import { cn, formatRelativeTime } from '../../lib/utils';
import {
  getCredentialKindBadgeClass,
  getCredentialKindLabel,
  getCredentialMaterialKind,
  getEffectiveCredentialStatus,
  getCredentialStatusClass,
  isCredentialReachable,
  credentialReachTargets,
  credentialExpiry,
  formatExpiryLabel,
  isCredentialExpansionCandidate,
} from '../../lib/credential-display';
import { ActionButton, DataRow, EmptyPanelState, FilterBar, PageHeader, SegmentedControl, StatusPill } from '../shared/primitives';
import * as api from '../../lib/api';
import type { PlaybookRun } from '../../lib/types';

type SortMode = 'recent' | 'kind' | 'status';
type StatusFilter = 'all' | 'active' | 'stale' | 'expired';
/** Derived "what kind of attention does this credential need" views, toggled
 *  from the count chips — orthogonal to the lifecycle StatusFilter. */
type ViewFilter = 'all' | 'reachable' | 'unverified' | 'expansion' | 'expiring';
type PreparedExecution = { run_id: string; step_id: string; execution: Record<string, unknown> };

export function groupPlaybookRunsByCredential(runs: PlaybookRun[]): Map<string, PlaybookRun[]> {
  const result = new Map<string, PlaybookRun[]>();
  for (const run of [...runs].sort((a, b) => b.updated_at.localeCompare(a.updated_at))) {
    result.set(run.credential_id, [...(result.get(run.credential_id) ?? []), run]);
  }
  return result;
}

export function CredentialsPanel() {
  const graph = useEngagementStore((s) => s.graph);
  const playbookRuns = useEngagementStore((s) => s.playbookRuns);
  const setPlaybookRuns = useEngagementStore((s) => s.setPlaybookRuns);
  const [sortMode, setSortMode] = useState<SortMode>('recent');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [viewFilter, setViewFilter] = useState<ViewFilter>('all');
  const [search, setSearch] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const [playbookBusy, setPlaybookBusy] = useState<string | null>(null);
  const [playbookError, setPlaybookError] = useState<string | null>(null);
  const [preparedExecution, setPreparedExecution] = useState<PreparedExecution | null>(null);
  const [searchParams] = useSearchParams();
  const { navigateToGraphTarget, navigateToPanel } = useNavigation();
  const nowMs = Date.now();

  const creds = useMemo(() => {
    return graph.nodes.filter(n => n.type === 'credential');
  }, [graph.nodes]);

  const playbooksByCredential = useMemo(() => groupPlaybookRunsByCredential(playbookRuns), [playbookRuns]);

  const replacePlaybookRun = (run: PlaybookRun) => {
    setPlaybookRuns([
      ...playbookRuns.filter(candidate => candidate.run_id !== run.run_id),
      run,
    ].sort((a, b) => b.updated_at.localeCompare(a.updated_at)));
  };

  const runPlaybookAction = async (key: string, operation: () => Promise<PlaybookRun | { run: PlaybookRun; execution: Record<string, unknown> }>) => {
    setPlaybookBusy(key);
    setPlaybookError(null);
    try {
      const result = await operation();
      const claim = result as { run?: PlaybookRun; execution?: Record<string, unknown> };
      const run = claim.run?.schema_version === 1 ? claim.run : result as PlaybookRun;
      replacePlaybookRun(run);
      if (claim.execution) {
        setPreparedExecution({
          run_id: run.run_id,
          step_id: String(claim.execution.playbook_step_id ?? ''),
          execution: claim.execution,
        });
      } else {
        setPreparedExecution(current => current?.run_id === run.run_id ? null : current);
      }
    } catch (error) {
      setPlaybookError(error instanceof Error ? error.message : String(error));
    } finally {
      setPlaybookBusy(null);
    }
  };

  useEffect(() => {
    const item = searchParams.get('item');
    if (item) setExpandedId(item);
  }, [searchParams]);

  const filtered = useMemo(() => {
    let list = creds;

    if (statusFilter !== 'all') {
      list = list.filter(c => getEffectiveCredentialStatus(c, nowMs) === statusFilter);
    }

    if (viewFilter === 'reachable') {
      list = list.filter(c => getEffectiveCredentialStatus(c, nowMs) !== 'expired' && isCredentialReachable(c, graph.edges));
    } else if (viewFilter === 'unverified') {
      list = list.filter(c => getEffectiveCredentialStatus(c, nowMs) !== 'expired' && !isCredentialReachable(c, graph.edges));
    } else if (viewFilter === 'expansion') {
      list = list.filter(c => isCredentialExpansionCandidate(c, nowMs, graph.edges));
    } else if (viewFilter === 'expiring') {
      list = list.filter(c => credentialExpiry(c, nowMs)?.urgency === 'soon');
    }

    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(c =>
        c.label?.toLowerCase().includes(q) ||
        String(c.cred_material_kind ?? '').toLowerCase().includes(q) ||
        String(c.cred_user ?? '').toLowerCase().includes(q) ||
        String(c.cred_audience ?? '').toLowerCase().includes(q) ||
        c.id.toLowerCase().includes(q)
      );
    }

    const sorted = [...list];
    if (sortMode === 'recent') {
      sorted.sort((a, b) => {
        const ta = a.discovered_at ? new Date(a.discovered_at).getTime() : 0;
        const tb = b.discovered_at ? new Date(b.discovered_at).getTime() : 0;
        return tb - ta;
      });
    } else if (sortMode === 'kind') {
      sorted.sort((a, b) => {
        const ka = getCredentialKindLabel(a);
        const kb = getCredentialKindLabel(b);
        return ka.localeCompare(kb);
      });
    } else if (sortMode === 'status') {
      const rank: Record<string, number> = { active: 0, stale: 1, expired: 2, rotated: 3 };
      sorted.sort((a, b) => {
        const ra = rank[getEffectiveCredentialStatus(a, nowMs) ?? ''] ?? 4;
        const rb = rank[getEffectiveCredentialStatus(b, nowMs) ?? ''] ?? 4;
        return ra - rb;
      });
    }
    return sorted;
  }, [creds, sortMode, statusFilter, viewFilter, search, graph.edges, nowMs]);

  // Kind → count breakdown
  const kindCounts = useMemo(() => {
    const map: Record<string, number> = {};
    for (const c of creds) {
      const k = getCredentialMaterialKind(c);
      map[k] = (map[k] ?? 0) + 1;
    }
    return Object.entries(map).sort((a, b) => b[1] - a[1]);
  }, [creds]);

  const activeCreds = creds.filter(c => getEffectiveCredentialStatus(c, nowMs) === 'active').length;
  const reachableCreds = creds.filter(c => getEffectiveCredentialStatus(c, nowMs) !== 'expired' && isCredentialReachable(c, graph.edges)).length;
  const unverifiedCreds = creds.filter(c => getEffectiveCredentialStatus(c, nowMs) !== 'expired' && !isCredentialReachable(c, graph.edges)).length;
  const expansionCandidates = creds.filter(c => isCredentialExpansionCandidate(c, nowMs, graph.edges)).length;

  const expiredTokenCreds = useMemo(
    () => creds.filter(c => !!c.cred_token_expires_at && getEffectiveCredentialStatus(c, nowMs) === 'expired'),
    [creds, nowMs],
  );
  // Not-yet-expired but lapsing within the urgency window — act before they die.
  const expiringSoonCreds = useMemo(
    () => creds.filter(c => credentialExpiry(c, nowMs)?.urgency === 'soon'),
    [creds, nowMs],
  );

  const toggleReveal = (id: string) => {
    setRevealed(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  return (
    <div className="space-y-4">
      <PageHeader
        title="Credentials"
        meta={`(${creds.length} total · ${activeCreds} active · ${reachableCreds} reachable)`}
      />

      {/* Derived-view chips double as filters — click to scope the list, click
          again to clear. (Active / Expired tokens mirror the lifecycle filter
          below and stay display-only.) */}
      <div className="flex flex-wrap gap-2 text-xs">
        <CredentialQueueChip label="Active" value={activeCreds} tone="success" />
        <CredentialQueueChip label="Reachable" value={reachableCreds} tone="warning"
          active={viewFilter === 'reachable'} onClick={() => setViewFilter(v => v === 'reachable' ? 'all' : 'reachable')} />
        <CredentialQueueChip label="Unverified" value={unverifiedCreds} tone={unverifiedCreds > 0 ? 'accent' : 'muted'}
          active={viewFilter === 'unverified'} onClick={() => setViewFilter(v => v === 'unverified' ? 'all' : 'unverified')} />
        <CredentialQueueChip label="Expansion candidates" value={expansionCandidates} tone={expansionCandidates > 0 ? 'accent' : 'muted'}
          active={viewFilter === 'expansion'} onClick={() => setViewFilter(v => v === 'expansion' ? 'all' : 'expansion')} />
        <CredentialQueueChip label="Expiring soon" value={expiringSoonCreds.length} tone={expiringSoonCreds.length > 0 ? 'warning' : 'muted'}
          active={viewFilter === 'expiring'} onClick={() => setViewFilter(v => v === 'expiring' ? 'all' : 'expiring')} />
        <CredentialQueueChip label="Expired tokens" value={expiredTokenCreds.length} tone={expiredTokenCreds.length > 0 ? 'warning' : 'muted'} />
      </div>

      {/* Expired token warning banner */}
      {expiredTokenCreds.length > 0 && (
        <div className="px-3 py-2 bg-warning/5 border border-warning/20 rounded text-xs text-warning flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-warning flex-shrink-0" />
          {expiredTokenCreds.length} credential{expiredTokenCreds.length > 1 ? 's' : ''} with expired token(s):{' '}
          {expiredTokenCreds.slice(0, 3).map(c => c.label || c.id).join(', ')}
          {expiredTokenCreds.length > 3 && ` and ${expiredTokenCreds.length - 3} more`}
        </div>
      )}

      {/* Kind breakdown chips */}
      {kindCounts.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {kindCounts.map(([kind, count]) => (
            <button
              key={kind}
              onClick={() => setSearch(kind)}
              className={cn(
                'text-[10px] px-2 py-0.5 rounded-full border transition-colors',
                getCredentialKindBadgeClass(kind),
                'border-transparent hover:border-border'
              )}
            >
              {getCredentialKindLabel(kind)} <span className="opacity-60">{count}</span>
            </button>
          ))}
        </div>
      )}

      {/* Filters */}
      <FilterBar>
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter by label, kind, user, audience…"
          className="settings-input flex-1 min-w-40"
        />
        <SegmentedControl
          value={statusFilter}
          onChange={setStatusFilter}
          options={[
            { value: 'all', label: 'All' },
            { value: 'active', label: 'Active' },
            { value: 'stale', label: 'Stale' },
            { value: 'expired', label: 'Expired' },
          ]}
        />
        <select
          value={sortMode}
          onChange={e => setSortMode(e.target.value as SortMode)}
          className="settings-input w-auto text-xs"
        >
          <option value="recent">Newest first</option>
          <option value="kind">By kind</option>
          <option value="status">By status</option>
        </select>
      </FilterBar>

      {/* List */}
      {filtered.length === 0 ? (
        <EmptyPanelState
          message={creds.length === 0
            ? 'No credentials captured yet. They appear here when agents report credential nodes via findings.'
            : 'No credentials match the current filter.'}
        />
      ) : (
        <div className="space-y-2">
          {filtered.map(cred => {
            const kind = getCredentialMaterialKind(cred);
            const status = getEffectiveCredentialStatus(cred, nowMs);
            const reachTargetCount = status !== 'expired' ? credentialReachTargets(cred, graph.edges).length : 0;
            const reachable = reachTargetCount > 0;
            const isExpanded = expandedId === cred.id;
            const isRevealed = revealed.has(cred.id);
            const credValue = cred.cred_value as string | undefined;
            const playbooks = playbooksByCredential.get(cred.id) ?? [];
            const hasIdentityContext = !!(
              cred.cred_audience ||
              cred.cred_mfa_required != null ||
              String(cred.cred_material_kind || '').includes('oidc') ||
              String(cred.cred_material_kind || '').includes('saml') ||
              String(cred.cred_material_kind || '').includes('session')
            );

            return (
              <DataRow
                key={cred.id}
                className={cn(
                  reachable ? 'border-warning/40' : 'border-border'
                )}
              >
                <div className="flex items-center gap-2 flex-wrap">
                  {/* Kind badge */}
                  <StatusPill className={getCredentialKindBadgeClass(kind)}>{getCredentialKindLabel(kind)}</StatusPill>

                  {/* Status badge */}
                  {status && (
                    <StatusPill className={getCredentialStatusClass(status)}>{status}</StatusPill>
                  )}

                  {playbook && (
                    <StatusPill className={playbook.report_status === 'completed' ? 'text-success bg-success/10' : playbook.status === 'failed' || playbook.status === 'interrupted' ? 'text-warning bg-warning/10' : 'text-accent bg-accent/10'}>
                      playbook · {playbook.status}
                    </StatusPill>
                  )}

                  {/* Reachable indicator — with the target count so coverage is
                      glanceable without expanding (full list under "Reachable via"). */}
                  {reachable && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-warning/10 text-warning font-medium" title={`Reaches ${reachTargetCount} target${reachTargetCount === 1 ? '' : 's'}`}>
                      reachable · {reachTargetCount}
                    </span>
                  )}

                  {/* Label */}
                  <span className="text-sm font-medium truncate flex-1 min-w-0">{cred.label || cred.id}</span>

                  {/* Timestamp */}
                  <span className="text-xs text-muted-foreground flex-shrink-0">
                    {cred.discovered_at ? formatRelativeTime(cred.discovered_at) : ''}
                  </span>

                  {/* Expand toggle */}
                  <ActionButton
                    onClick={() => setExpandedId(isExpanded ? null : cred.id)}
                    variant="ghost"
                  >
                    {isExpanded ? 'less' : 'more'}
                  </ActionButton>
                </div>

                {/* Inline meta: user + audience on same line */}
                {!!(cred.cred_user || cred.cred_audience) && (
                  <div className="mt-1 flex items-center gap-3 text-xs text-muted-foreground flex-wrap">
                    {cred.cred_user != null && (
                      <span>User: <span className="text-foreground font-mono">{String(cred.cred_user)}</span></span>
                    )}
                    {cred.cred_audience != null && (
                      <span>Aud: <span className="text-foreground font-mono truncate max-w-64 inline-block align-bottom">{String(cred.cred_audience)}</span></span>
                    )}
                  </div>
                )}

                {/* Expanded detail */}
                {isExpanded && (
                  <div className="mt-3 pt-3 border-t border-border space-y-2 text-xs">
                    {/* Node ID */}
                    <DetailRow label="Node ID">
                      <span className="font-mono text-accent">{cred.id}</span>
                      <ActionButton
                        onClick={() => navigateToGraphTarget({ kind: 'node', nodeId: cred.id, hops: 2, label: `Credential ${cred.label || cred.id}` })}
                        variant="ghost"
                        size="xs"
                        className="ml-2 text-accent"
                      >
                        View in Graph
                      </ActionButton>
                      {hasIdentityContext && (
                        <ActionButton
                          onClick={() => navigateToPanel('identity', cred.id)}
                          variant="ghost"
                          size="xs"
                          className="text-accent"
                        >
                          Identity
                        </ActionButton>
                      )}
                    </DetailRow>

                    {/* Confidence */}
                    <DetailRow label="Confidence">
                      {cred.confidence != null ? `${Math.round((cred.confidence as number) * 100)}%` : '—'}
                    </DetailRow>

                    {/* Expiry — with relative TTL urgency for token credentials */}
                    {!!(cred.cred_token_expires_at || cred.valid_until) && (
                      <DetailRow label="Expires">
                        {String(cred.cred_token_expires_at ?? cred.valid_until)}
                        {(() => {
                          const exp = credentialExpiry(cred, nowMs);
                          if (!exp) return null;
                          return (
                            <span className={cn('ml-2', exp.urgency === 'ok' ? 'text-muted-foreground' : exp.urgency === 'soon' ? 'text-warning' : 'text-destructive')}>
                              {formatExpiryLabel(exp)}
                            </span>
                          );
                        })()}
                      </DetailRow>
                    )}

                    {/* Scopes */}
                    {Array.isArray(cred.cred_scopes) && (cred.cred_scopes as string[]).length > 0 && (
                      <DetailRow label="Scopes">
                        <span className="font-mono">{(cred.cred_scopes as string[]).join(', ')}</span>
                      </DetailRow>
                    )}

                    {/* MFA */}
                    {cred.cred_mfa_required != null && (
                      <DetailRow label="MFA">
                        {cred.cred_mfa_required ? (
                          cred.cred_mfa_satisfied
                            ? <span className="text-success">required · satisfied</span>
                            : <span className="text-destructive">required · not satisfied</span>
                        ) : <span className="text-muted-foreground">not required</span>}
                      </DetailRow>
                    )}

                    {/* Reachability edges */}
                    {reachable && (
                      <DetailRow label="Reachable via">
                        {graph.edges
                          .filter(e => e.source === cred.id && ['VALID_FOR_APP', 'ASSUMES_ROLE', 'VALID_ON', 'AUTHENTICATES_TO'].includes(e.type as string))
                          .map(e => `${e.type} → ${e.target}`)
                          .join(', ')}
                      </DetailRow>
                    )}

                    {/* Credential value (reveal/hide) */}
                    {credValue && (
                      <div className="flex items-center gap-2">
                        <span className="text-muted-foreground w-24 flex-shrink-0">Value</span>
                        <div className="flex items-center gap-1.5 flex-1 min-w-0">
                          {isRevealed ? (
                            <span className="font-mono text-[10px] break-all text-foreground bg-background rounded p-1 flex-1">
                              {credValue}
                            </span>
                          ) : (
                            <span className="text-muted-foreground">••••••••</span>
                          )}
                          <ActionButton
                            onClick={() => toggleReveal(cred.id)}
                            variant="secondary"
                            size="xs"
                          >
                            {isRevealed ? 'hide' : 'reveal'}
                          </ActionButton>
                          {isRevealed && (
                            <ActionButton
                              onClick={() => navigator.clipboard.writeText(credValue)}
                              variant="secondary"
                              size="xs"
                            >
                              copy
                            </ActionButton>
                          )}
                        </div>
                      </div>
                    )}

                    <div className="mt-3 border-t border-border pt-3 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-medium text-foreground">Credential playbook</span>
                        {playbook?.status === 'interrupted' && (
                          <ActionButton
                            size="xs"
                            variant="secondary"
                            disabled={playbookBusy !== null}
                            onClick={() => void runPlaybookAction(`resume:${playbook.run_id}`, () => api.resumePlaybookRun(playbook.run_id))}
                          >
                            {playbookBusy === `resume:${playbook.run_id}` ? 'resuming…' : 'Resume'}
                          </ActionButton>
                        )}
                      </div>
                      {!playbook ? (
                        <p className="text-muted-foreground">
                          No durable run yet. Deploy a credential or cloud agent, or call the matching expand tool; the resulting run will appear here and survive restarts.
                        </p>
                      ) : (
                        <>
                          <div className="text-muted-foreground">
                            {playbook.definition.title} · {playbook.report_status} · {playbook.steps.filter(step => step.status === 'succeeded' || step.status === 'skipped').length}/{playbook.steps.length} steps complete
                          </div>
                          <div className="space-y-1.5">
                            {playbook.steps.map(step => {
                              const key = `${playbook.run_id}:${step.step_id}`;
                              const canStart = step.status === 'pending' && step.attempts.length === 0;
                              const canRetry = step.status === 'failed' || step.status === 'interrupted';
                              const canSkip = ['pending', 'blocked', 'failed', 'interrupted'].includes(step.status);
                              const activeAttempt = step.attempts.find(attempt => attempt.status === 'running');
                              return (
                                <div key={step.step_id} className="rounded border border-border bg-background/40 p-2">
                                  <div className="flex items-center gap-2">
                                    <StatusPill className={step.status === 'succeeded' ? 'text-success bg-success/10' : step.status === 'blocked' ? 'text-muted-foreground bg-elevated' : step.status === 'failed' || step.status === 'interrupted' ? 'text-warning bg-warning/10' : 'text-accent bg-accent/10'}>
                                      {step.status}
                                    </StatusPill>
                                    <span className="flex-1 text-foreground">{step.ordinal}. {step.description}</span>
                                    {canStart && (
                                      <ActionButton
                                        size="xs"
                                        variant="secondary"
                                        disabled={playbookBusy !== null}
                                        onClick={() => void runPlaybookAction(`start:${key}`, () => api.startPlaybookStep(playbook.run_id, step.step_id))}
                                      >Prepare</ActionButton>
                                    )}
                                    {canRetry && (
                                      <ActionButton
                                        size="xs"
                                        variant="secondary"
                                        disabled={playbookBusy !== null}
                                        onClick={() => void runPlaybookAction(`retry:${key}`, () => api.retryPlaybookStep(playbook.run_id, step.step_id))}
                                      >Prepare retry</ActionButton>
                                    )}
                                    {activeAttempt && (
                                      <ActionButton
                                        size="xs"
                                        variant="ghost"
                                        disabled={playbookBusy !== null}
                                        onClick={() => void runPlaybookAction(`interrupt:${key}`, () => api.interruptPlaybookAttempt(playbook.run_id, step.step_id, 'Prepared dashboard claim released by operator'))}
                                      >Release claim</ActionButton>
                                    )}
                                    {canSkip && (
                                      <ActionButton
                                        size="xs"
                                        variant="ghost"
                                        disabled={playbookBusy !== null}
                                        onClick={() => void runPlaybookAction(`skip:${key}`, () => api.skipPlaybookStep(playbook.run_id, step.step_id, 'Skipped from Credentials'))}
                                      >Skip</ActionButton>
                                    )}
                                  </div>
                                  {step.blocked_reason && <div className="mt-1 text-muted-foreground">{step.blocked_reason}</div>}
                                  {step.attempts.length > 0 && (
                                    <div className="mt-1 text-muted-foreground">
                                      Attempts: {step.attempts.map(attempt => `${attempt.attempt_number} ${attempt.status} · ${attempt.claimed_by_task_id ?? attempt.claimed_via}${attempt.executed_via ? ` → ${attempt.executed_by_task_id ?? attempt.executed_via}` : ''}${attempt.finding_ids.length ? ` · ${attempt.finding_ids.length} finding` : ''}`).join(' · ')}
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        </>
                      )}
                      {playbookError && <div className="text-destructive">{playbookError}</div>}
                      {preparedExecution && (
                        <div className="rounded border border-accent/30 bg-accent/5 p-2 space-y-1">
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-accent">Execution descriptor prepared; the step is now claimed.</span>
                            <ActionButton size="xs" variant="secondary" onClick={() => navigator.clipboard.writeText(JSON.stringify(preparedExecution, null, 2))}>copy</ActionButton>
                          </div>
                          <p className="text-muted-foreground">This button does not execute against the target. Copy the descriptor to the indicated runner or a deployed credential agent. Its stable command identity makes retries safe; release the claim if you will not run it.</p>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </DataRow>
            );
          })}
        </div>
      )}
    </div>
  );
}

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2">
      <span className="text-muted-foreground w-24 flex-shrink-0">{label}</span>
      <div className="flex-1 min-w-0 text-foreground">{children}</div>
    </div>
  );
}

function CredentialQueueChip({
  label,
  value,
  tone,
  onClick,
  active,
}: {
  label: string;
  value: number;
  tone: 'success' | 'warning' | 'accent' | 'muted';
  /** When provided, the chip becomes a toggle filter. */
  onClick?: () => void;
  active?: boolean;
}) {
  const toneClass: Record<typeof tone, string> = {
    success: 'border-success/20 bg-success/5 text-success',
    warning: 'border-warning/20 bg-warning/5 text-warning',
    accent: 'border-accent/20 bg-accent/5 text-accent',
    muted: 'border-border bg-elevated/40 text-muted-foreground',
  };
  const inner = (
    <>
      <span className="font-medium">{label}</span>
      <span className="font-mono">{value}</span>
    </>
  );
  const base = 'inline-flex items-center gap-1.5 rounded border px-2 py-1';
  if (!onClick) {
    return <span className={cn(base, toneClass[tone])}>{inner}</span>;
  }
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(base, 'transition-colors hover:border-current', toneClass[tone], active && 'ring-1 ring-current')}
    >
      {inner}
    </button>
  );
}
