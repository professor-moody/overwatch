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

type SortMode = 'recent' | 'kind' | 'status';
type StatusFilter = 'all' | 'active' | 'stale' | 'expired';
/** Derived "what kind of attention does this credential need" views, toggled
 *  from the count chips — orthogonal to the lifecycle StatusFilter. */
type ViewFilter = 'all' | 'reachable' | 'unverified' | 'expansion' | 'expiring';

export function CredentialsPanel() {
  const graph = useEngagementStore((s) => s.graph);
  const [sortMode, setSortMode] = useState<SortMode>('recent');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [viewFilter, setViewFilter] = useState<ViewFilter>('all');
  const [search, setSearch] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const [searchParams] = useSearchParams();
  const { navigateToGraphTarget, navigateToPanel } = useNavigation();
  const nowMs = Date.now();

  const creds = useMemo(() => {
    return graph.nodes.filter(n => n.type === 'credential');
  }, [graph.nodes]);

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
