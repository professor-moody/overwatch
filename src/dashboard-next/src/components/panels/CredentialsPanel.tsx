import { useState, useMemo } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import { useNavigation } from '../../hooks/useNavigation';
import { cn, formatRelativeTime } from '../../lib/utils';
import type { ExportedNode } from '../../lib/types';

type SortMode = 'recent' | 'kind' | 'status';
type StatusFilter = 'all' | 'active' | 'stale' | 'expired';

const KIND_LABELS: Record<string, string> = {
  plaintext_password: 'Password',
  ntlm_hash: 'NTLM',
  ntlmv1_challenge: 'NTLMv1',
  ntlmv2_challenge: 'NTLMv2',
  kerberos_tgt: 'Kerberos TGT',
  kerberos_tgs: 'Kerberos TGS',
  kerberos_asrep: 'Kerberos ASREPRoast',
  aes256_key: 'AES-256',
  certificate: 'Certificate',
  token: 'Token',
  ssh_key: 'SSH Key',
  oidc_id_token: 'OIDC ID Token',
  oidc_access_token: 'OIDC Access Token',
  oidc_refresh_token: 'OIDC Refresh Token',
  saml_assertion: 'SAML Assertion',
  oauth_client_secret: 'OAuth Secret',
  pat: 'PAT',
  app_password: 'App Password',
  session_cookie: 'Session Cookie',
};

function kindLabel(kind: string | undefined): string {
  return kind ? (KIND_LABELS[kind] ?? kind) : 'Unknown';
}

function statusColor(status: string | undefined): string {
  switch (status) {
    case 'active': return 'text-success bg-success/10';
    case 'stale': return 'text-warning bg-warning/10';
    case 'expired': return 'text-muted-foreground bg-elevated';
    case 'rotated': return 'text-destructive bg-destructive/10';
    default: return 'text-muted-foreground bg-elevated';
  }
}

function kindBadgeColor(kind: string | undefined): string {
  if (!kind) return 'bg-elevated text-muted-foreground';
  if (kind.includes('oidc') || kind.includes('saml') || kind.includes('oauth') || kind === 'pat') {
    return 'bg-accent-dim text-accent';
  }
  if (kind.includes('kerberos') || kind === 'aes256_key' || kind === 'certificate') {
    return 'bg-purple-dim text-purple';
  }
  if (kind === 'ssh_key') return 'bg-elevated text-foreground';
  return 'bg-elevated text-muted-foreground';
}

function isReachable(cred: ExportedNode, edges: { source: string; type: string }[]): boolean {
  return edges.some(
    e => e.source === cred.id &&
      ['VALID_FOR_APP', 'ASSUMES_ROLE', 'VALID_ON', 'AUTHENTICATES_TO'].includes(e.type)
  );
}

export function CredentialsPanel() {
  const graph = useEngagementStore((s) => s.graph);
  const [sortMode, setSortMode] = useState<SortMode>('recent');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [search, setSearch] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const { navigateToGraph } = useNavigation();

  const creds = useMemo(() => {
    return graph.nodes.filter(n => n.type === 'credential');
  }, [graph.nodes]);

  const filtered = useMemo(() => {
    let list = creds;

    if (statusFilter !== 'all') {
      list = list.filter(c => (c.credential_status as string | undefined) === statusFilter);
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
        const ka = kindLabel(a.cred_material_kind as string | undefined);
        const kb = kindLabel(b.cred_material_kind as string | undefined);
        return ka.localeCompare(kb);
      });
    } else if (sortMode === 'status') {
      const rank: Record<string, number> = { active: 0, stale: 1, expired: 2, rotated: 3 };
      sorted.sort((a, b) => {
        const ra = rank[(a.credential_status as string) ?? ''] ?? 4;
        const rb = rank[(b.credential_status as string) ?? ''] ?? 4;
        return ra - rb;
      });
    }
    return sorted;
  }, [creds, sortMode, statusFilter, search]);

  // Kind → count breakdown
  const kindCounts = useMemo(() => {
    const map: Record<string, number> = {};
    for (const c of creds) {
      const k = (c.cred_material_kind as string | undefined) ?? 'unknown';
      map[k] = (map[k] ?? 0) + 1;
    }
    return Object.entries(map).sort((a, b) => b[1] - a[1]);
  }, [creds]);

  const activeCreds = creds.filter(c => (c.credential_status as string | undefined) === 'active').length;
  const reachableCreds = creds.filter(c => isReachable(c, graph.edges as { source: string; type: string }[])).length;

  const toggleReveal = (id: string) => {
    setRevealed(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  return (
    <div className="space-y-4">
      {/* Header + summary bar */}
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">
          Credentials
          <span className="text-muted-foreground font-normal text-sm ml-2">
            ({creds.length} total · {activeCreds} active · {reachableCreds} reachable)
          </span>
        </h2>
      </div>

      {/* Kind breakdown chips */}
      {kindCounts.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {kindCounts.map(([kind, count]) => (
            <button
              key={kind}
              onClick={() => setSearch(kind)}
              className={cn(
                'text-[10px] px-2 py-0.5 rounded-full border transition-colors',
                kindBadgeColor(kind),
                'border-transparent hover:border-border'
              )}
            >
              {kindLabel(kind)} <span className="opacity-60">{count}</span>
            </button>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-2 flex-wrap">
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter by label, kind, user, audience…"
          className="settings-input flex-1 min-w-40"
        />
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value as StatusFilter)}
          className="settings-input w-auto text-xs"
        >
          <option value="all">All statuses</option>
          <option value="active">Active</option>
          <option value="stale">Stale</option>
          <option value="expired">Expired</option>
        </select>
        <select
          value={sortMode}
          onChange={e => setSortMode(e.target.value as SortMode)}
          className="settings-input w-auto text-xs"
        >
          <option value="recent">Newest first</option>
          <option value="kind">By kind</option>
          <option value="status">By status</option>
        </select>
      </div>

      {/* List */}
      {filtered.length === 0 ? (
        <div className="text-center py-12 text-muted-foreground text-sm">
          {creds.length === 0
            ? 'No credentials captured yet. They appear here when agents report credential nodes via findings.'
            : 'No credentials match the current filter.'}
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map(cred => {
            const kind = cred.cred_material_kind as string | undefined;
            const status = cred.credential_status as string | undefined;
            const reachable = isReachable(cred, graph.edges as { source: string; type: string }[]);
            const isExpanded = expandedId === cred.id;
            const isRevealed = revealed.has(cred.id);
            const credValue = cred.cred_value as string | undefined;

            return (
              <div
                key={cred.id}
                className={cn(
                  'bg-surface border rounded-lg p-3 transition-colors',
                  reachable ? 'border-warning/40' : 'border-border'
                )}
              >
                <div className="flex items-center gap-2 flex-wrap">
                  {/* Kind badge */}
                  <span className={cn('text-[10px] px-1.5 py-0.5 rounded font-medium', kindBadgeColor(kind))}>
                    {kindLabel(kind)}
                  </span>

                  {/* Status badge */}
                  {status && (
                    <span className={cn('text-[10px] px-1.5 py-0.5 rounded', statusColor(status))}>
                      {status}
                    </span>
                  )}

                  {/* Reachable indicator */}
                  {reachable && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-warning/10 text-warning font-medium">
                      reachable
                    </span>
                  )}

                  {/* Label */}
                  <span className="text-sm font-medium truncate flex-1 min-w-0">{cred.label || cred.id}</span>

                  {/* Timestamp */}
                  <span className="text-xs text-muted-foreground flex-shrink-0">
                    {cred.discovered_at ? formatRelativeTime(cred.discovered_at) : ''}
                  </span>

                  {/* Expand toggle */}
                  <button
                    onClick={() => setExpandedId(isExpanded ? null : cred.id)}
                    className="text-xs text-muted-foreground hover:text-foreground transition-colors flex-shrink-0"
                  >
                    {isExpanded ? 'less' : 'more'}
                  </button>
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
                      <button
                        onClick={() => navigateToGraph(cred.id, 2)}
                        className="ml-2 px-1.5 py-0.5 rounded bg-accent/10 text-accent text-[10px] hover:bg-accent/20 transition-colors"
                      >
                        View in Graph
                      </button>
                    </DetailRow>

                    {/* Confidence */}
                    <DetailRow label="Confidence">
                      {cred.confidence != null ? `${Math.round((cred.confidence as number) * 100)}%` : '—'}
                    </DetailRow>

                    {/* Expiry */}
                    {!!(cred.cred_token_expires_at || cred.valid_until) && (
                      <DetailRow label="Expires">
                        {String(cred.cred_token_expires_at ?? cred.valid_until)}
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
                          <button
                            onClick={() => toggleReveal(cred.id)}
                            className="text-[10px] px-1.5 py-0.5 rounded bg-elevated hover:bg-border transition-colors flex-shrink-0"
                          >
                            {isRevealed ? 'hide' : 'reveal'}
                          </button>
                          {isRevealed && (
                            <button
                              onClick={() => navigator.clipboard.writeText(credValue)}
                              className="text-[10px] px-1.5 py-0.5 rounded bg-elevated hover:bg-border transition-colors flex-shrink-0"
                            >
                              copy
                            </button>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
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
