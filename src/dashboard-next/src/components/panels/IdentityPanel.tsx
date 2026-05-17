// ============================================================
// Identity Panel (Phase 4 enterprise readiness).
//
// Renders the SSO / IdP layer of the engagement graph in a dedicated
// surface so the identity tier doesn't get lost inside the giant graph
// view. Sources data from the existing engagement store — no new API
// endpoint — by filtering nodes/edges to identity types and rendering:
//   - IdPs (Okta orgs, Entra tenants, …) with federation_mode + tenant
//   - Apps registered with each IdP
//   - Federated principals with MFA factor counts
//   - Captured token credentials (audience, scopes, expiry, MFA flags)
// ============================================================

import { useMemo, useState } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import type { ExportedNode, ExportedEdge } from '../../lib/types';
import { EmptyState } from '../shared';

interface IdpGroup {
  idp: ExportedNode;
  apps: ExportedNode[];
  principals: ExportedNode[];
  federatedDomains: string[];
}

function asString(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

export function groupByIdp(nodes: ExportedNode[], edges: ExportedEdge[]): IdpGroup[] {
  const idps = nodes.filter(n => n.type === 'idp');
  const apps = nodes.filter(n => n.type === 'idp_application');
  const principals = nodes.filter(n => n.type === 'idp_principal');
  const fedEdges = edges.filter(e => e.type === 'FEDERATES_WITH');
  const trustEdges = edges.filter(e => e.type === 'TRUSTS' || e.type === 'ASSIGNED_TO_APP');

  return idps.map(idp => {
    const idpAppIds = new Set(
      trustEdges
        .filter(e => e.target === idp.id)
        .map(e => e.source)
    );
    const groupApps = apps.filter(a =>
      idpAppIds.has(a.id) ||
      asString(a.idp_id) === idp.id
    );
    const appIdSet = new Set(groupApps.map(a => a.id));
    const idpKind = asString(idp.idp_kind);
    const idpTenant = asString(idp.tenant_id);
    const principalsForIdp = principals.filter(p => {
      if (asString(p.idp_id) === idp.id) return true;
      const assigned = trustEdges.some(e => e.source === p.id && appIdSet.has(e.target));
      if (assigned) return true;
      // Heuristic fallback: principal id encodes the same IdP kind/tenant.
      if (idpKind && idpTenant && p.id.includes(`${idpKind}-${idpTenant}`)) return true;
      return false;
    });
    const federatedDomains = fedEdges
      .filter(e => e.source === idp.id || e.target === idp.id)
      .map(e => {
        const peerId = e.source === idp.id ? e.target : e.source;
        const peer = nodes.find(n => n.id === peerId);
        return peer ? asString(peer.domain_name) : undefined;
      })
      .filter((d): d is string => !!d);

    return { idp, apps: groupApps, principals: principalsForIdp, federatedDomains };
  });
}

export function tokenCredentials(nodes: ExportedNode[]): ExportedNode[] {
  const TOKEN_KINDS = new Set([
    'oidc_id_token', 'oidc_access_token', 'oidc_refresh_token',
    'saml_assertion', 'oauth_client_secret', 'pat', 'app_password', 'session_cookie',
  ]);
  return nodes.filter(n => {
    if (n.type !== 'credential') return false;
    const kind = asString(n.cred_material_kind);
    return !!kind && TOKEN_KINDS.has(kind);
  });
}

function tokenStatusLabel(node: ExportedNode): string {
  if (node.cred_mfa_satisfied === true) return 'MFA satisfied';
  if (node.cred_mfa_required === true) return 'MFA blocked';
  return 'usable';
}

function tokenStatusClass(node: ExportedNode): string {
  const label = tokenStatusLabel(node);
  if (label === 'MFA blocked') return 'text-warning';
  if (label === 'MFA satisfied') return 'text-success';
  return 'text-muted-foreground';
}

export function IdentityPanel() {
  const graph = useEngagementStore((s) => s.graph);
  const initialized = useEngagementStore((s) => s.initialized);

  const groups = useMemo(() => groupByIdp(graph.nodes, graph.edges), [graph.nodes, graph.edges]);
  const tokens = useMemo(() => tokenCredentials(graph.nodes), [graph.nodes]);

  if (!initialized) {
    return <EmptyState title="Loading" description="Waiting for engagement state…" />;
  }

  if (groups.length === 0 && tokens.length === 0) {
    return (
      <EmptyState
        title="No identity-tier data yet"
        description="Run an SSO/cloud-identity parser (roadrecon, okta-cli, jwt-tool, microburst, aadinternals, evilginx) or ingest_azurehound to populate this panel."
      />
    );
  }

  return (
    <div className="space-y-6 p-4">
      <section>
        <h2 className="text-lg font-semibold mb-3">Identity Providers</h2>
        {groups.length === 0 ? (
          <p className="text-sm text-muted-foreground">No IdP nodes in the graph yet.</p>
        ) : (
          <div className="space-y-3">
            {groups.map(({ idp, apps, principals, federatedDomains }) => {
              return (
                <div key={idp.id} className="rounded border border-elevated bg-card p-3">
                  <div className="flex items-center justify-between mb-2">
                    <div>
                      <span className="font-mono text-xs uppercase rounded bg-elevated px-1.5 py-0.5 mr-2">
                        {asString(idp.idp_kind) ?? 'idp'}
                      </span>
                      <span className="font-medium">{idp.label}</span>
                      {asString(idp.tenant_id) ? (
                        <span className="ml-2 text-xs text-muted-foreground font-mono">{asString(idp.tenant_id)}</span>
                      ) : null}
                    </div>
                    {asString(idp.federation_mode) ? (
                      <span className="text-xs text-muted-foreground">
                        federation: {asString(idp.federation_mode)}
                      </span>
                    ) : null}
                  </div>
                  <div className="grid grid-cols-3 gap-3 text-sm">
                    <div>
                      <div className="text-xs text-muted-foreground">Apps</div>
                      <div className="font-mono">{apps.length}</div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground">Principals</div>
                      <div className="font-mono">{principals.length}</div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground">Federates with</div>
                      <div className="font-mono text-xs">
                        {federatedDomains.length > 0 ? federatedDomains.join(', ') : '—'}
                      </div>
                    </div>
                  </div>
                  <div className="mt-2 grid gap-1 text-xs text-muted-foreground">
                    <div>
                      Apps:{' '}
                      <span className="font-mono text-foreground">
                        {apps.length > 0 ? apps.slice(0, 3).map(a => asString(a.app_name) ?? a.label).join(', ') : 'none'}
                      </span>
                    </div>
                    <div>
                      Principals:{' '}
                      <span className="font-mono text-foreground">
                        {principals.length > 0 ? principals.slice(0, 3).map(p => asString(p.username) ?? p.label).join(', ') : 'none'}
                      </span>
                    </div>
                  </div>
                  {apps.length > 0 ? (
                    <details className="mt-2">
                      <summary className="text-xs text-muted-foreground cursor-pointer hover:text-foreground">
                        Show apps
                      </summary>
                      <ul className="mt-2 space-y-1 text-xs font-mono">
                        {apps.slice(0, 20).map(a => (
                          <li key={a.id} className="flex justify-between">
                            <span>{asString(a.app_name) ?? a.label}</span>
                            <span className="text-muted-foreground">
                              {a.app_mfa_required ? 'MFA req' : ''}
                              {asString(a.audience) ? ` · aud:${asString(a.audience)!.slice(0, 30)}` : ''}
                            </span>
                          </li>
                        ))}
                        {apps.length > 20 ? <li className="text-muted-foreground">+ {apps.length - 20} more</li> : null}
                      </ul>
                    </details>
                  ) : null}
                  {principals.length > 0 ? (
                    <details className="mt-2">
                      <summary className="text-xs text-muted-foreground cursor-pointer hover:text-foreground">
                        Show principals
                      </summary>
                      <ul className="mt-2 space-y-1 text-xs font-mono">
                        {principals.slice(0, 20).map(p => {
                          const factors = Array.isArray(p.mfa_factors) ? (p.mfa_factors as string[]) : [];
                          return (
                            <li key={p.id} className="flex justify-between gap-3">
                              <span className="truncate">{asString(p.username) ?? p.label}</span>
                              <span className="text-muted-foreground shrink-0">
                                {factors.length > 0 ? `MFA: ${factors.slice(0, 2).join(', ')}` : 'MFA: unknown'}
                              </span>
                            </li>
                          );
                        })}
                        {principals.length > 20 ? <li className="text-muted-foreground">+ {principals.length - 20} more</li> : null}
                      </ul>
                    </details>
                  ) : null}
                </div>
              );
            })}
          </div>
        )}
      </section>

      <section>
        <h2 className="text-lg font-semibold mb-3">Captured Tokens</h2>
        {tokens.length === 0 ? (
          <p className="text-sm text-muted-foreground">No token credentials captured yet.</p>
        ) : (
          <div className="space-y-2">
            {tokens.slice(0, 50).map(t => {
              const expiry = asString(t.cred_token_expires_at);
              const scopes = Array.isArray(t.cred_scopes) ? (t.cred_scopes as string[]) : [];
              return (
                <div key={t.id} className="rounded border border-elevated bg-card p-2 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs">{asString(t.cred_material_kind) ?? 'token'}</span>
                    <span className={`text-xs ${tokenStatusClass(t)}`}>{tokenStatusLabel(t)}</span>
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {asString(t.cred_user) ? <>user: <span className="font-mono">{asString(t.cred_user)}</span> · </> : null}
                    {asString(t.cred_audience) ? <>aud: <span className="font-mono">{asString(t.cred_audience)!.slice(0, 60)}</span></> : null}
                  </div>
                  {scopes.length > 0 ? (
                    <div className="text-xs text-muted-foreground mt-1">
                      scopes: <span className="font-mono">{scopes.slice(0, 6).join(' ')}</span>
                    </div>
                  ) : null}
                  {expiry ? (
                    <div className="text-xs text-muted-foreground mt-1">
                      expires: <span className="font-mono">{expiry}</span>
                    </div>
                  ) : null}
                  <CredValueRow value={asString(t.cred_value)} />
                </div>
              );
            })}
            {tokens.length > 50 ? (
              <p className="text-xs text-muted-foreground">+ {tokens.length - 50} more not shown</p>
            ) : null}
          </div>
        )}
      </section>
    </div>
  );
}

/**
 * Reveal-on-click cred_value display with copy-to-clipboard. Operators
 * need to be able to use captured credentials themselves; the dashboard
 * is the natural surface to retrieve them. Hidden by default so a
 * shoulder-surfer or screen-share doesn't leak the value casually.
 */
function CredValueRow({ value }: { value: string | undefined }) {
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);

  if (!value) return null;

  const display = revealed ? value : '••••••••••••••••';
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* clipboard blocked — operator can still reveal + select */ }
  };

  return (
    <div className="text-xs text-muted-foreground mt-1 flex items-center gap-2">
      <span>value:</span>
      <span className="font-mono bg-elevated px-1.5 py-0.5 rounded text-foreground select-all">{display}</span>
      <button
        onClick={() => setRevealed(v => !v)}
        className="text-accent hover:underline text-[10px]"
      >
        {revealed ? 'hide' : 'reveal'}
      </button>
      <button
        onClick={copy}
        className="text-accent hover:underline text-[10px]"
      >
        {copied ? 'copied!' : 'copy'}
      </button>
    </div>
  );
}
