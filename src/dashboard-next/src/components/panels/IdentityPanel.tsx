import { useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useEngagementStore } from '../../stores/engagement-store';
import { useNavigation } from '../../hooks/useNavigation';
import type { ExportedNode, ExportedEdge } from '../../lib/types';
import { ActionButton, DataRow, EmptyPanelState, PageHeader, PanelSection, StatusPill } from '../shared/primitives';
import { GraphNodeLinks } from '../shared/GraphNodeLinks';
import { cn } from '../../lib/utils';

interface IdpGroup {
  idp: ExportedNode;
  apps: ExportedNode[];
  principals: ExportedNode[];
  federatedDomains: string[];
}

export interface IdentityTokenSummary {
  id: string;
  label: string;
  kind: string;
  user?: string;
  audience?: string;
  scopes: string[];
  expires?: string;
  status: 'usable' | 'MFA satisfied' | 'MFA blocked';
  tone: 'success' | 'warning' | 'muted';
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
        .map(e => e.source),
    );
    const groupApps = apps.filter(a => idpAppIds.has(a.id) || asString(a.idp_id) === idp.id);
    const appIdSet = new Set(groupApps.map(a => a.id));
    const idpKind = asString(idp.idp_kind);
    const idpTenant = asString(idp.tenant_id);
    const principalsForIdp = principals.filter(p => {
      if (asString(p.idp_id) === idp.id) return true;
      if (trustEdges.some(e => e.source === p.id && appIdSet.has(e.target))) return true;
      return !!(idpKind && idpTenant && p.id.includes(`${idpKind}-${idpTenant}`));
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

export function identityTokenSummaries(nodes: ExportedNode[]): IdentityTokenSummary[] {
  return tokenCredentials(nodes).map(node => {
    const scopes = Array.isArray(node.cred_scopes) ? (node.cred_scopes as string[]) : [];
    let status: IdentityTokenSummary['status'] = 'usable';
    let tone: IdentityTokenSummary['tone'] = 'muted';
    if (node.cred_mfa_satisfied === true) {
      status = 'MFA satisfied';
      tone = 'success';
    } else if (node.cred_mfa_required === true) {
      status = 'MFA blocked';
      tone = 'warning';
    }
    return {
      id: node.id,
      label: node.label || node.id,
      kind: asString(node.cred_material_kind) || 'token',
      user: asString(node.cred_user),
      audience: asString(node.cred_audience),
      scopes,
      expires: asString(node.cred_token_expires_at),
      status,
      tone,
    };
  });
}

export function IdentityPanel() {
  const graph = useEngagementStore((s) => s.graph);
  const initialized = useEngagementStore((s) => s.initialized);
  const [searchParams] = useSearchParams();
  const selectedItem = searchParams.get('item');
  const { navigateToPanel } = useNavigation();

  const groups = useMemo(() => groupByIdp(graph.nodes, graph.edges), [graph.nodes, graph.edges]);
  const tokens = useMemo(() => identityTokenSummaries(graph.nodes), [graph.nodes]);
  const appCount = groups.reduce((sum, group) => sum + group.apps.length, 0);
  const principalCount = groups.reduce((sum, group) => sum + group.principals.length, 0);

  if (!initialized) {
    return <EmptyPanelState message="Waiting for engagement state..." />;
  }

  if (groups.length === 0 && tokens.length === 0) {
    return <EmptyPanelState message="No identity-tier data yet." />;
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Identity"
        meta={`(${groups.length} IdPs · ${appCount} apps · ${principalCount} principals · ${tokens.length} token refs)`}
      />

      <PanelSection title="Identity Providers" meta={groups.length}>
        {groups.length === 0 ? (
          <EmptyPanelState message="No IdP nodes in the graph yet." />
        ) : (
          <div className="space-y-2">
            {groups.map(group => <IdpRow key={group.idp.id} group={group} selectedItem={selectedItem} />)}
          </div>
        )}
      </PanelSection>

      <PanelSection title="Token Relationships" meta={tokens.length}>
        {tokens.length === 0 ? (
          <EmptyPanelState message="No token credentials reference identity providers yet." />
        ) : (
          <div className="space-y-2">
            {tokens.slice(0, 50).map(token => (
              <DataRow key={token.id} className={cn(selectedItem === token.id && 'border-accent/60 bg-accent/5')}>
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <StatusPill tone="accent">{token.kind}</StatusPill>
                      <StatusPill tone={token.tone}>{token.status}</StatusPill>
                      <span className="text-sm font-medium truncate">{token.label}</span>
                    </div>
                    <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
                      {token.user && <span>User <span className="font-mono text-foreground">{token.user}</span></span>}
                      {token.audience && <span>Aud <span className="font-mono text-foreground">{token.audience}</span></span>}
                      {token.expires && <span>Expires <span className="font-mono text-foreground">{token.expires}</span></span>}
                    </div>
                    {token.scopes.length > 0 && (
                      <div className="mt-1 text-xs text-muted-foreground">
                        Scopes <span className="font-mono text-foreground">{token.scopes.slice(0, 6).join(' ')}</span>
                      </div>
                    )}
                  </div>
                  <div className="flex shrink-0 items-center gap-1">
                    <GraphNodeLinks
                      nodeId={token.id}
                      graphTarget={{ kind: 'evidence', nodeId: token.id, label: `Identity token ${token.label}` }}
                    />
                    <ActionButton onClick={() => navigateToPanel('credentials', token.id)} variant="secondary" size="xs">
                      Credential
                    </ActionButton>
                  </div>
                </div>
              </DataRow>
            ))}
          </div>
        )}
      </PanelSection>
    </div>
  );
}

function IdpRow({ group, selectedItem }: { group: IdpGroup; selectedItem: string | null }) {
  const { idp, apps, principals, federatedDomains } = group;
  const idpKind = asString(idp.idp_kind) || 'idp';
  return (
    <DataRow className={cn(selectedItem === idp.id && 'border-accent/60 bg-accent/5')}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <StatusPill tone="muted">{idpKind}</StatusPill>
            <span className="text-sm font-medium truncate">{idp.label}</span>
            {asString(idp.tenant_id) && <span className="font-mono text-xs text-muted-foreground">{asString(idp.tenant_id)}</span>}
            {asString(idp.federation_mode) && <StatusPill tone="purple">{asString(idp.federation_mode)}</StatusPill>}
          </div>
          <div className="mt-2 grid grid-cols-1 gap-2 text-xs md:grid-cols-3">
            <Fact label="Apps" value={String(apps.length)} />
            <Fact label="Principals" value={String(principals.length)} />
            <Fact label="Federates With" value={federatedDomains.length > 0 ? federatedDomains.join(', ') : '-'} />
          </div>
          <div className="mt-2 grid gap-1 text-xs text-muted-foreground">
            <div>
              Apps{' '}
              <span className="font-mono text-foreground">
                {apps.length > 0 ? apps.slice(0, 3).map(app => asString(app.app_name) || app.label).join(', ') : 'none'}
              </span>
            </div>
            <div>
              Principals{' '}
              <span className="font-mono text-foreground">
                {principals.length > 0 ? principals.slice(0, 3).map(principal => asString(principal.username) || principal.label).join(', ') : 'none'}
              </span>
            </div>
          </div>
          <EntityList title="Apps" items={apps} labelFor={node => asString(node.app_name) || node.label} />
          <EntityList title="Principals" items={principals} labelFor={node => asString(node.username) || node.label} />
        </div>
        <GraphNodeLinks nodeId={idp.id} graphTarget={{ kind: 'node', nodeId: idp.id, hops: 2, label: `Identity provider ${idp.label}` }} />
      </div>
    </DataRow>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 rounded border border-border bg-background/45 px-2 py-1.5">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="truncate font-mono text-xs text-foreground">{value}</div>
    </div>
  );
}

function EntityList({
  title,
  items,
  labelFor,
}: {
  title: string;
  items: ExportedNode[];
  labelFor: (node: ExportedNode) => string;
}) {
  if (items.length === 0) return null;
  return (
    <details className="mt-2">
      <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">{title}</summary>
      <div className="mt-2 flex flex-wrap gap-1">
        {items.slice(0, 20).map(node => (
          <GraphNodeLinks
            key={node.id}
            nodeId={node.id}
            label={labelFor(node)}
            graphTarget={{ kind: 'node', nodeId: node.id, hops: 2, label: `${title.slice(0, -1)} ${labelFor(node)}` }}
          />
        ))}
        {items.length > 20 && <span className="text-[10px] text-muted-foreground">+{items.length - 20} more</span>}
      </div>
    </details>
  );
}
