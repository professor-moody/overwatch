import { useMemo, useState } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import { useNavigation } from '../../hooks/useNavigation';
import { evidenceImageUrl } from '../../lib/api';
import { AuthenticatedImage } from '../shared/AuthenticatedImage';
import type { ExportedNode } from '../../lib/types';
import { ActionButton, DataRow, EmptyPanelState, FilterBar, PageHeader, SegmentedControl, StatusPill } from '../shared/primitives';
import { DeploySelectedModal } from './DeploySelectedModal';

// Recon (OSINT) workspace. The external-recon surface lives in the graph
// (subdomain / webapp / asn / organization / email nodes) but was only legible in
// the graph viewport or raw tool output. This lists it as readable, assessable
// tables — one segment per asset class — deep-linking each row back into the graph,
// with multi-select fan-out to deploy agents across a selection.

type Segment = 'subdomains' | 'webapps' | 'infra' | 'people';
type SubView = 'all' | 'resolved' | 'takeover';

// Cap rows rendered per (expanded) group so a domain with thousands of subdomains
// can't blow up the DOM; the filter/collapse narrow the rest.
const GROUP_RENDER_CAP = 200;

// --- shared accessors ---
function strArr(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}
function str(v: unknown): string | undefined {
  return typeof v === 'string' && v ? v : undefined;
}
function num(v: unknown): number | undefined {
  return typeof v === 'number' ? v : undefined;
}

// --- subdomain helpers ---
function subName(n: ExportedNode): string {
  return str(n.subdomain_name) || n.label || n.id;
}
const NO_DOMAIN = '(no parent domain)';
function parentDomain(n: ExportedNode): string {
  if (str(n.parent_domain)) return n.parent_domain as string;
  // Fallback only when the name looks like a hostname. An IP-like or bare-label name
  // would otherwise derive nonsense (e.g. 192.168.1.1 → "1.1"), so bucket those.
  const name = subName(n);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(name) || name.includes(':')) return NO_DOMAIN;
  const parts = name.split('.');
  return parts.length >= 2 ? parts.slice(-2).join('.') : NO_DOMAIN;
}
const resolvedIps = (n: ExportedNode) => strArr(n.resolved_ips);
const dnsRecords = (n: ExportedNode) => strArr(n.dns_records);
const isTakeover = (n: ExportedNode) => n.takeover_candidate === true;

// Shared multi-select surface handed to every segment.
interface SelectProps {
  selected: Set<string>;
  onToggle: (id: string) => void;
  onSelectMany: (ids: string[], on: boolean) => void;
}

function RowCheckbox({ id, selected, onToggle }: { id: string; selected: Set<string>; onToggle: (id: string) => void }) {
  return (
    <input
      type="checkbox"
      checked={selected.has(id)}
      onChange={() => onToggle(id)}
      onClick={e => e.stopPropagation()}
      className="mt-0.5 flex-shrink-0 accent-accent"
    />
  );
}

export function ReconPanel() {
  const graph = useEngagementStore(s => s.graph);
  const graphVersion = useEngagementStore(s => s.graphVersion);
  const { navigateToGraph } = useNavigation();
  const [segment, setSegment] = useState<Segment>('subdomains');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [fanOutOpen, setFanOutOpen] = useState(false);

  const byType = useMemo(() => {
    const m: Record<string, ExportedNode[]> = { subdomain: [], webapp: [], asn: [], organization: [], email: [] };
    for (const n of graph.nodes) {
      if (n.type && m[n.type]) m[n.type].push(n);
    }
    return m;
  }, [graph.nodes, graphVersion]);

  const counts = {
    subdomains: byType.subdomain.length,
    webapps: byType.webapp.length,
    infra: byType.asn.length + byType.organization.length,
    people: byType.email.length,
  };

  const toggleSelect = (id: string) => setSelected(prev => {
    const next = new Set(prev);
    next.has(id) ? next.delete(id) : next.add(id);
    return next;
  });
  const selectMany = (ids: string[], on: boolean) => setSelected(prev => {
    const next = new Set(prev);
    for (const id of ids) on ? next.add(id) : next.delete(id);
    return next;
  });
  const clearSelection = () => setSelected(new Set());
  const selectedIds = useMemo(() => [...selected], [selected]);

  const selectProps: SelectProps = { selected, onToggle: toggleSelect, onSelectMany: selectMany };

  return (
    <div className="space-y-4">
      <PageHeader
        title="Recon"
        meta={`(${counts.subdomains + counts.webapps + counts.infra + counts.people} assets)`}
        actions={(
          <FilterBar>
            <SegmentedControl
              value={segment}
              onChange={setSegment}
              options={[
                { value: 'subdomains', label: 'Subdomains', count: counts.subdomains },
                { value: 'webapps', label: 'Web hosts', count: counts.webapps },
                { value: 'infra', label: 'Infra', count: counts.infra },
                { value: 'people', label: 'People', count: counts.people },
              ]}
            />
          </FilterBar>
        )}
      />

      {selected.size > 0 && (
        <div className="flex items-center gap-3 rounded-md border border-accent/40 bg-accent/5 px-3 py-2">
          <span className="text-xs text-foreground">{selected.size} selected</span>
          <ActionButton onClick={() => setFanOutOpen(true)} variant="purple" size="xs">
            Deploy agents across selection
          </ActionButton>
          <ActionButton onClick={clearSelection} variant="ghost" size="xs">Clear</ActionButton>
        </div>
      )}

      {segment === 'subdomains' && <SubdomainsSegment subs={byType.subdomain} navigate={navigateToGraph} {...selectProps} />}
      {segment === 'webapps' && <WebHostsSegment webapps={byType.webapp} edges={graph.edges} navigate={navigateToGraph} {...selectProps} />}
      {segment === 'infra' && <InfraSegment asns={byType.asn} orgs={byType.organization} navigate={navigateToGraph} {...selectProps} />}
      {segment === 'people' && <PeopleSegment emails={byType.email} navigate={navigateToGraph} {...selectProps} />}

      {fanOutOpen && (
        <DeploySelectedModal
          nodeIds={selectedIds}
          onClose={() => setFanOutOpen(false)}
          onDeployed={() => { setFanOutOpen(false); clearSelection(); }}
        />
      )}
    </div>
  );
}

// ---- Subdomains (grouped by apex domain) ----
function SubdomainsSegment({ subs, navigate, selected, onToggle, onSelectMany }: SelectProps & {
  subs: ExportedNode[];
  navigate: (id: string, hops: number) => void;
}) {
  const [view, setView] = useState<SubView>('all');
  const [search, setSearch] = useState('');
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const stats = useMemo(() => ({
    total: subs.length,
    resolved: subs.filter(n => resolvedIps(n).length > 0).length,
    takeover: subs.filter(isTakeover).length,
  }), [subs]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return subs.filter(n => {
      if (view === 'resolved' && resolvedIps(n).length === 0) return false;
      if (view === 'takeover' && !isTakeover(n)) return false;
      if (q && !`${subName(n)} ${parentDomain(n)} ${resolvedIps(n).join(' ')}`.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [subs, view, search]);

  const groups = useMemo(() => {
    const m = new Map<string, ExportedNode[]>();
    for (const n of filtered) {
      const d = parentDomain(n);
      let arr = m.get(d);
      if (!arr) { arr = []; m.set(d, arr); }
      arr.push(n);
    }
    return [...m.entries()]
      .map(([domain, list]) => [domain, list.sort((a, b) => subName(a).localeCompare(subName(b)))] as const)
      .sort((a, b) => b[1].length - a[1].length);
  }, [filtered]);

  const toggle = (d: string) => setCollapsed(prev => {
    const next = new Set(prev);
    next.has(d) ? next.delete(d) : next.add(d);
    return next;
  });

  if (subs.length === 0) {
    return (
      <EmptyPanelState
        title="No subdomains yet"
        message="Run passive DNS recon (subfinder, amass, crt.sh) against an in-scope domain — discovered subdomains land here."
      />
    );
  }

  return (
    <div className="space-y-3">
      <FilterBar>
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter subdomains…"
          className="settings-input w-56"
        />
        <SegmentedControl
          value={view}
          onChange={setView}
          options={[
            { value: 'all', label: 'All', count: stats.total },
            { value: 'resolved', label: 'Resolved', count: stats.resolved },
            { value: 'takeover', label: 'Takeover-risk', count: stats.takeover },
          ]}
        />
      </FilterBar>

      {groups.length === 0 ? (
        <EmptyPanelState message="No subdomains match the current filter." />
      ) : groups.map(([domain, list]) => {
        const isCollapsed = collapsed.has(domain);
        const resolved = list.filter(n => resolvedIps(n).length > 0).length;
        const takeover = list.filter(isTakeover).length;
        const groupIds = list.map(n => n.id);
        const allSelected = groupIds.every(id => selected.has(id));
        return (
          <div key={domain} className="rounded-md border border-border bg-surface">
            <div className="w-full flex items-center gap-2 px-3 py-2 hover:bg-hover/30">
              <input
                type="checkbox"
                checked={allSelected}
                onChange={e => onSelectMany(groupIds, e.target.checked)}
                onClick={e => e.stopPropagation()}
                className="flex-shrink-0 accent-accent"
                title="Select all in group"
              />
              <button onClick={() => toggle(domain)} className="flex flex-1 items-center gap-2 text-left min-w-0">
                <span className="text-muted-foreground text-xs w-3">{isCollapsed ? '▸' : '▾'}</span>
                <span className="font-mono text-sm text-foreground truncate">{domain}</span>
                <span className="text-[10px] text-muted-foreground">{list.length}</span>
                <div className="ml-auto flex items-center gap-1.5">
                  {takeover > 0 && <StatusPill className="bg-destructive/10 text-destructive">⚠ {takeover} takeover</StatusPill>}
                  <StatusPill className="bg-elevated text-muted-foreground">{resolved} resolved</StatusPill>
                </div>
              </button>
            </div>
            {!isCollapsed && (
              <div className="border-t border-border p-2 space-y-1.5">
                {list.slice(0, GROUP_RENDER_CAP).map(n => {
                  const ips = resolvedIps(n);
                  const dns = dnsRecords(n);
                  return (
                    <DataRow key={n.id} onClick={() => navigate(n.id, 2)}>
                      <div className="flex items-start gap-2">
                        <RowCheckbox id={n.id} selected={selected} onToggle={onToggle} />
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-xs font-medium text-foreground">{subName(n)}</span>
                          <span className="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[10px] text-muted-foreground">
                            {ips.length > 0
                              ? <>{ips.slice(0, 4).map(ip => <span key={ip} className="font-mono">{ip}</span>)}{ips.length > 4 && <span>+{ips.length - 4}</span>}</>
                              : <span className="italic">unresolved</span>}
                            {dns.length > 0 && <span>· {dns.length} DNS</span>}
                          </span>
                        </span>
                        {isTakeover(n) && <StatusPill className="bg-destructive/10 text-destructive flex-shrink-0">⚠ takeover</StatusPill>}
                      </div>
                    </DataRow>
                  );
                })}
                {list.length > GROUP_RENDER_CAP && (
                  <div className="px-2 py-1 text-[10px] text-muted-foreground">
                    Showing {GROUP_RENDER_CAP} of {list.length} — use the filter to narrow.
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ---- Web hosts (webapp nodes with screenshots + assess signals) ----
function webName(n: ExportedNode): string {
  return str(n.url) || str(n.title) || n.label || n.id;
}
function httpStatusClass(code: number): string {
  if (code >= 200 && code < 300) return 'bg-success/10 text-success';
  if (code >= 300 && code < 400) return 'bg-warning/10 text-warning';
  return 'bg-destructive/10 text-destructive';
}
function WebHostsSegment({ webapps, edges, navigate, selected, onToggle }: SelectProps & {
  webapps: ExportedNode[];
  edges: Array<{ source: string; target: string; type: string }>;
  navigate: (id: string, hops: number) => void;
}) {
  const [search, setSearch] = useState('');

  // One pass over edges → per-webapp endpoint + vuln counts (assess signals).
  const edgeCounts = useMemo(() => {
    const m = new Map<string, { endpoints: number; vulns: number }>();
    for (const e of edges) {
      if (e.type === 'HAS_ENDPOINT') {
        const c = m.get(e.source) ?? { endpoints: 0, vulns: 0 }; c.endpoints++; m.set(e.source, c);
      } else if (e.type === 'VULNERABLE_TO') {
        const c = m.get(e.source) ?? { endpoints: 0, vulns: 0 }; c.vulns++; m.set(e.source, c);
      }
    }
    return m;
  }, [edges]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const list = q
      ? webapps.filter(n => `${webName(n)} ${str(n.technology) ?? ''} ${str(n.framework) ?? ''}`.toLowerCase().includes(q))
      : webapps;
    return [...list].sort((a, b) => webName(a).localeCompare(webName(b)));
  }, [webapps, search]);

  if (webapps.length === 0) {
    return <EmptyPanelState title="No web hosts yet" message="Run web discovery (httpx, gowitness/aquatone) against in-scope hosts — live web apps and their screenshots land here." />;
  }

  return (
    <div className="space-y-2">
      <FilterBar>
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Filter web hosts…" className="settings-input w-56" />
      </FilterBar>
      {filtered.map(n => {
        const shotId = str(n.screenshot_evidence_id);
        const status = num(n.http_status);
        const tech = str(n.technology);
        const framework = str(n.framework);
        const counts = edgeCounts.get(n.id);
        return (
          <DataRow key={n.id} onClick={() => navigate(n.id, 2)}>
            <div className="flex items-start gap-2">
              <RowCheckbox id={n.id} selected={selected} onToggle={onToggle} />
              {shotId && (
                <AuthenticatedImage
                  src={evidenceImageUrl(shotId)}
                  alt=""
                  loading="lazy"
                  className="h-14 w-20 flex-shrink-0 rounded border border-border object-cover object-top"
                />
              )}
              <span className="min-w-0 flex-1">
                <span className="flex items-center gap-1.5">
                  <span className="truncate text-xs font-medium text-foreground">{webName(n)}</span>
                  {status !== undefined && <StatusPill className={`${httpStatusClass(status)} flex-shrink-0`}>{status}</StatusPill>}
                </span>
                {str(n.title) && str(n.url) && <span className="mt-0.5 block truncate text-[11px] text-muted-foreground">{n.title as string}</span>}
                <span className="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[10px] text-muted-foreground">
                  {tech && <span className="rounded border border-border bg-background/50 px-1.5 py-0.5">{tech}</span>}
                  {framework && framework !== tech && <span className="rounded border border-border bg-background/50 px-1.5 py-0.5">{framework}</span>}
                  {counts?.endpoints ? <span>{counts.endpoints} endpoint{counts.endpoints === 1 ? '' : 's'}</span> : null}
                </span>
              </span>
              {counts?.vulns ? <StatusPill className="bg-destructive/10 text-destructive flex-shrink-0">⚠ {counts.vulns} vuln{counts.vulns === 1 ? '' : 's'}</StatusPill> : null}
            </div>
          </DataRow>
        );
      })}
    </div>
  );
}

// ---- Infra (ASN netblocks + organizations) ----
function InfraSegment({ asns, orgs, navigate, selected, onToggle }: SelectProps & {
  asns: ExportedNode[];
  orgs: ExportedNode[];
  navigate: (id: string, hops: number) => void;
}) {
  if (asns.length === 0 && orgs.length === 0) {
    return <EmptyPanelState title="No infra yet" message="Run ASN / org enumeration (whois, BGP, org OSINT) — netblocks and owning organizations land here." />;
  }
  return (
    <div className="space-y-3">
      {orgs.length > 0 && (
        <div className="space-y-1.5">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Organizations ({orgs.length})</div>
          {orgs.map(n => {
            const domains = strArr(n.domains_owned);
            return (
              <DataRow key={n.id} onClick={() => navigate(n.id, 2)}>
                <div className="flex items-start gap-2">
                  <RowCheckbox id={n.id} selected={selected} onToggle={onToggle} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-xs font-medium text-foreground">{str(n.org_name) || n.label || n.id}</span>
                    <span className="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[10px] text-muted-foreground">
                      {str(n.industry) && <span>{n.industry as string}</span>}
                      {domains.length > 0 && <span>· {domains.length} domain{domains.length === 1 ? '' : 's'}: <span className="font-mono">{domains.slice(0, 3).join(', ')}{domains.length > 3 ? ` +${domains.length - 3}` : ''}</span></span>}
                    </span>
                  </span>
                </div>
              </DataRow>
            );
          })}
        </div>
      )}
      {asns.length > 0 && (
        <div className="space-y-1.5">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">ASN netblocks ({asns.length})</div>
          {asns.map(n => {
            const cidrs = strArr(n.cidr_ranges);
            const asn = num(n.asn_number);
            return (
              <DataRow key={n.id} onClick={() => navigate(n.id, 2)}>
                <div className="flex items-start gap-2">
                  <RowCheckbox id={n.id} selected={selected} onToggle={onToggle} />
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-1.5">
                      {asn !== undefined && <span className="font-mono text-xs font-medium text-foreground">AS{asn}</span>}
                      <span className="truncate text-xs text-foreground">{str(n.asn_org) || str(n.org_name) || n.label}</span>
                    </span>
                    <span className="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[10px] text-muted-foreground">
                      {str(n.registry) && <span>{n.registry as string}</span>}
                      {cidrs.length > 0 && <span className="font-mono">· {cidrs.slice(0, 4).join(', ')}{cidrs.length > 4 ? ` +${cidrs.length - 4}` : ''}</span>}
                    </span>
                  </span>
                </div>
              </DataRow>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ---- People (email anchors + breach exposure) ----
function PeopleSegment({ emails, navigate, selected, onToggle }: SelectProps & {
  emails: ExportedNode[];
  navigate: (id: string, hops: number) => void;
}) {
  const [search, setSearch] = useState('');
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const list = q
      ? emails.filter(n => `${str(n.email_address) ?? ''} ${str(n.person_name) ?? ''}`.toLowerCase().includes(q))
      : emails;
    return [...list].sort((a, b) => (str(a.email_address) || a.label || '').localeCompare(str(b.email_address) || b.label || ''));
  }, [emails, search]);

  if (emails.length === 0) {
    return <EmptyPanelState title="No people yet" message="Run email/people OSINT (harvesters, breach lookups) against in-scope domains — email anchors and breach exposure land here." />;
  }
  return (
    <div className="space-y-2">
      <FilterBar>
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Filter people…" className="settings-input w-56" />
      </FilterBar>
      {filtered.map(n => {
        const breaches = strArr(n.breach_names);
        return (
          <DataRow key={n.id} onClick={() => navigate(n.id, 2)}>
            <div className="flex items-start gap-2">
              <RowCheckbox id={n.id} selected={selected} onToggle={onToggle} />
              <span className="min-w-0 flex-1">
                <span className="flex items-center gap-1.5">
                  <span className="truncate text-xs font-medium text-foreground">{str(n.email_address) || n.label || n.id}</span>
                  {n.email_verified === true && <StatusPill className="bg-success/10 text-success flex-shrink-0">verified</StatusPill>}
                </span>
                <span className="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[10px] text-muted-foreground">
                  {str(n.person_name) && <span>{n.person_name as string}</span>}
                  {str(n.email_source) && <span>· {n.email_source as string}</span>}
                </span>
                {breaches.length > 0 && (
                  <span className="mt-1 flex flex-wrap gap-1">
                    {breaches.slice(0, 6).map(b => (
                      <span key={b} className="rounded border border-destructive/20 bg-destructive/5 px-1.5 py-0.5 text-[10px] text-destructive">{b}</span>
                    ))}
                    {breaches.length > 6 && <span className="text-[10px] text-muted-foreground">+{breaches.length - 6}</span>}
                  </span>
                )}
              </span>
              {breaches.length > 0 && <StatusPill className="bg-destructive/10 text-destructive flex-shrink-0">⚠ {breaches.length} breach{breaches.length === 1 ? '' : 'es'}</StatusPill>}
            </div>
          </DataRow>
        );
      })}
    </div>
  );
}
