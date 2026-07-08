import { useMemo, useState } from 'react';
import { useEngagementStore } from '../../stores/engagement-store';
import { useNavigation } from '../../hooks/useNavigation';
import type { ExportedNode } from '../../lib/types';
import { DataRow, EmptyPanelState, FilterBar, PageHeader, SegmentedControl, StatusPill } from '../shared/primitives';

// Recon (OSINT) workspace — Tier 1: the SUBDOMAINS view. The external-recon surface
// is all in the graph (subdomain/domain/asn/email nodes), but until now it was only
// legible in the graph viewport or raw tool output. This lists it as a readable,
// assessable table grouped by apex domain, deep-linking each row back into the graph.
// (Web hosts / Infra / People segments — and multi-select fan-out dispatch — follow.)

type View = 'all' | 'resolved' | 'takeover';

// Cap rows rendered per (expanded) domain group so a domain with thousands of
// subdomains can't blow up the DOM; the filter/collapse narrow the rest.
const GROUP_RENDER_CAP = 200;

function strArr(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}
function subName(n: ExportedNode): string {
  return (typeof n.subdomain_name === 'string' && n.subdomain_name) || n.label || n.id;
}
const NO_DOMAIN = '(no parent domain)';
function parentDomain(n: ExportedNode): string {
  if (typeof n.parent_domain === 'string' && n.parent_domain) return n.parent_domain;
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

export function ReconPanel() {
  const graph = useEngagementStore(s => s.graph);
  const { navigateToGraph } = useNavigation();
  const [view, setView] = useState<View>('all');
  const [search, setSearch] = useState('');
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const subs = useMemo(() => graph.nodes.filter(n => n.type === 'subdomain'), [graph.nodes]);

  const stats = useMemo(() => ({
    total: subs.length,
    domains: new Set(subs.map(parentDomain)).size,
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

  return (
    <div className="space-y-4">
      <PageHeader
        title="Recon"
        meta={`(${stats.total} subdomains · ${stats.domains} domains${stats.takeover > 0 ? ` · ${stats.takeover} takeover-risk` : ''})`}
        actions={(
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
        )}
      />

      {subs.length === 0 ? (
        <EmptyPanelState
          title="No subdomains yet"
          message="Run passive DNS recon (subfinder, amass, crt.sh) against an in-scope domain — discovered subdomains land here."
        />
      ) : groups.length === 0 ? (
        <EmptyPanelState message="No subdomains match the current filter." />
      ) : (
        <div className="space-y-3">
          {groups.map(([domain, list]) => {
            const isCollapsed = collapsed.has(domain);
            const resolved = list.filter(n => resolvedIps(n).length > 0).length;
            const takeover = list.filter(isTakeover).length;
            return (
              <div key={domain} className="rounded-md border border-border bg-surface">
                <button onClick={() => toggle(domain)} className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-hover/30">
                  <span className="text-muted-foreground text-xs w-3">{isCollapsed ? '▸' : '▾'}</span>
                  <span className="font-mono text-sm text-foreground truncate">{domain}</span>
                  <span className="text-[10px] text-muted-foreground">{list.length}</span>
                  <div className="ml-auto flex items-center gap-1.5">
                    {takeover > 0 && <StatusPill className="bg-destructive/10 text-destructive">⚠ {takeover} takeover</StatusPill>}
                    <StatusPill className="bg-elevated text-muted-foreground">{resolved} resolved</StatusPill>
                  </div>
                </button>
                {!isCollapsed && (
                  <div className="border-t border-border p-2 space-y-1.5">
                    {list.slice(0, GROUP_RENDER_CAP).map(n => {
                      const ips = resolvedIps(n);
                      const dns = dnsRecords(n);
                      return (
                        <DataRow key={n.id} onClick={() => navigateToGraph(n.id, 2)}>
                          <div className="flex items-start gap-2">
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
      )}
    </div>
  );
}
