// ============================================================
// Breadcrumb — contextual navigation breadcrumb
// ============================================================

import type { PanelId } from './OperatorLayout';

const PANEL_LABELS: Record<PanelId, string> = {
  overview: 'Overview',
  campaigns: 'Campaigns',
  agents: 'Console',
  sessions: 'Sessions',
  actions: 'Approvals',
  frontier: 'Frontier',
  activity: 'Activity',
  evidence: 'Evidence',
  identity: 'Identity',
  credentials: 'Credentials',
  paths: 'Attack Paths',
  findings: 'Findings',
  engagements: 'Engagements',
  smoke: 'Smoke',
  settings: 'Settings',
};

interface BreadcrumbProps {
  panel: PanelId;
  item?: string;
}

export function Breadcrumb({ panel, item }: BreadcrumbProps) {
  if (!item) return null;

  return (
    <nav className="px-6 pt-3 pb-0 text-[11px] text-muted-foreground flex items-center gap-1">
      <span className="text-foreground font-medium">{PANEL_LABELS[panel]}</span>
      {item && (
        <>
          <span className="text-muted">/</span>
          <span className="font-mono truncate max-w-[200px]">{item}</span>
        </>
      )}
    </nav>
  );
}
