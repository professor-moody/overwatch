import { lazy, Suspense } from 'react';
import { useSearchParams } from 'react-router';
import { useEngagementStore } from '../../stores/engagement-store';
import { MANAGE_SECTIONS, type ManageSection } from '../../lib/workspace-navigation';
import { WorkspaceHeader, WorkspaceTabs } from '../shared/primitives';

const EngagementsPanel = lazy(() => import('../panels/EngagementsPanel').then(module => ({ default: module.EngagementsPanel })));
const SettingsPanel = lazy(() => import('../panels/SettingsPanel').then(module => ({ default: module.SettingsPanel })));
const SmokePanel = lazy(() => import('../panels/SmokePanel').then(module => ({ default: module.SmokePanel })));

function isSection(value: string | null): value is ManageSection {
  return !!value && (MANAGE_SECTIONS as readonly string[]).includes(value);
}

export function ManageWorkspace() {
  const [searchParams, setSearchParams] = useSearchParams();
  const engagement = useEngagementStore(state => state.engagement);
  const recovery = useEngagementStore(state => state.persistenceRecovery);
  const requested = searchParams.get('section');
  const section: ManageSection = isSection(requested) ? requested : 'engagement';

  const setSection = (nextSection: ManageSection) => {
    const next = new URLSearchParams(searchParams);
    next.set('section', nextSection);
    next.delete('item');
    setSearchParams(next);
  };

  const tabs: Array<{ value: ManageSection; label: string; count?: number }> = [
    { value: 'engagement', label: 'Engagement' },
    { value: 'settings', label: 'Settings' },
    { value: 'diagnostics', label: 'Diagnostics', count: recovery && recovery.status !== 'ready' ? 1 : undefined },
  ];

  return (
    <div className="flex min-h-0 flex-1 flex-col bg-background">
      <WorkspaceHeader
        eyebrow="Configuration and health"
        title="Manage"
        description={`Configure ${engagement?.name || 'the active engagement'} and inspect system readiness without crowding daily operations.`}
      >
        <WorkspaceTabs value={section} options={tabs} onChange={setSection} ariaLabel="Manage sections" />
      </WorkspaceHeader>
      <section className="min-h-0 flex-1 overflow-y-auto p-4 lg:p-5">
        <Suspense fallback={<div className="flex min-h-56 items-center justify-center text-xs text-muted-foreground"><span className="workspace-pulse">Loading management tools…</span></div>}>
          {section === 'engagement' && <EngagementsPanel />}
          {section === 'settings' && <SettingsPanel embedded />}
          {section === 'diagnostics' && <SmokePanel embedded />}
        </Suspense>
      </section>
    </div>
  );
}
