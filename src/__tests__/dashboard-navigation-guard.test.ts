import { describe, expect, it } from 'vitest';
import { auditDashboardSources } from '../../scripts/check-dashboard-navigation.mjs';

describe('dashboard navigation guard', () => {
  it('accepts typed canonical navigation and isolated compatibility adapters', () => {
    expect(auditDashboardSources({
      'components/workspaces/OperateWorkspace.tsx': "navigate(buildWorkspacePath({ workspace: 'review', view: 'proof' }));",
      'lib/legacy-navigation.ts': "const supported = '/agents?item=task-1';",
      'App.tsx': "return legacyPathToWorkspacePath('/graph');",
    })).toEqual([]);
  });

  it('rejects a legacy route emitted by active dashboard code', () => {
    expect(auditDashboardSources({
      'components/shared/FindingLink.tsx': "navigate('/findings?item=f-1');",
    })).toEqual([
      'components/shared/FindingLink.tsx:1 emits legacy dashboard route /findings',
    ]);
  });

  it('rejects retired shell imports and workspace page grammar', () => {
    expect(auditDashboardSources({
      'components/workspaces/ReviewWorkspace.tsx': [
        "import { PageHeader } from '../shared/primitives';",
        "import { FindingsPanel } from '../panels/FindingsPanel';",
      ].join('\n'),
    })).toEqual([
      'components/workspaces/ReviewWorkspace.tsx:2 imports retired dashboard runtime panels/FindingsPanel',
      'components/workspaces/ReviewWorkspace.tsx:1 uses retired page grammar PageHeader',
    ]);
  });
});
