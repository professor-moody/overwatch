// ============================================================
// EdgeLegend — graph overlay listing edge categories with colors.
// Collapsible. Mirrors the legacy graph.html legend.
// ============================================================

import { useState } from 'react';
import { EDGE_CATEGORIES } from '../../lib/graph-constants';
import { cn } from '../../lib/utils';

type Category = { label: string; types: string[] };

const EDGE_LEGEND_CATEGORIES: Category[] = [
  { label: 'Network',      types: ['REACHABLE', 'RUNS'] },
  { label: 'Access',       types: ['ADMIN_TO', 'HAS_SESSION', 'CAN_RDPINTO', 'CAN_PSREMOTE'] },
  { label: 'Credentials',  types: ['VALID_ON', 'OWNS_CRED', 'TESTED_CRED'] },
  { label: 'Cred Reuse',   types: ['SHARED_CREDENTIAL'] },
  { label: 'AD Attack',    types: ['CAN_DCSYNC', 'GENERIC_ALL', 'WRITE_DACL'] },
  { label: 'ADCS',         types: ['CAN_ENROLL', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC6', 'ESC7', 'ESC8'] },
  { label: 'Delegation',   types: ['DELEGATES_TO', 'CAN_DELEGATE_TO'] },
  { label: 'Roasting',     types: ['KERBEROASTABLE', 'AS_REP_ROASTABLE'] },
  { label: 'Lateral',      types: ['RELAY_TARGET', 'NULL_SESSION'] },
  { label: 'Cred Chain',   types: ['DERIVED_FROM', 'DUMPED_FROM'] },
  { label: 'Domain',       types: ['MEMBER_OF', 'TRUSTS'] },
  { label: 'Web',          types: ['VULNERABLE_TO', 'EXPLOITS'] },
  { label: 'Cloud',        types: ['ASSUMES_ROLE', 'POLICY_ALLOWS'] },
  { label: 'Inferred',     types: ['_inferred_'] },
];

export function EdgeLegend() {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="absolute bottom-4 left-4 z-30 bg-surface/95 border border-border rounded-md shadow-md text-xs select-none">
      <button
        type="button"
        onClick={() => setCollapsed((c) => !c)}
        className="w-full flex items-center justify-between gap-3 px-2.5 py-1.5 text-foreground hover:bg-foreground/5 rounded-t-md"
      >
        <span className="font-semibold">Edge Legend</span>
        <span className={cn('transition-transform', collapsed && '-rotate-90')}>▾</span>
      </button>
      {!collapsed && (
        <div className="px-2.5 pb-2 pt-0.5 space-y-1 max-h-[40vh] overflow-y-auto">
          {EDGE_LEGEND_CATEGORIES.map((cat) => {
            if (cat.types[0] === '_inferred_') {
              return (
                <div key={cat.label} className="flex items-center gap-2">
                  <span className="w-3 h-0.5 border-t border-dashed border-muted-foreground" />
                  <span className="text-muted-foreground">Inferred (no arrow)</span>
                </div>
              );
            }
            const color = EDGE_CATEGORIES[cat.types[0]] || '#888';
            return (
              <div key={cat.label} className="flex items-center gap-2">
                <span
                  className="w-3 h-0.5"
                  style={{ backgroundColor: color }}
                />
                <span className="text-muted-foreground">{cat.label}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
