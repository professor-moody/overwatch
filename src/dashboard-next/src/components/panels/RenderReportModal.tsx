// ============================================================
// RenderReportModal (B.3)
//
// Operator-facing modal that POSTs /api/reports/render with the
// chosen options. Mirrors the generate_report MCP tool's option
// surface; PDF format is reserved for B.4 and shown disabled.
// ============================================================

import { useState } from 'react';
import * as api from '../../lib/api';
import { cn } from '../../lib/utils';

interface Props {
  onClose: () => void;
  onRendered: () => void;
}

export function RenderReportModal({ onClose, onRendered }: Props) {
  const [format, setFormat] = useState<'markdown' | 'html' | 'json' | 'pdf'>('markdown');
  const [theme, setTheme] = useState<'light' | 'dark'>('light');
  const [clientSafe, setClientSafe] = useState(false);
  const [includeAttackPaths, setIncludeAttackPaths] = useState(true);
  const [includeRetrospective, setIncludeRetrospective] = useState(false);
  const [includeCompliance, setIncludeCompliance] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.renderReport({
        format,
        theme: format === 'html' || format === 'pdf' ? theme : undefined,
        client_safe: clientSafe,
        include_attack_paths: includeAttackPaths,
        include_retrospective: includeRetrospective,
        include_compliance: includeCompliance,
      });
      onRendered();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm p-4">
      <div className="bg-surface border border-border rounded-lg shadow-xl w-full max-w-md p-5">
        <div className="flex items-start justify-between mb-4">
          <h3 className="text-base font-semibold">Generate Report</h3>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground text-lg leading-none" aria-label="Close">&times;</button>
        </div>

        <div className="space-y-3">
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Format</label>
            <div className="flex gap-1">
              {(['markdown', 'html', 'json', 'pdf'] as const).map(f => (
                <button
                  key={f}
                  onClick={() => setFormat(f)}
                  className={cn(
                    'flex-1 px-3 py-1.5 text-xs rounded border transition-colors',
                    format === f
                      ? 'bg-accent/10 border-accent/40 text-accent'
                      : 'bg-elevated border-border text-muted-foreground hover:text-foreground'
                  )}
                  title={f === 'pdf' ? 'Renders HTML through headless Chromium (requires chromium binary on the engine host).' : undefined}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          {(format === 'html' || format === 'pdf') && (
            <div>
              <label className="block text-xs text-muted-foreground mb-1">Theme</label>
              <div className="flex gap-1">
                {(['light', 'dark'] as const).map(t => (
                  <button
                    key={t}
                    onClick={() => setTheme(t)}
                    className={cn(
                      'flex-1 px-3 py-1.5 text-xs rounded border transition-colors',
                      theme === t
                        ? 'bg-accent/10 border-accent/40 text-accent'
                        : 'bg-elevated border-border text-muted-foreground hover:text-foreground'
                    )}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>
          )}

          <ToggleRow
            checked={clientSafe}
            onChange={setClientSafe}
            label="Client-safe redaction"
            hint="Strips cred values, raw output, and operator paths."
          />
          <ToggleRow
            checked={includeAttackPaths}
            onChange={setIncludeAttackPaths}
            label="Include Attack Paths section"
            hint="Synthesizes per-objective attack chains with confidence."
          />
          <ToggleRow
            checked={includeCompliance}
            onChange={setIncludeCompliance}
            label="Include compliance mapping"
            hint="CWE / OWASP / NIST 800-53 / PCI-DSS / ATT&CK rollups."
          />
          <ToggleRow
            checked={includeRetrospective}
            onChange={setIncludeRetrospective}
            label="Include retrospective"
            hint="Inference gaps, skill gaps, RLVR-trace quality."
          />

          {error && (
            <div className="text-xs text-destructive bg-destructive/10 border border-destructive/30 rounded p-2">
              {error}
            </div>
          )}
        </div>

        <div className="flex justify-end gap-2 mt-5">
          <button
            onClick={onClose}
            className="text-xs px-3 py-1.5 rounded border border-border text-muted-foreground hover:text-foreground"
          >
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={busy}
            className="text-xs px-3 py-1.5 rounded bg-accent text-background hover:bg-accent/90 disabled:opacity-50"
          >
            {busy ? 'Rendering…' : 'Render & Save'}
          </button>
        </div>
      </div>
    </div>
  );
}

function ToggleRow({ checked, onChange, label, hint }: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  hint?: string;
}) {
  return (
    <label className="flex items-start gap-2 cursor-pointer">
      <input
        type="checkbox"
        checked={checked}
        onChange={e => onChange(e.target.checked)}
        className="mt-0.5 accent-accent"
      />
      <div className="flex-1">
        <div className="text-xs text-foreground">{label}</div>
        {hint && <div className="text-[10px] text-muted-foreground">{hint}</div>}
      </div>
    </label>
  );
}
