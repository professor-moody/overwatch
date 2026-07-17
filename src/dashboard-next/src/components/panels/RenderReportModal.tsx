// ============================================================
// RenderReportModal (B.3)
//
// Operator-facing modal that POSTs /api/reports/render with the
// chosen options. Mirrors the generate_report MCP tool's option
// surface, including report profile and evidence presentation.
// ============================================================

import { useState } from 'react';
import * as api from '../../lib/api';
import { formatReportBytes, reportEvidenceLabel, reportPrimaryActionLabel, reportProfileLabel } from '../../lib/report-display';
import { cn, formatTimestamp } from '../../lib/utils';
import { downloadDashboardResource, openDashboardResource } from '../../lib/dashboard-transport';

interface Props {
  onClose: () => void;
  onRendered: () => void;
}

export function RenderReportModal({ onClose, onRendered }: Props) {
  const [profile, setProfile] = useState<'client' | 'operator'>('client');
  const [format, setFormat] = useState<'markdown' | 'html' | 'json' | 'pdf'>('html');
  const [theme, setTheme] = useState<'light' | 'dark'>('light');
  const [clientSafe, setClientSafe] = useState(true);
  const [evidenceStyle, setEvidenceStyle] = useState<'proof_cards' | 'appendix' | 'full_inline'>('proof_cards');
  const [includeAttackPaths, setIncludeAttackPaths] = useState(true);
  const [includeRetrospective, setIncludeRetrospective] = useState(false);
  const [includeCompliance, setIncludeCompliance] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rendered, setRendered] = useState<Awaited<ReturnType<typeof api.renderReport>> | null>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await api.renderReport({
        format,
        theme: format === 'html' || format === 'pdf' ? theme : undefined,
        client_safe: clientSafe,
        profile,
        evidence_style: evidenceStyle,
        include_attack_paths: includeAttackPaths,
        include_retrospective: includeRetrospective,
        include_compliance: includeCompliance,
      });
      setRendered(result);
      onRendered();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const chooseProfile = (nextProfile: 'client' | 'operator') => {
    setProfile(nextProfile);
    if (nextProfile === 'client') {
      setClientSafe(true);
      setEvidenceStyle('proof_cards');
      setTheme('light');
      setFormat(prev => (prev === 'pdf' ? 'pdf' : 'html'));
    } else {
      setClientSafe(false);
      setEvidenceStyle('proof_cards');
      setFormat(prev => (prev === 'html' || prev === 'pdf' ? prev : 'markdown'));
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm p-4">
      <div className="bg-surface border border-border rounded-lg shadow-xl w-full max-w-md p-5">
        <div className="flex items-start justify-between mb-4">
          <h3 className="text-base font-semibold">{rendered
            ? rendered.report_committed ? 'Report Saved' : 'Report Needs Attention'
            : 'Generate Report'}</h3>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground text-lg leading-none" aria-label="Close">&times;</button>
        </div>

        {rendered ? (
          <ReportResult
            result={rendered}
            onClose={onClose}
            onRenderAnother={() => {
              setRendered(null);
              setError(null);
            }}
          />
        ) : (
          <>
        <div className="space-y-3">
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Profile</label>
            <div className="grid grid-cols-2 gap-2">
              <ProfileButton
                active={profile === 'client'}
                title="Client deliverable"
                description="Polished, client-safe proof summaries."
                onClick={() => chooseProfile('client')}
              />
              <ProfileButton
                active={profile === 'operator'}
                title="Operator binder"
                description="Full internal evidence metadata."
                onClick={() => chooseProfile('operator')}
              />
            </div>
          </div>

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
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Evidence</label>
            <select
              value={evidenceStyle}
              onChange={e => setEvidenceStyle(e.target.value as typeof evidenceStyle)}
              className="settings-input w-full text-xs"
            >
              <option value="proof_cards">Proof cards</option>
              <option value="appendix">Appendix first</option>
              <option value="full_inline">Full inline previews</option>
            </select>
          </div>
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
        </>
        )}
      </div>
    </div>
  );
}

function ReportResult({ result, onClose, onRenderAnother }: {
  result: Awaited<ReturnType<typeof api.renderReport>>;
  onClose: () => void;
  onRenderAnother: () => void;
}) {
  const report = result.report;
  const findingsCount = report.findings_count ?? result.findings_count;
  const evidenceCount = report.evidence_count ?? result.evidence_count ?? 0;
  const openUrl = api.reportOpenUrl(report.id);
  const downloadUrl = api.reportDownloadUrl(report.id);
  const durable = result.report_committed && result.commit_durability === 'confirmed';

  return (
    <div className="space-y-4">
      <div className={cn(
        'rounded border p-3',
        durable ? 'border-success/30 bg-success/10' : 'border-warning/30 bg-warning/10',
      )}>
        <div className={cn('text-sm font-medium', durable ? 'text-success' : 'text-warning')}>
          {durable ? 'Render committed' : 'Rendered, but durability is unconfirmed'}
        </div>
        <div className="mt-1 text-xs text-muted-foreground break-words">{report.filename}</div>
        {result.warning && <div className="mt-2 text-xs text-warning">{result.warning}</div>}
        {!result.reference_persisted && (
          <div className="mt-2 text-xs text-warning">The engagement state does not yet contain a durable reference to this report.</div>
        )}
      </div>

      <div className="grid grid-cols-2 gap-2 text-xs">
        <ResultFact label="Profile" value={reportProfileLabel(report)} />
        <ResultFact label="Format" value={report.format.toUpperCase()} />
        <ResultFact label="Redaction" value={report.redaction_mode === 'client_safe' ? 'client-safe' : 'operator'} />
        <ResultFact label="Evidence style" value={reportEvidenceLabel(report.evidence_style)} />
        <ResultFact label="Findings" value={String(findingsCount ?? '—')} />
        <ResultFact label="Evidence count" value={String(evidenceCount)} />
        <ResultFact label="Generated" value={formatTimestamp(report.generated_at)} span />
        <ResultFact label="Size" value={formatReportBytes(report.size_bytes)} />
      </div>

      <div className="flex flex-wrap justify-end gap-2">
        <button
          onClick={onRenderAnother}
          className="text-xs px-3 py-1.5 rounded border border-border text-muted-foreground hover:text-foreground"
        >
          Render another
        </button>
        <button
          onClick={onClose}
          className="text-xs px-3 py-1.5 rounded border border-border text-muted-foreground hover:text-foreground"
        >
          Close
        </button>
        <button
          onClick={() => void openDashboardResource(openUrl)}
          className="text-xs px-3 py-1.5 rounded bg-accent/10 text-accent hover:bg-accent/20"
        >
          {reportPrimaryActionLabel(report.format)}
        </button>
        <button
          onClick={() => void downloadDashboardResource(downloadUrl, { filename: report.filename })}
          className="text-xs px-3 py-1.5 rounded bg-accent text-background hover:bg-accent/90"
        >
          Download
        </button>
      </div>
    </div>
  );
}

function ResultFact({ label, value, span = false }: { label: string; value: string; span?: boolean }) {
  return (
    <div className={cn('rounded border border-border bg-elevated p-2 min-w-0', span && 'col-span-2')}>
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-0.5 font-medium text-foreground break-words">{value}</div>
    </div>
  );
}

function ProfileButton({ active, title, description, onClick }: {
  active: boolean;
  title: string;
  description: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'rounded border p-2 text-left transition-colors',
        active
          ? 'border-accent/50 bg-accent/10 text-foreground'
          : 'border-border bg-elevated text-muted-foreground hover:text-foreground',
      )}
    >
      <div className="text-xs font-medium">{title}</div>
      <div className="mt-0.5 text-[10px] leading-snug text-muted-foreground">{description}</div>
    </button>
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
