import { useMemo, useState } from 'react';
import * as api from '../../lib/api';
import { useToastStore } from '../../stores/toast-store';
import { useNavigation } from '../../hooks/useNavigation';
import { parseTargetBlob, mergeScopeWithTargets, hasParsedTargets } from '../../lib/target-input';
import { ActionButton } from '../shared/primitives';

// Phase 4c — add IPs/CIDRs/domains mid-engagement without leaving the console.
// Mirrors the command bar's preview→confirm UX: paste → client-side parse
// (identical rules to "scan …") → server dry-run preview (how many nodes
// enter/leave scope) → confirm (PATCH /api/config/scope, the canonical write
// path with audit + inference) → optional enumerate hand-off to the frontier.

type Phase =
  | { kind: 'input' }
  | { kind: 'previewing' }
  | { kind: 'preview'; preview: api.ScopeChangePreview }
  | { kind: 'confirming' }
  | { kind: 'result'; affected: number; addedCidrs: number }
  | { kind: 'error'; text: string };

export function AddTargetsModal({ onClose, onAdded }: { onClose: () => void; onAdded?: () => void }) {
  const [text, setText] = useState('');
  const [phase, setPhase] = useState<Phase>({ kind: 'input' });
  const addToast = useToastStore(s => s.addToast);
  const { navigateToPanel } = useNavigation();

  const parsed = useMemo(() => parseTargetBlob(text), [text]);
  // Allow re-previewing from the error phase too, so a transient failure isn't a
  // dead end requiring a textarea edit to recover.
  const canPreview = hasParsedTargets(parsed) && (phase.kind === 'input' || phase.kind === 'error');

  const runPreview = async () => {
    setPhase({ kind: 'previewing' });
    try {
      const config = await api.getConfig();
      const merged = mergeScopeWithTargets(config.scope, parsed);
      const preview = await api.previewScope(merged);
      setPhase({ kind: 'preview', preview });
    } catch (err) {
      setPhase({ kind: 'error', text: err instanceof Error ? err.message : String(err) });
    }
  };

  const confirm = async () => {
    setPhase({ kind: 'confirming' });
    try {
      // Re-derive the body against the LIVE scope at confirm time rather than
      // replaying the preview-time snapshot. mergeScopeWithTargets only UNIONS
      // the parsed targets onto current scope, so a CIDR/domain added by another
      // operator between preview and confirm is preserved — never diffed into a
      // silent removal (the server treats the body as a full-replacement).
      const config = await api.getConfig();
      const merged = mergeScopeWithTargets(config.scope, parsed);
      const res = await api.updateScope(merged);
      const affected = res.affected_node_count ?? 0;
      addToast({ type: 'success', title: 'Scope updated', message: `${affected} node(s) affected` });
      setPhase({ kind: 'result', affected, addedCidrs: parsed.cidrs.length });
      onAdded?.();
    } catch (err) {
      setPhase({ kind: 'error', text: err instanceof Error ? err.message : String(err) });
    }
  };

  const busy = phase.kind === 'previewing' || phase.kind === 'confirming';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" onClick={busy ? undefined : onClose}>
      <div className="absolute inset-0 bg-black/40" />
      <div className="relative w-[30rem] max-h-[85vh] overflow-y-auto rounded-lg border border-border bg-surface p-5 shadow-xl" onClick={e => e.stopPropagation()}>
        <h3 className="text-sm font-semibold">Add Targets</h3>
        <p className="mt-0.5 text-[11px] text-muted-foreground">
          Paste IPs, CIDRs, or domains — same rules as the <span className="font-mono">scan</span> command. Preview the impact, then add to scope.
        </p>

        {(phase.kind === 'input' || phase.kind === 'previewing' || phase.kind === 'error') && (
          <>
            <textarea
              value={text}
              onChange={e => { setText(e.target.value); if (phase.kind === 'error') setPhase({ kind: 'input' }); }}
              placeholder={'10.30.0.0/24, 10.20.0.5\nevil.example.com'}
              rows={4}
              className="mt-3 w-full rounded border border-border bg-elevated px-2 py-1.5 text-xs font-mono text-foreground outline-none focus:border-accent placeholder:text-muted-foreground"
              disabled={busy}
            />
            <ParsedSummary parsed={parsed} />
            {phase.kind === 'error' && <div className="mt-2 text-xs text-destructive">{phase.text}</div>}
            <div className="mt-4 flex justify-end gap-2">
              <ActionButton onClick={onClose} variant="ghost" size="xs" disabled={busy}>Cancel</ActionButton>
              <ActionButton onClick={runPreview} variant="purple" size="xs" disabled={!canPreview}>
                {phase.kind === 'previewing' ? 'Previewing…' : 'Preview impact'}
              </ActionButton>
            </div>
          </>
        )}

        {(phase.kind === 'preview' || phase.kind === 'confirming') && (
          <div className="mt-3 space-y-2">
            <ParsedSummary parsed={parsed} />
            <div className="rounded border border-accent/30 bg-accent/5 p-3 text-xs">
              <div className="font-medium text-accent">Impact</div>
              <div className="mt-1.5 grid grid-cols-2 gap-2">
                <Stat label="Nodes entering scope" value={phase.kind === 'preview' ? phase.preview.nodes_entering_scope : 0} accent />
                <Stat label="Nodes leaving scope" value={phase.kind === 'preview' ? phase.preview.nodes_leaving_scope : 0} />
              </div>
              {phase.kind === 'preview' && phase.preview.pending_suggestions_resolved.length > 0 && (
                <div className="mt-2 text-[11px] text-muted-foreground">
                  Resolves {phase.preview.pending_suggestions_resolved.length} pending scope suggestion(s).
                </div>
              )}
              {phase.kind === 'preview' && phase.preview.nodes_entering_scope === 0 && phase.preview.nodes_leaving_scope === 0 && (
                <div className="mt-2 text-[11px] text-muted-foreground">
                  No known nodes change scope yet — new ranges will be enumerated lazily from the frontier.
                </div>
              )}
            </div>
            <div className="flex justify-end gap-2">
              <ActionButton onClick={() => setPhase({ kind: 'input' })} variant="ghost" size="xs" disabled={busy}>Back</ActionButton>
              {phase.kind === 'preview' && (
                <ActionButton onClick={confirm} variant="success" size="xs">Confirm &amp; add</ActionButton>
              )}
              {phase.kind === 'confirming' && (
                <ActionButton variant="success" size="xs" disabled>Adding…</ActionButton>
              )}
            </div>
          </div>
        )}

        {phase.kind === 'result' && (
          <div className="mt-3 space-y-3">
            <div className="flex items-center gap-2 text-xs text-success">
              <span>✓</span>
              <span>Scope updated — {phase.affected} node(s) affected.</span>
            </div>
            {phase.addedCidrs > 0 && (
              <div className="rounded border border-border bg-background/40 p-3 text-xs text-muted-foreground">
                New network ranges are added. Overwatch surfaces <span className="font-mono">network_discovery</span> items on the frontier as it lazily enumerates them — no host seeding.
              </div>
            )}
            <div className="flex justify-end gap-2">
              {phase.addedCidrs > 0 && (
                <ActionButton onClick={() => { navigateToPanel('frontier'); onClose(); }} variant="purple" size="xs">
                  Enumerate from Frontier →
                </ActionButton>
              )}
              <ActionButton onClick={onClose} variant="secondary" size="xs">Done</ActionButton>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function ParsedSummary({ parsed }: { parsed: ReturnType<typeof parseTargetBlob> }) {
  if (!parsed.cidrs.length && !parsed.domains.length && !parsed.invalid.length) return null;
  return (
    <div className="mt-2 space-y-1 text-[11px]">
      {parsed.cidrs.length > 0 && (
        <div><span className="text-muted-foreground">CIDRs/IPs:</span> <span className="font-mono text-accent">{parsed.cidrs.join(', ')}</span></div>
      )}
      {parsed.domains.length > 0 && (
        <div><span className="text-muted-foreground">Domains:</span> <span className="font-mono text-accent">{parsed.domains.join(', ')}</span></div>
      )}
      {parsed.invalid.length > 0 && (
        <div className="text-warning">Ignored (not a CIDR/IP/domain — IPv6 unsupported): <span className="font-mono">{parsed.invalid.join(', ')}</span></div>
      )}
      {parsed.truncated && <div className="text-warning">Too many entries — only the first 256 will be added.</div>}
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: number; accent?: boolean }) {
  return (
    <div className="rounded border border-border bg-background/40 px-2 py-1.5">
      <div className={accent && value > 0 ? 'text-base font-semibold text-accent' : 'text-base font-semibold text-foreground'}>{value}</div>
      <div className="text-[10px] text-muted-foreground">{label}</div>
    </div>
  );
}
