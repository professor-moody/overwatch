// ============================================================
// NodeContextMenu — right-click context menu on graph nodes
// ============================================================

import { useState } from 'react';
import { useNavigation } from '../../hooks/useNavigation';
import { correctGraph, type GraphCorrectionOperation } from '../../lib/api';
import { useToastStore } from '../../stores/toast-store';
import { cn } from '../../lib/utils';

export interface ContextMenuState {
  x: number;
  y: number;
  nodeId: string;
}

interface NodeContextMenuProps {
  menu: ContextMenuState | null;
  onClose: () => void;
  onFocus: (nodeId: string, hops: number) => void;
  onUndoPush: (operation: { reason: string; reverse: GraphCorrectionOperation[] }) => void;
}

export function NodeContextMenu({ menu, onClose, onFocus, onUndoPush }: NodeContextMenuProps) {
  const { navigateToEvidence } = useNavigation();
  const toast = useToastStore((s) => s.addToast);
  const [annotateOpen, setAnnotateOpen] = useState(false);
  const [annotateText, setAnnotateText] = useState('');

  if (!menu) return null;

  const patchNode = async (patch: Record<string, unknown>, label: string) => {
    const op: GraphCorrectionOperation = {
      kind: 'patch_node',
      node_id: menu.nodeId,
      patch,
    };
    try {
      await correctGraph(`[console] ${label}: ${menu.nodeId}`, [op]);
      toast({ type: 'success', title: label, message: menu.nodeId });
      // Push reverse operation for undo
      const reversePatch: Record<string, unknown> = {};
      for (const key of Object.keys(patch)) {
        reversePatch[key] = undefined;
      }
      onUndoPush({
        reason: `Undo: ${label}: ${menu.nodeId}`,
        reverse: [{ kind: 'patch_node', node_id: menu.nodeId, patch: reversePatch }],
      });
    } catch (err) {
      toast({ type: 'error', title: 'Correction failed', message: String(err) });
    }
    onClose();
  };

  const handleAnnotate = async () => {
    if (!annotateText.trim()) return;
    await patchNode({ notes: annotateText.trim() }, 'Annotated node');
    setAnnotateText('');
    setAnnotateOpen(false);
  };

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-[60]" onClick={onClose} />
      {/* Menu */}
      <div
        className="fixed z-[61] bg-surface border border-border rounded-lg shadow-xl py-1 min-w-[180px]"
        style={{ left: menu.x, top: menu.y }}
      >
        <div className="px-3 py-1.5 text-[10px] text-muted-foreground font-mono truncate border-b border-border mb-1">
          {menu.nodeId}
        </div>

        <MenuItem onClick={() => { onFocus(menu.nodeId, 2); onClose(); }}>
          Focus Neighborhood
        </MenuItem>
        <MenuItem onClick={() => { navigateToEvidence(menu.nodeId); onClose(); }}>
          View Evidence
        </MenuItem>

        <div className="border-t border-border my-1" />

        <MenuItem onClick={() => setAnnotateOpen(!annotateOpen)}>
          Annotate
        </MenuItem>

        {annotateOpen && (
          <div className="px-3 py-1.5 flex gap-1">
            <input
              autoFocus
              value={annotateText}
              onChange={(e) => setAnnotateText(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAnnotate()}
              placeholder="Note…"
              className="settings-input flex-1 text-xs"
            />
            <button onClick={handleAnnotate} className="text-[10px] px-1.5 py-0.5 rounded bg-accent/10 text-accent hover:bg-accent/20">
              Save
            </button>
          </div>
        )}

        <MenuItem onClick={() => patchNode({ honeypot: true }, 'Marked as honeypot')} warn>
          Mark as Honeypot
        </MenuItem>
        <MenuItem onClick={() => patchNode({ out_of_scope: true }, 'Marked out-of-scope')} warn>
          Mark Out-of-Scope
        </MenuItem>
      </div>
    </>
  );
}

function MenuItem({
  children,
  onClick,
  warn,
}: {
  children: React.ReactNode;
  onClick: () => void;
  warn?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full text-left px-3 py-1.5 text-xs hover:bg-hover transition-colors',
        warn ? 'text-warning hover:text-warning' : 'text-foreground',
      )}
    >
      {children}
    </button>
  );
}
