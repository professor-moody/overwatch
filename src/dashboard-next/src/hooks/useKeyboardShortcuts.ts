import { useEffect } from 'react';
import type { PanelId } from '../components/layout/OperatorLayout';

const PANEL_KEYS: Record<string, PanelId> = {
  '1': 'overview',
  '2': 'campaigns',
  '3': 'agents',
  '4': 'sessions',
  '5': 'actions',
  '6': 'frontier',
  '7': 'activity',
  '8': 'evidence',
  '9': 'engagements',
  '0': 'settings',
};

export function useKeyboardShortcuts({
  onPanelChange,
  onNavigateGraph,
  onNavigateEvidence,
}: {
  onPanelChange: (panel: PanelId) => void;
  onNavigateGraph?: () => void;
  onNavigateEvidence?: () => void;
}) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      const tag = target.tagName;
      // Don't intercept when user is typing in an input/textarea/select
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target.isContentEditable) return;
      // Don't intercept when terminal is focused (xterm captures its own keys)
      if (target.closest('.xterm')) return;

      const key = e.key;

      // Panel switching: 1-0
      if (PANEL_KEYS[key] && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        onPanelChange(PANEL_KEYS[key]);
        return;
      }

      // 'g' — navigate to graph explorer
      if (key === 'g' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        onNavigateGraph?.();
        return;
      }

      // 'e' — navigate to evidence panel
      if (key === 'e' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        onNavigateEvidence?.();
        return;
      }

      // '?' — toggle help overlay (handled by dispatching custom event)
      if (key === '?' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        document.dispatchEvent(new CustomEvent('toggle-shortcut-help'));
        return;
      }

      // Escape — close overlays
      if (key === 'Escape') {
        document.dispatchEvent(new CustomEvent('close-overlay'));
      }
    };

    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onPanelChange, onNavigateGraph, onNavigateEvidence]);
}

export const SHORTCUT_HELP: { key: string; desc: string }[] = [
  { key: '1-0', desc: 'Switch panels (Overview through Settings)' },
  { key: 'g', desc: 'Open Graph Explorer' },
  { key: 'e', desc: 'Evidence panel' },
  { key: '?', desc: 'Toggle this help' },
  { key: 'Esc', desc: 'Close overlays / forms' },
];
