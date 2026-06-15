import { useEffect } from 'react';
import type { PanelId } from '../components/layout/OperatorLayout';

const PANEL_KEYS: Record<string, PanelId> = {
  '1': 'overview',
  '2': 'frontier',
  '3': 'actions',
  '4': 'agents',
  '5': 'sessions',
  '6': 'campaigns',
  '7': 'evidence',
  '8': 'credentials',
  '9': 'paths',
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
  { key: '1-0', desc: 'Routes: Overview, Frontier, Actions, Operator, Sessions, Campaigns, Evidence, Credentials, Paths, Settings' },
  { key: 'g', desc: 'Open Graph workspace' },
  { key: 'e', desc: 'Open Evidence route' },
  { key: 'F / Space', desc: 'Graph route: fit view / pause or resume layout' },
  { key: '?', desc: 'Toggle this help' },
  { key: 'Esc', desc: 'Close overlays / forms' },
];
