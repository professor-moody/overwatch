// ============================================================
// ToastContainer — stacked auto-dismissing notifications
// ============================================================

import { useToastStore, type Toast } from '../../stores/toast-store';
import { cn } from '../../lib/utils';
import { useNavigation } from '../../hooks/useNavigation';
import type { PanelId } from '../layout/OperatorLayout';
import { useLocation } from 'react-router-dom';
import { useDashboardUiStore } from '../../stores/dashboard-ui-store';

const TYPE_STYLES: Record<string, string> = {
  info: 'border-accent/40 bg-accent/5',
  success: 'border-success/40 bg-success/5',
  warning: 'border-warning/40 bg-warning/5',
  error: 'border-destructive/40 bg-destructive/5',
};

const TYPE_DOT: Record<string, string> = {
  info: 'bg-accent',
  success: 'bg-success',
  warning: 'bg-warning',
  error: 'bg-destructive',
};

export function ToastContainer() {
  const toasts = useToastStore((s) => s.toasts);
  const removeToast = useToastStore((s) => s.removeToast);
  const { navigateToPanel } = useNavigation();
  const location = useLocation();
  const graphInspectorOpen = useDashboardUiStore(s => s.graphInspectorOpen);

  if (toasts.length === 0) return null;

  const handleClick = (toast: Toast) => {
    if (toast.linkPanel) {
      navigateToPanel(toast.linkPanel as PanelId, toast.linkItem);
    }
    removeToast(toast.id);
  };

  const isGraph = location.pathname === '/graph';

  return (
    <div
      className={cn(
        'fixed z-[60] flex max-w-sm flex-col gap-2 pointer-events-none',
        isGraph
          ? cn('bottom-24 right-4', graphInspectorOpen && 'lg:right-[25rem]')
          : 'bottom-4 right-4',
      )}
    >
      {toasts.map((toast) => (
        <div
          key={toast.id}
          onClick={() => handleClick(toast)}
          className={cn(
            'pointer-events-auto border rounded-lg px-3 py-2 shadow-lg backdrop-blur-sm transition-all animate-in slide-in-from-right-5 cursor-pointer hover:brightness-110',
            TYPE_STYLES[toast.type] || TYPE_STYLES.info,
          )}
        >
          <div className="flex items-center gap-2">
            <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0', TYPE_DOT[toast.type] || TYPE_DOT.info)} />
            <span className="text-xs font-medium text-foreground">{toast.title}</span>
            <button
              onClick={(e) => { e.stopPropagation(); removeToast(toast.id); }}
              className="ml-auto text-muted-foreground hover:text-foreground text-xs"
            >
              &times;
            </button>
          </div>
          {toast.message && (
            <p className="text-[10px] text-muted-foreground mt-0.5 ml-3.5 truncate">{toast.message}</p>
          )}
        </div>
      ))}
    </div>
  );
}
