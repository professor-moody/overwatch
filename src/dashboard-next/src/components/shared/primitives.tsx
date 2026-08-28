import type React from 'react';
import { Copy, X } from 'lucide-react';
import { cn } from '../../lib/utils';
import type { SourceTrust } from '../../lib/types';
import { WorkspaceInspectorPortal } from '../layout/WorkspaceInspectorHost';

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'success' | 'warning' | 'purple';
type ButtonSize = 'xs' | 'sm';
export type StatusTone = 'default' | 'accent' | 'success' | 'warning' | 'danger' | 'purple' | 'muted';

/** Honesty label: whether the thing was directly captured (observed), merely claimed
 *  (asserted), or produced by an inference rule (inferred) - so a reader tells proof
 *  from hypothesis at a glance. Shared by the evidence narrative and the node drawer. */
export function TrustBadge({ trust, className }: { trust: SourceTrust; className?: string }) {
  const cls = trust === 'observed' ? 'border-success/40 text-success'
    : trust === 'asserted' ? 'border-warning/40 text-warning'
    : 'border-border text-muted-foreground';
  const title = trust === 'observed' ? 'Directly captured from tool output - proof.'
    : trust === 'asserted' ? 'Claimed by the tool/agent, not independently captured.'
    : 'Produced by an inference rule, not a direct observation.';
  return (
    <span className={cn('rounded border px-1.5 py-0.5 text-[9px] uppercase tracking-wide', cls, className)} title={title}>
      {trust}
    </span>
  );
}

const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary: 'bg-accent text-accent-foreground border-accent hover:bg-accent/90',
  secondary: 'bg-elevated text-foreground border-border hover:bg-hover',
  ghost: 'bg-transparent text-muted-foreground border-transparent hover:bg-hover hover:text-foreground',
  danger: 'bg-destructive/10 text-destructive border-destructive/20 hover:bg-destructive/20',
  success: 'bg-success/10 text-success border-success/20 hover:bg-success/20',
  warning: 'bg-warning/10 text-warning border-warning/20 hover:bg-warning/20',
  purple: 'bg-purple-dim text-purple border-purple/20 hover:bg-purple/20',
};

const BUTTON_SIZES: Record<ButtonSize, string> = {
  xs: 'h-6 px-2 text-[11px]',
  sm: 'h-7 px-2.5 text-xs',
};

const STATUS_TONES: Record<StatusTone, string> = {
  default: 'bg-elevated text-muted-foreground',
  accent: 'bg-accent/10 text-accent',
  success: 'bg-success/10 text-success',
  warning: 'bg-warning/10 text-warning',
  danger: 'bg-destructive/10 text-destructive',
  purple: 'bg-purple-dim text-purple',
  muted: 'bg-background/70 text-muted-foreground',
};

export function MetricTile({
  label,
  value,
  sub,
  accent,
  onClick,
  dense,
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  accent?: boolean;
  onClick?: () => void;
  /** Tighter padding + smaller value for dense grids (p-3/text-xl vs p-4/text-2xl). */
  dense?: boolean;
}) {
  const Comp = onClick ? 'button' : 'div';
  return (
    <Comp
      onClick={onClick}
      className={cn(
        'bg-surface border border-border rounded-lg text-left',
        dense ? 'p-3' : 'p-4',
        onClick && 'hover:border-accent/40 hover:bg-hover/30 transition-colors cursor-pointer',
      )}
    >
      <div className="text-xs text-muted-foreground mb-1">{label}</div>
      <div className={cn('font-semibold tabular-nums', dense ? 'text-xl' : 'text-2xl', accent ? 'text-success' : 'text-foreground')}>
        {value}
      </div>
      {sub && <div className="text-xs text-muted-foreground mt-1 truncate">{sub}</div>}
    </Comp>
  );
}

export function FilterBar({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn('flex items-center gap-2 flex-wrap', className)}>{children}</div>;
}

export function ActionButton({
  children,
  variant = 'secondary',
  size = 'sm',
  active,
  className,
  type = 'button',
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  size?: ButtonSize;
  active?: boolean;
}) {
  return (
    <button
      type={type}
      className={cn(
        'inline-flex items-center justify-center gap-1.5 rounded border font-medium transition-colors whitespace-nowrap disabled:cursor-not-allowed disabled:opacity-50',
        BUTTON_SIZES[size],
        BUTTON_VARIANTS[variant],
        active && 'border-accent/50 bg-accent/15 text-accent',
        className,
      )}
      {...props}
    >
      {children}
    </button>
  );
}

/** Workspace-level heading. Unlike PageHeader this reserves a predictable band
 *  for orientation + actions and deliberately avoids a surrounding card. */
export function WorkspaceHeader({
  eyebrow,
  title,
  description,
  actions,
  children,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: React.ReactNode;
  children?: React.ReactNode;
}) {
  return (
    <header className="border-b border-border-subtle px-5 pb-3 pt-4 lg:px-6">
      <div className="flex min-w-0 items-start justify-between gap-4">
        <div className="min-w-0">
          {eyebrow && <div className="mb-1 text-[10px] font-medium uppercase tracking-[0.18em] text-accent">{eyebrow}</div>}
          <h1 className="truncate text-xl font-semibold tracking-[-0.02em] text-foreground">{title}</h1>
          {description && <p className="mt-1 max-w-3xl text-xs leading-5 text-muted-foreground">{description}</p>}
        </div>
        {actions && <div className="flex flex-shrink-0 items-center gap-2">{actions}</div>}
      </div>
      {children && <div className="mt-3">{children}</div>}
    </header>
  );
}

export function WorkspaceTabs<T extends string>({
  value,
  options,
  onChange,
  ariaLabel,
  className,
}: {
  value: T;
  options: Array<{ value: T; label: React.ReactNode; count?: number; title?: string }>;
  onChange: (value: T) => void;
  ariaLabel: string;
  className?: string;
}) {
  return (
    <div className={cn('flex min-w-0 items-center gap-1 overflow-x-auto', className)} role="tablist" aria-label={ariaLabel}>
      {options.map(option => (
        <button
          key={option.value}
          type="button"
          role="tab"
          aria-selected={value === option.value}
          title={option.title}
          onClick={() => onChange(option.value)}
          className={cn(
            'relative flex h-8 flex-shrink-0 items-center gap-1.5 rounded-md px-2.5 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/70',
            value === option.value
              ? 'bg-elevated text-foreground'
              : 'text-muted-foreground hover:bg-hover/60 hover:text-foreground',
          )}
        >
          {option.label}
          {option.count !== undefined && option.count > 0 && (
            <span className={cn(
              'min-w-4 rounded-full px-1 text-center text-[9px] tabular-nums',
              value === option.value ? 'bg-accent/15 text-accent' : 'bg-background/70 text-muted-foreground',
            )}>
              {option.count > 99 ? '99+' : option.count}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}

/** Cardless master-list row used by all four workspaces. */
export function WorkspaceRow({
  children,
  selected,
  onClick,
  className,
  title,
}: {
  children: React.ReactNode;
  selected?: boolean;
  onClick?: () => void;
  className?: string;
  title?: string;
}) {
  const Comp = onClick ? 'button' : 'div';
  return (
    <Comp
      type={onClick ? 'button' : undefined}
      title={title}
      onClick={onClick}
      className={cn(
        'group relative flex w-full min-w-0 items-center gap-3 border-b border-border-subtle px-3 py-2.5 text-left transition-colors',
        onClick && 'hover:bg-hover/45 focus-visible:z-10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/70',
        selected && 'bg-accent/[0.08] before:absolute before:inset-y-2 before:left-0 before:w-0.5 before:rounded-r before:bg-accent',
        className,
      )}
    >
      {children}
    </Comp>
  );
}

export function WorkspaceEmpty({
  title,
  detail,
  action,
}: {
  title: string;
  detail?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex min-h-56 flex-col items-center justify-center px-6 text-center">
      <div className="text-sm font-medium text-foreground">{title}</div>
      {detail && <div className="mt-1 max-w-md text-xs leading-5 text-muted-foreground">{detail}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

/** One visual and responsive contract for contextual detail across workspaces. */
export function WorkspaceInspector({
  label = 'Inspector',
  title,
  identifier,
  tabs,
  activeTab,
  onTabChange,
  onClose,
  footer,
  children,
}: {
  label?: string;
  title?: React.ReactNode;
  identifier?: string;
  tabs?: Array<{ value: string; label: React.ReactNode }>;
  activeTab?: string;
  onTabChange?: (tab: string) => void;
  onClose: () => void;
  footer?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <WorkspaceInspectorPortal>
      <button type="button" className="fixed inset-0 z-30 bg-black/45 xl:hidden" onClick={onClose} aria-label="Close inspector backdrop" />
      <aside className="workspace-inspector fixed bottom-11 right-0 top-14 z-40 flex w-[min(400px,calc(100vw-2rem))] flex-col border-l border-border-subtle bg-surface shadow-2xl transition-transform duration-150 motion-reduce:transition-none xl:static xl:z-0 xl:w-[376px] xl:flex-shrink-0 xl:shadow-none" aria-label={typeof label === 'string' ? label : 'Inspector'}>
        <div className="flex min-h-10 flex-shrink-0 items-center gap-3 border-b border-border-subtle bg-surface/95 px-3 backdrop-blur">
          <div className="min-w-0 flex-1">
            <div className="text-[10px] font-medium uppercase tracking-[0.16em] text-muted-foreground">{label}</div>
            {title && <div className="truncate text-xs font-medium text-foreground">{title}</div>}
          </div>
          <button type="button" onClick={onClose} className="rounded p-1 text-muted-foreground hover:bg-hover hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/70" aria-label="Close inspector"><X className="h-3.5 w-3.5" /></button>
        </div>
        {identifier && (
          <div className="flex flex-shrink-0 items-center gap-2 border-b border-border-subtle px-3 py-1.5 text-muted-foreground">
            <span className="min-w-0 flex-1 truncate font-mono text-[9px]" title={identifier}>{identifier}</span>
            <button
              type="button"
              className="rounded p-1 hover:bg-hover hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/70"
              aria-label="Copy identifier"
              title="Copy identifier"
              onClick={() => { void navigator.clipboard?.writeText(identifier).catch(() => undefined); }}
            >
              <Copy className="h-3 w-3" />
            </button>
          </div>
        )}
        {tabs && tabs.length > 0 && activeTab && onTabChange && (
          <div className="flex flex-shrink-0 gap-1 overflow-x-auto border-b border-border-subtle px-2 py-1.5" role="tablist" aria-label={`${label} sections`}>
            {tabs.map(tab => <button key={tab.value} type="button" role="tab" aria-selected={activeTab === tab.value} onClick={() => onTabChange(tab.value)} className={cn('h-7 flex-shrink-0 rounded px-2 text-[10px] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/70', activeTab === tab.value ? 'bg-elevated text-foreground' : 'text-muted-foreground hover:bg-hover hover:text-foreground')}>{tab.label}</button>)}
          </div>
        )}
        <div className="min-h-0 flex-1 overflow-y-auto p-3">{children}</div>
        {footer && <div className="flex-shrink-0 border-t border-border-subtle bg-surface/95 p-3">{footer}</div>}
      </aside>
    </WorkspaceInspectorPortal>
  );
}

export function SegmentedControl<T extends string>({
  value,
  options,
  onChange,
  className,
}: {
  value: T;
  options: Array<{ value: T; label: React.ReactNode; count?: number }>;
  onChange: (value: T) => void;
  className?: string;
}) {
  return (
    <div className={cn('inline-flex flex-wrap items-center gap-1 rounded-md border border-border bg-background/40 p-1', className)}>
      {options.map(option => (
        <button
          key={option.value}
          type="button"
          onClick={() => onChange(option.value)}
          className={cn(
            'inline-flex h-6 items-center gap-1 rounded px-2 text-[10px] transition-colors',
            value === option.value
              ? 'bg-accent text-accent-foreground'
              : 'text-muted-foreground hover:bg-hover hover:text-foreground',
          )}
        >
          <span>{option.label}</span>
          {option.count !== undefined && <span className="opacity-70">{option.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function DataRow({
  children,
  onClick,
  className,
}: {
  children: React.ReactNode;
  onClick?: () => void;
  className?: string;
}) {
  const Comp = onClick ? 'button' : 'div';
  return (
    <Comp
      onClick={onClick}
      className={cn(
        'w-full bg-surface border border-border rounded-lg p-3 text-left transition-colors',
        onClick && 'hover:border-accent/40 hover:bg-hover/30',
        className,
      )}
    >
      {children}
    </Comp>
  );
}

export function StatusPill({
  children,
  className,
  tone,
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & {
  children: React.ReactNode;
  className?: string;
  tone?: StatusTone;
}) {
  return (
    <span className={cn('text-[10px] px-1.5 py-0.5 rounded font-medium', tone && STATUS_TONES[tone], className)} {...props}>
      {children}
    </span>
  );
}

export function IconButton({
  children,
  label,
  active,
  className,
  onClick,
}: {
  children: React.ReactNode;
  label: string;
  active?: boolean;
  className?: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      className={cn(
        'inline-flex h-7 min-w-7 items-center justify-center rounded border border-transparent px-2 text-xs transition-colors',
        active ? 'bg-accent/20 text-accent' : 'text-muted-foreground hover:text-foreground hover:bg-hover',
        className,
      )}
    >
      {children}
    </button>
  );
}

export function DrawerShell({
  title,
  onClose,
  children,
  footer,
  subtitle,
  topOffset = 'top-12',
  className,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  footer?: React.ReactNode;
  subtitle?: React.ReactNode;
  topOffset?: string;
  className?: string;
}) {
  return (
    <aside className={cn('fixed right-0 bottom-0 z-50 w-[min(24rem,calc(100vw-3rem))] bg-surface border-l border-border shadow-xl flex flex-col', topOffset, className)}>
      <div className="px-4 py-3 border-b border-border flex items-start justify-between gap-3 flex-shrink-0">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold truncate">{title}</h3>
          {subtitle && <div className="mt-0.5 text-[10px] text-muted-foreground truncate">{subtitle}</div>}
        </div>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground text-sm" aria-label="Close">Close</button>
      </div>
      <div className="p-4 overflow-y-auto flex-1 min-h-0">{children}</div>
      {footer && <div className="flex-shrink-0 border-t border-border bg-surface/95 p-4">{footer}</div>}
    </aside>
  );
}

export const InspectorDrawer = DrawerShell;

export function EmptyPanelState({
  title,
  message,
  className,
}: {
  title?: string;
  message: string;
  className?: string;
}) {
  return (
    <div className={cn('rounded-md border border-border bg-surface p-6 text-center', className)}>
      {title && <div className="text-sm font-medium text-foreground">{title}</div>}
      <div className={cn('text-sm text-muted-foreground', title && 'mt-1')}>{message}</div>
    </div>
  );
}
