import type React from 'react';
import { cn } from '../../lib/utils';

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'success' | 'warning' | 'purple';
type ButtonSize = 'xs' | 'sm';
export type StatusTone = 'default' | 'accent' | 'success' | 'warning' | 'danger' | 'purple' | 'muted';

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

export function PageHeader({
  title,
  meta,
  actions,
}: {
  title: string;
  meta?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-3 flex-wrap">
      <h2 className="text-lg font-semibold">
        {title}
        {meta && <span className="text-muted-foreground font-normal text-sm ml-2">{meta}</span>}
      </h2>
      {actions && <div className="flex items-center gap-2 flex-wrap">{actions}</div>}
    </div>
  );
}

export function PanelSection({
  title,
  meta,
  children,
  className,
}: {
  title?: string;
  meta?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={cn('bg-surface border border-border rounded-lg p-4', className)}>
      {title && (
        <h3 className="text-sm font-medium mb-3">
          {title}
          {meta && <span className="text-muted-foreground font-normal ml-1">{meta}</span>}
        </h3>
      )}
      {children}
    </section>
  );
}

export function MetricTile({
  label,
  value,
  sub,
  accent,
  onClick,
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  accent?: boolean;
  onClick?: () => void;
}) {
  const Comp = onClick ? 'button' : 'div';
  return (
    <Comp
      onClick={onClick}
      className={cn(
        'bg-surface border border-border rounded-lg p-4 text-left',
        onClick && 'hover:border-accent/40 hover:bg-hover/30 transition-colors cursor-pointer',
      )}
    >
      <div className="text-xs text-muted-foreground mb-1">{label}</div>
      <div className={cn('text-2xl font-semibold tabular-nums', accent ? 'text-success' : 'text-foreground')}>
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
