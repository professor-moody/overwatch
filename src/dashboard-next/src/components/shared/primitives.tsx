import type React from 'react';
import { cn } from '../../lib/utils';

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

export function StatusPill({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={cn('text-[10px] px-1.5 py-0.5 rounded font-medium', className)}>
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
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  return (
    <aside className="fixed right-0 top-0 bottom-0 z-50 w-[360px] bg-surface border-l border-border shadow-xl">
      <div className="h-12 px-4 border-b border-border flex items-center justify-between">
        <h3 className="text-sm font-semibold truncate">{title}</h3>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground text-sm">Close</button>
      </div>
      <div className="p-4 overflow-y-auto h-[calc(100%-3rem)]">{children}</div>
    </aside>
  );
}
