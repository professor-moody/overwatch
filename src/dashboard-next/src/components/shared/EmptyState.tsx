import { cn } from '../../lib/utils';

interface EmptyStateProps {
  /** Single-line message (legacy single-prop form). Mutually exclusive with title/description. */
  message?: string;
  /** Bold heading shown above the description. */
  title?: string;
  /** Secondary line below the title. */
  description?: string;
  children?: React.ReactNode;
  className?: string;
}

export function EmptyState({ message, title, description, children, className }: EmptyStateProps) {
  return (
    <div className={cn('bg-surface border border-border rounded-lg p-8 text-center text-sm text-muted-foreground', className)}>
      {title && <div className="text-foreground font-medium mb-1">{title}</div>}
      {description && <div>{description}</div>}
      {message && <div>{message}</div>}
      {children}
    </div>
  );
}
