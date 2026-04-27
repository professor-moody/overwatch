import { cn } from '../../lib/utils';

export function EmptyState({
  message,
  children,
  className,
}: {
  message: string;
  children?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('bg-surface border border-border rounded-lg p-8 text-center text-sm text-muted-foreground', className)}>
      {message}
      {children}
    </div>
  );
}
