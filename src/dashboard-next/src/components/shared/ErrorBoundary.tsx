import { Component, type ReactNode, type ErrorInfo } from 'react';

interface Props {
  children: ReactNode;
  fallbackLabel?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`[ErrorBoundary${this.props.fallbackLabel ? ` (${this.props.fallbackLabel})` : ''}]`, error, info.componentStack);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="bg-surface border border-destructive/30 rounded-lg p-6 text-center">
          <div className="text-sm font-medium text-destructive mb-2">
            {this.props.fallbackLabel || 'Component'} crashed
          </div>
          <div className="text-xs text-muted-foreground mb-3 max-w-sm mx-auto break-all">
            {this.state.error?.message || 'Unknown error'}
          </div>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            className="text-xs px-3 py-1.5 rounded bg-accent/10 text-accent hover:bg-accent/20 transition-colors"
          >
            Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
