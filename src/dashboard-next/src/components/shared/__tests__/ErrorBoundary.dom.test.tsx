import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ErrorBoundary } from '../ErrorBoundary';

describe('ErrorBoundary DOM containment', () => {
  it('contains a panel exception and retries the child without blanking navigation', async () => {
    let shouldThrow = true;
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    function Child() {
      if (shouldThrow) throw new Error('synthetic render failure');
      return <div>Recovered panel</div>;
    }

    render(
      <ErrorBoundary fallbackLabel="Credentials">
        <Child />
      </ErrorBoundary>,
    );
    expect(screen.getByText('Credentials crashed')).toBeInTheDocument();
    expect(screen.getByText('synthetic render failure')).toBeInTheDocument();
    shouldThrow = false;
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(screen.getByText('Recovered panel')).toBeInTheDocument();
    expect(consoleError).toHaveBeenCalled();
  });
});
