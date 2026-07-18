import { afterEach, describe, expect, it } from 'vitest';
import {
  listPendingTerminalMutations,
  pendingTerminalMutationBucket,
  resetPendingTerminalMutationsForTest,
  settlePendingTerminalMutation,
  terminalMutationGenerationKey,
} from '../session-terminal-pending';

afterEach(resetPendingTerminalMutationsForTest);

describe('page-lifetime terminal mutation registry', () => {
  const first = {
    session_id: 'session:one',
    connection_id: 'connection:one',
    connection_generation: 2,
  };

  it('retains exact pending input across component-style reacquisition', () => {
    const event = {
      type: 'input' as const,
      data: 'secret\n',
      command_id: 'command-one',
      idempotency_key: 'dashboard:ws:input:command-one',
    };
    pendingTerminalMutationBucket(first).set(event.command_id, event);
    expect(pendingTerminalMutationBucket({ ...first }).get(event.command_id))
      .toEqual(event);
    expect(listPendingTerminalMutations()).toEqual([{
      generation: first,
      command: event,
    }]);
    expect(terminalMutationGenerationKey(first)).toBe(
      terminalMutationGenerationKey({ ...first }),
    );
  });

  it('isolates connection generations and clears only terminal receipts', () => {
    const second = { ...first, connection_generation: 3 };
    pendingTerminalMutationBucket(first).set('first', {
      type: 'resize', cols: 80, rows: 24, command_id: 'first',
    });
    pendingTerminalMutationBucket(second).set('second', {
      type: 'resize', cols: 120, rows: 40, command_id: 'second',
    });

    expect(settlePendingTerminalMutation(first, 'first', 'running')).toBe(false);
    expect(pendingTerminalMutationBucket(first).has('first')).toBe(true);
    expect(settlePendingTerminalMutation(first, 'first', 'succeeded')).toBe(true);
    expect(pendingTerminalMutationBucket(second).has('second')).toBe(true);
    expect(listPendingTerminalMutations().map(item => item.command.command_id))
      .toEqual(['second']);
  });
});
