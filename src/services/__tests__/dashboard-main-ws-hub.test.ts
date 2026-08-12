import { describe, expect, it, vi } from 'vitest';
import { serializeOutboundEvent } from '../dashboard-main-ws-hub.js';

// send() runs synchronously inside the WS connection handler, so a throwing .parse() on
// the outbound path is an unhandled exception that crashes the whole daemon — one bad
// event (e.g. a malformed record in the state snapshot) would DoS every connected
// operator on connect. serializeOutboundEvent must therefore DROP-and-log, never throw.
describe('serializeOutboundEvent — outbound WS contract is fail-safe, not fail-crash', () => {
  it('serializes a contract-valid event to JSON', () => {
    const msg = serializeOutboundEvent({ type: 'agent_query', timestamp: '2026-01-01T00:00:00Z', data: {} });
    expect(msg).not.toBeNull();
    expect(JSON.parse(msg!).type).toBe('agent_query');
  });

  it('drops a contract-invalid event (returns null) instead of throwing', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    // The exact shape that crashed the daemon on connect: a pending action whose
    // opsec_context.defensive_signals are strings, not {type,detected_at,description}.
    let msg: string | null = 'sentinel';
    expect(() => {
      msg = serializeOutboundEvent({
        type: 'action_pending', timestamp: '2026-01-01T00:00:00Z',
        data: { action_id: 'a1', opsec_context: { defensive_signals: ['RDP logon event 4624'] } },
      });
    }).not.toThrow();
    expect(msg).toBeNull();

    // An unknown event type is likewise dropped, not thrown.
    expect(serializeOutboundEvent({ type: 'nonsense' })).toBeNull();

    // Dropped events are logged so the drift is diagnosable, not silent.
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });
});
