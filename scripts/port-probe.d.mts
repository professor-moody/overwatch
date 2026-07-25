/**
 * Liveness probe by connecting to a port (never binding it). Resolves true when a
 * TCP connection is accepted, false on connection-refused / short timeout / invalid
 * port. Never throws.
 */
export function portAcceptsConnection(
  port: number,
  host: string,
  timeoutMs?: number,
): Promise<boolean>;
