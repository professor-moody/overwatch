/** Resolve the demo clock once at startup. The environment override is for
 * deterministic tests and screenshots only; interactive demos use wall time. */
export function resolveDemoNow(
  override: string | undefined,
  wallClock: () => Date = () => new Date(),
): Date {
  const resolved = override ? new Date(override) : wallClock();
  if (!Number.isFinite(resolved.getTime())) {
    throw new Error('OVERWATCH_DEMO_NOW must be a valid ISO-8601 timestamp');
  }
  return new Date(resolved.getTime());
}
