// Centralized dashboard poll intervals (ms). Previously these were magic
// numbers scattered across panels (3s/5s/8s/10s); naming them here keeps the
// cadence consistent and tunable in one place. All polls should also gate on
// the WS `connected` flag so a dropped socket doesn't hammer the API.
export const POLL = {
  /** Primary operator console reconciliation (WS push is the live signal). */
  CONSOLE_PRIMARY_MS: 3000,
  /** A single-agent console drawer (lower volume, slower cadence). */
  CONSOLE_DRAWER_MS: 8000,
  /** Agent roster / fleet status. */
  AGENTS_MS: 5000,
  /** Durable planner-command status poll in the command bar. */
  PLAN_POLL_MS: 2000,
  /** Overview metrics (budget, trust signals). */
  OVERVIEW_MS: 10000,
} as const;
