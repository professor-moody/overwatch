// ============================================================
// Overwatch — MCP Orchestrator Server
// ============================================================

import { createAppOrExit, shutdownOverwatchApp, startStdioApp, startHttpApp } from './app.js';

let app: ReturnType<typeof createAppOrExit> | undefined;
const transport = process.env.OVERWATCH_TRANSPORT
  || (process.argv.includes('--http') ? 'http' : 'stdio');

async function sharedDaemonAlreadyRunning(): Promise<boolean> {
  const port = Number(process.env.OVERWATCH_DASHBOARD_PORT || '8384');
  if (!Number.isFinite(port)) return false;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1_500);
  try {
    const response = await fetch(`http://127.0.0.1:${port}/api/health`, {
      signal: controller.signal,
    });
    if (!response.ok) return false;
    const body = await response.json() as Record<string, unknown>;
    return 'health_checks' in body || 'status' in body || 'issues' in body;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

// ============================================================
// Start Server
// ============================================================
async function main(): Promise<void> {
  if (transport !== 'http' && await sharedDaemonAlreadyRunning()) {
    throw new Error(
      'Another Overwatch instance is already running. Do not launch a second stdio writer for the same working copy. '
      + 'Run `npm run setup -- --daemon` so terminal Claude connects to the existing /mcp daemon, or stop the existing instance first.',
    );
  }
  app = createAppOrExit();
  if (transport === 'http') {
    await startHttpApp(app);
  } else {
    await startStdioApp(app);
  }
}

// Graceful shutdown
let shuttingDown = false;
async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  console.error('Shutting down Overwatch...');
  const timer = setTimeout(() => process.exit(1), 5000);
  try {
    if (app) await shutdownOverwatchApp(app);
  } catch (err) {
    console.error('Shutdown error:', err);
  } finally {
    clearTimeout(timer);
  }
  // Exit explicitly: shutdownOverwatchApp has awaited every durable flush, but the
  // stdio transport keeps process.stdin open, so without this the process lingers
  // until the SIGKILL fallback (the "graceful shutdown hangs" bug).
  process.exit(0);
}
process.on('SIGTERM', () => { void shutdown(); });
process.on('SIGINT', () => { void shutdown(); });

main().catch(error => {
  console.error('Server error:', error);
  process.exit(1);
});
