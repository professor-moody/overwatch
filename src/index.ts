// ============================================================
// Overwatch — MCP Orchestrator Server
// ============================================================

import { createAppOrExit, shutdownOverwatchApp, startStdioApp, startHttpApp } from './app.js';
import {
  probeRunningDashboard,
  readRuntimeBuildInfo,
  type RuntimeBuildInfo,
} from './services/runtime-build-info.js';

let app: ReturnType<typeof createAppOrExit> | undefined;
const transport = process.env.OVERWATCH_TRANSPORT
  || (process.argv.includes('--http') ? 'http' : 'stdio');

function describeBuild(build: RuntimeBuildInfo | undefined): string {
  if (!build) return 'unknown legacy build';
  const revision = build.git_sha?.slice(0, 8) || build.input_sha256.slice(0, 12);
  return `${revision} (PID ${build.runtime_pid || 'unknown'})`;
}

// ============================================================
// Start Server
// ============================================================
async function main(): Promise<void> {
  const dashboardPort = Number(process.env.OVERWATCH_DASHBOARD_PORT || '8384');
  const dashboardHost = process.env.OVERWATCH_DASHBOARD_HOST || '127.0.0.1';
  const dashboardToken = process.env.OVERWATCH_DASHBOARD_TOKEN;
  const existing = await probeRunningDashboard(
    dashboardPort,
    fetch,
    undefined,
    dashboardToken ? `Bearer ${dashboardToken}` : undefined,
    dashboardHost,
  );
  if (existing.running && transport === 'http') {
    const localBuild = readRuntimeBuildInfo();
    const mismatch = localBuild && existing.runtime_build
      && localBuild.input_sha256 !== existing.runtime_build.input_sha256;
    throw new Error(
      `An Overwatch daemon is already running on dashboard port ${dashboardPort} `
      + `(${describeBuild(existing.runtime_build)}). `
      + (mismatch
        ? `It does not match this checkout (${describeBuild(localBuild)}). Stop the old daemon, then start again and reload the dashboard tab.`
        : 'Reuse it, or stop it before starting another daemon.'),
    );
  }
  if (existing.running) {
    throw new Error(
      'Another Overwatch instance is already running. Do not launch a second stdio writer for the same working copy. '
      + 'Run `npm run setup` so terminal Claude connects to the existing /mcp daemon, or stop the existing instance first.',
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
