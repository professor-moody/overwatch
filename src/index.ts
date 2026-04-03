// ============================================================
// Overwatch — MCP Orchestrator Server
// ============================================================

import { createAppOrExit, shutdownOverwatchApp, startStdioApp, startHttpApp } from './app.js';

const app = createAppOrExit();

// ============================================================
// Start Server
// ============================================================
async function main(): Promise<void> {
  const transport = process.env.OVERWATCH_TRANSPORT || (process.argv.includes('--http') ? 'http' : 'stdio');

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
    await shutdownOverwatchApp(app);
  } finally {
    clearTimeout(timer);
  }
}
process.on('SIGTERM', () => { void shutdown(); });
process.on('SIGINT', () => { void shutdown(); });

main().catch(error => {
  console.error('Server error:', error);
  process.exit(1);
});
