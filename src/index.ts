// ============================================================
// Overwatch — MCP Orchestrator Server
// ============================================================

import { createAppOrExit, shutdownOverwatchApp, startStdioApp } from './app.js';

const app = createAppOrExit();

// ============================================================
// Start Server
// ============================================================
async function main(): Promise<void> {
  await startStdioApp(app);
}

// Graceful shutdown
let shuttingDown = false;
async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  console.error('Shutting down Overwatch...');
  await shutdownOverwatchApp(app);
  process.exit(0);
}
process.on('SIGTERM', () => { void shutdown(); });
process.on('SIGINT', () => { void shutdown(); });

main().catch(error => {
  console.error('Server error:', error);
  process.exit(1);
});
