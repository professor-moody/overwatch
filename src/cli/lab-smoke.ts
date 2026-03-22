#!/usr/bin/env node
// ============================================================
// Overwatch — Dev Lab Smoke Harness
// Usage: npm run lab:smoke [-- --keep-state --verbose]
// ============================================================

import { parseLabSmokeArgs, runLabSmoke } from './lab-smoke-lib.js';

function summarizeCounts(summary: Record<string, unknown>): string {
  const nodes = Number(summary.total_nodes || 0);
  const edges = Number(summary.total_edges || 0);
  return `${nodes} nodes / ${edges} edges`;
}

async function main(): Promise<void> {
  const options = parseLabSmokeArgs(process.argv.slice(2));
  const report = await runLabSmoke(options);

  console.log('Fixture: goad-synth');
  console.log(`Preflight: ${report.preflight.status}`);
  console.log(`Graph before ingest: ${report.graph_stage.before_ingest} (${summarizeCounts(report.graph_summary.before_ingest)})`);
  console.log(`Graph after ingest: ${report.graph_stage.after_ingest} (${summarizeCounts(report.graph_summary.after_ingest)})`);
  console.log(`Graph after restart: ${report.graph_stage.after_restart} (${summarizeCounts(report.graph_summary.after_restart)})`);
  console.log(`Health after ingest: ${report.graph_health.after_ingest.status}`);
  console.log(`Health after restart: ${report.graph_health.after_restart.status}`);
  console.log(`Restart preservation: ${report.restart_check.passed ? 'pass' : 'fail'}`);
  console.log(`Provenance host: ${report.provenance.host_label} (${report.provenance.passed ? 'pass' : 'fail'})`);
  console.log(`Retrospective logging quality: ${report.retrospective.logging_quality_status}`);
  console.log(`Retrospective trace quality: ${report.retrospective.trace_quality_status}`);
  console.log(`Output dir: ${report.output_dir}`);
  console.log(`Report: ${report.report_file}`);

  if (options.verbose) {
    console.log('');
    console.log(report.retrospective.summary);
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Lab smoke failed: ${message}`);
  if (parseLabSmokeArgs(process.argv.slice(2)).verbose && error instanceof Error && error.stack) {
    console.error(error.stack);
  }
  process.exit(1);
});
