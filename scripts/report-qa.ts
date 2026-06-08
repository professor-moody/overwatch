#!/usr/bin/env npx tsx
// Generate deterministic report QA artifacts without starting the dashboard.

import { mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { assembleReport, type ReportFormat } from '../src/services/report-assembler.js';
import { isPdfRenderingAvailable, renderReportPdf } from '../src/services/report-pdf.js';
import { createReportQaFixture, REPORT_QA_SECRET_MARKERS } from '../src/services/report-qa-fixture.js';

type Artifact = {
  name: string;
  path: string;
  bytes: number;
  profile?: 'operator' | 'client';
  format?: string;
};

const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const outDir = process.env.OVERWATCH_REPORT_QA_DIR || join('tmp', 'report-qa', stamp);
mkdirSync(outDir, { recursive: true });

const fixture = createReportQaFixture({ rootDir: join(outDir, 'fixture') });
const artifacts: Artifact[] = [];

function writeArtifact(name: string, content: string | Buffer, meta: Omit<Artifact, 'name' | 'path' | 'bytes'> = {}): string {
  const path = join(outDir, name);
  writeFileSync(path, content);
  artifacts.push({
    name,
    path,
    bytes: Buffer.isBuffer(content) ? content.byteLength : Buffer.byteLength(content),
    ...meta,
  });
  return path;
}

function assemble(name: string, format: ReportFormat, profile: 'operator' | 'client'): string {
  const assembled = assembleReport(fixture.engine, fixture.skills, {
    format,
    profile,
    client_safe: profile === 'client',
    evidence_style: 'proof_cards',
    include_attack_paths: true,
    include_compliance: true,
    include_evidence: true,
    include_narrative: true,
  });
  writeArtifact(name, assembled.content, { profile, format });
  return assembled.content;
}

const clientHtml = assemble('client.html', 'html', 'client');
const operatorHtml = assemble('operator.html', 'html', 'operator');
const operatorMarkdown = assemble('operator.md', 'markdown', 'operator');
const operatorJson = assemble('operator.json', 'json', 'operator');
const clientJson = assemble('client.json', 'json', 'client');

const redactionFailures = REPORT_QA_SECRET_MARKERS.filter(marker =>
  clientHtml.includes(marker) || clientJson.includes(marker),
);
if (redactionFailures.length > 0) {
  throw new Error(`Client report leaked secret marker(s): ${redactionFailures.join(', ')}`);
}
if (!clientHtml.includes('class="proof-card"') || !clientHtml.includes('Evidence Appendix')) {
  throw new Error('Client HTML report did not include proof cards and evidence appendix.');
}
if (!operatorHtml.includes('Raw preview') || !operatorMarkdown.includes('Raw preview')) {
  throw new Error('Operator reports did not expose raw evidence previews.');
}
const parsedOperatorJson = JSON.parse(operatorJson) as { report_profile?: string; evidence_appendix?: unknown[] };
if (parsedOperatorJson.report_profile !== 'operator' || !Array.isArray(parsedOperatorJson.evidence_appendix) || parsedOperatorJson.evidence_appendix.length === 0) {
  throw new Error('Operator JSON report missing profile or evidence appendix.');
}

const pdfStatus = isPdfRenderingAvailable();
let pdf: { status: 'rendered' | 'skipped'; executable?: string; reason?: string } = { status: 'skipped', reason: pdfStatus.error };
if (pdfStatus.available) {
  const buffer = await renderReportPdf(clientHtml, { format: 'A4', printBackground: true });
  writeArtifact('client.pdf', buffer, { profile: 'client', format: 'pdf' });
  pdf = { status: 'rendered', executable: pdfStatus.executable };
} else {
  writeArtifact('client-pdf.skipped.txt', `PDF rendering skipped: ${pdfStatus.error}\n`, { profile: 'client', format: 'pdf' });
}

const manifest = {
  generated_at: new Date().toISOString(),
  output_dir: outDir,
  fixture_state: fixture.stateFilePath,
  pdf,
  artifacts,
};
writeArtifact('manifest.json', `${JSON.stringify(manifest, null, 2)}\n`, { format: 'json' });

console.log(`Report QA artifacts written to ${outDir}`);
for (const artifact of artifacts) {
  console.log(`- ${artifact.name} (${artifact.bytes.toLocaleString()} bytes)`);
}
if (pdf.status === 'skipped') {
  console.log(`PDF skipped: ${pdf.reason}`);
}
