import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

describe('report assembly architecture', () => {
  it('uses one prepared document model instead of rebuilding findings or discarded Markdown', () => {
    const source = readFileSync(new URL('../report-assembler.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('buildFindings(');
    expect(source).not.toContain('buildReportEvidenceModel(');
    expect(source).not.toContain('generateFullReport(');
    expect(source.match(/buildReportFindingModel\(/g)).toHaveLength(1);
    expect(source.match(/renderFullReportFromModel\(/g)).toHaveLength(1);
  });
});
