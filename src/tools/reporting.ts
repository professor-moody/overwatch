import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import type { SkillIndex } from '../services/skill-index.js';
import { assembleReport, type ReportFormat } from '../services/report-assembler.js';
import { validateFilePath } from '../utils/path-validation.js';
import { join } from 'path';
import { withErrorBoundary } from './error-boundary.js';
import {
  publishArtifactGenerationDurable,
  type ArtifactGenerationPublication,
} from '../services/artifact-generation.js';

export function registerReportingTools(server: McpServer, engine: GraphEngine, skills: SkillIndex): void {

  // ============================================================
  // Tool: generate_report
  // Full pentest report with per-finding detail, narrative, evidence
  // ============================================================
  server.registerTool(
    'generate_report',
    {
      title: 'Generate Pentest Report',
      description: `Generate a comprehensive penetration test report from the engagement graph and activity history.

Produces a client-deliverable report with:
- **Executive summary** with severity distribution
- **Per-finding sections** — each compromised host, credential, and vulnerability gets its own section with evidence and auto-generated remediation
- **Attack narrative** — chronological prose description of the engagement phases (Recon → Initial Access → Lateral Movement → PrivEsc → Objective)
- **Compliance mapping** — CWE, OWASP Top 10, NIST 800-53, PCI DSS tables
- **MITRE ATT&CK** — technique coverage and optional Navigator layer export
- **Risk heatmap** — severity × category distribution
- **Remediation priority ranking** — CVSS × blast radius × credential exposure
- **Evidence chains** — command → tool output → graph mutation linkage for each finding
- **Credential chains** — derivation paths showing how credentials were obtained
- **Objectives status** and recommendations

Use this at the end of an engagement to produce the final deliverable report.

When writing to output_dir, the returned generation_path and pointer_path are
the checksummed authority. Fixed report.* and attack-navigator.json paths are
post-commit compatibility mirrors.`,
      inputSchema: {
        format: z.enum(['markdown', 'md', 'html', 'json', 'pdf']).default('markdown')
          .describe('Output format: markdown (or md), html, json (structured findings data), or pdf (HTML rendered through headless Chromium via puppeteer-core; requires a chromium binary).'),
        include_evidence: z.boolean().default(true)
          .describe('Include evidence chains for each finding'),
        include_narrative: z.boolean().default(true)
          .describe('Include attack narrative section'),
        include_retrospective: z.boolean().default(false)
          .describe('Include retrospective analysis (inference gaps, skill gaps)'),
        include_compliance: z.boolean().default(true)
          .describe('Include compliance mapping (CWE, OWASP, NIST, PCI) and ATT&CK techniques'),
        include_attack_navigator: z.boolean().default(false)
          .describe('Generate ATT&CK Navigator layer JSON file (requires write_to_disk)'),
        include_gap_analysis: z.boolean().default(false)
          .describe('Include ATT&CK coverage gap analysis section in the report'),
        write_to_disk: z.boolean().default(false)
          .describe('Save report file(s) to output_dir'),
        output_dir: z.string().default('./reports/')
          .describe('Directory for output files (used when write_to_disk is true)'),
        theme: z.enum(['light', 'dark']).default('light')
          .describe('Theme for HTML output'),
        client_safe: z.boolean().default(false)
          .describe('Produce a client-deliverable variant. Strips cred_value, raw_output, stdout/stderr previews, and operator-machine paths from the rendered report. Output files get a `.client-safe.<ext>` suffix when written to disk. Defaults to false so the operator-internal report is unchanged.'),
        profile: z.enum(['operator', 'client']).optional()
          .describe('Report profile. operator keeps full proof metadata; client defaults to client-safe deliverable language and redaction. client_safe:true maps to profile=client for backward compatibility.'),
        evidence_style: z.enum(['proof_cards', 'appendix', 'full_inline']).default('proof_cards')
          .describe('Evidence presentation style: proof_cards in findings, appendix-first references, or full_inline raw previews for operator binders.'),
        include_attack_paths: z.boolean().default(true)
          .describe('Include synthesized attack-path chains from current access to each engagement objective. Decorated with per-edge confidence and inferred-vs-confirmed flags.'),
        max_paths_per_objective: z.number().int().min(1).max(20).default(3)
          .describe('Cap on attack paths rendered per objective (top-K by confidence).'),
        persist_to_archive: z.boolean().default(true)
          .describe('Write the rendered report to the engagement\'s persistent report archive (`<engagement-dir>/reports/`). The returned `report_id` can be fetched later through the dashboard report endpoints.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      }
    },
    withErrorBoundary('generate_report', async ({
      format: rawFormat, include_evidence, include_narrative,
      include_retrospective, include_compliance, include_attack_navigator,
      include_gap_analysis, write_to_disk, output_dir, theme, client_safe,
      profile, evidence_style,
      include_attack_paths, max_paths_per_objective, persist_to_archive,
    }) => {
      const config = engine.getConfig();
      const format = (rawFormat === 'md' ? 'markdown' : rawFormat) as ReportFormat | 'pdf';
      const assembleFormat: ReportFormat = format === 'pdf' ? 'html' : format;
      const evidenceStyle = evidence_style ?? 'proof_cards';
      const assembled = assembleReport(engine, skills, {
        format: assembleFormat,
        include_evidence,
        include_narrative,
        include_retrospective,
        include_compliance,
        include_attack_navigator,
        include_gap_analysis,
        include_attack_paths,
        max_paths_per_objective,
        theme,
        client_safe: client_safe === true,
        profile,
        evidence_style: evidenceStyle,
      });

      let pdfBuffer: Buffer | undefined;
      if (format === 'pdf') {
        try {
          const { renderReportPdf } = await import('../services/report-pdf.js');
          pdfBuffer = await renderReportPdf(assembled.content, { format: 'A4', printBackground: true });
        } catch (err) {
          return {
            content: [{ type: 'text', text: JSON.stringify({ error: `PDF rendering failed: ${err instanceof Error ? err.message : String(err)}` }, null, 2) }],
            isError: true,
          };
        }
      }

      const output = assembled.content;
      const stored: string | Buffer = format === 'pdf' ? pdfBuffer! : output;
      let diskPublication: ArtifactGenerationPublication | undefined;

      if (write_to_disk) {
        let validatedDir: string;
        try {
          validatedDir = validateFilePath(join(output_dir, config.id));
        } catch (error) {
          return {
            content: [{ type: 'text', text: JSON.stringify({ error: `Invalid output_dir: ${error instanceof Error ? error.message : String(error)}` }, null, 2) }],
            isError: true,
          };
        }
        // PDF rendering and path validation may take time; gate the actual
        // generation commit at the last possible boundary.
        engine.assertPersistenceWritable();
        const suffix = assembled.redaction_mode === 'client_safe' ? '.client-safe' : '';
        const ext = format === 'markdown' ? 'md' : format;
        const reportName = `report${suffix}.${ext}`;
        const files: Record<string, { content: string | Buffer; media_type?: string }> = {
          [reportName]: {
            content: stored,
            media_type: format === 'pdf' ? 'application/pdf'
              : format === 'html' ? 'text/html'
              : format === 'json' ? 'application/json'
              : 'text/markdown',
          },
        };
        if (include_attack_navigator && assembled.navigator_layer) {
          files['attack-navigator.json'] = {
            content: `${JSON.stringify(assembled.navigator_layer, null, 2)}\n`,
            media_type: 'application/json',
          };
        }
        const legacyNames = [
          'report.md', 'report.html', 'report.json', 'report.pdf',
          'report.client-safe.md', 'report.client-safe.html',
          'report.client-safe.json', 'report.client-safe.pdf',
          'attack-navigator.json',
        ];
        engine.registerArtifactGenerationRecovery({
          root: validatedDir,
          namespace: 'report',
          legacy_names: legacyNames,
        });
        diskPublication = publishArtifactGenerationDurable({
          root: validatedDir,
          namespace: 'report',
          files,
          legacy_names: legacyNames,
        });
      }

      let archivedReportId: string | undefined;
      let archiveReferencePersisted: boolean | undefined;
      let archiveCommitted: boolean | undefined;
      let archiveCommitDurability: 'confirmed' | 'uncertain' | undefined;
      let aggregateManifestPersisted: boolean | undefined;
      let archivePersistenceWarning: string | undefined;
      if (persist_to_archive) {
        try {
          engine.assertPersistenceWritable();
          const archive = engine.getReportArchive();
          const record = archive.add(stored, {
            generated_at: new Date().toISOString(),
            format,
            redaction_mode: assembled.redaction_mode,
            profile: assembled.profile,
            evidence_style: evidenceStyle,
            findings_count: assembled.findings_count,
            evidence_count: assembled.evidence_count,
            options: {
              include_evidence,
              include_narrative,
              include_retrospective,
              include_compliance,
              include_attack_paths,
              include_attack_navigator,
              include_gap_analysis,
              profile: assembled.profile,
              evidence_style: evidenceStyle,
              theme: format === 'html' || format === 'pdf' ? theme : undefined,
            },
          });
          archivedReportId = record.id;
          archiveCommitDurability = record.commit_durability;
          archiveCommitted = record.commit_durability === 'confirmed';
          aggregateManifestPersisted = record.manifest_persisted;
          if (record.warning) archivePersistenceWarning = record.warning;
          if (record.commit_durability === 'confirmed') {
            try {
              engine.logActionEvent({
                description: `Report archived: ${record.id}`,
                event_type: 'system',
                category: 'system',
                details: {
                  report_id: record.id,
                  report_format: record.format,
                  report_size_bytes: record.size_bytes,
                  report_sha256: record.content_sha256,
                },
              });
              engine.flushNow();
              archiveReferencePersisted = true;
            } catch (error) {
              archiveReferencePersisted = false;
              const checkpointWarning = `Report bytes were archived, but the state artifact reference could not be checkpointed: ${error instanceof Error ? error.message : String(error)}`;
              archivePersistenceWarning = archivePersistenceWarning
                ? `${archivePersistenceWarning} ${checkpointWarning}`
                : checkpointWarning;
            }
          } else archiveReferencePersisted = false;
        } catch (error) {
          if (!diskPublication) throw error;
          archiveCommitted = false;
          aggregateManifestPersisted = false;
          archiveReferencePersisted = false;
          archivePersistenceWarning = `Disk generation committed, but engagement-archive publication failed: ${error instanceof Error ? error.message : String(error)}`;
        }
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            format,
            profile: assembled.profile,
            redaction_mode: assembled.redaction_mode,
            findings_count: assembled.findings_count,
            evidence_count: assembled.evidence_count,
            severity_summary: assembled.severity_summary,
            report_preview: output.slice(0, 800) + (output.length > 800 ? '...' : ''),
            report_length: Buffer.isBuffer(stored) ? stored.byteLength : stored.length,
            ...(archivedReportId ? { report_id: archivedReportId } : {}),
            ...(archiveCommitted !== undefined ? { archive_committed: archiveCommitted } : {}),
            ...(archiveCommitDurability !== undefined ? { archive_commit_durability: archiveCommitDurability } : {}),
            ...(aggregateManifestPersisted !== undefined
              ? { aggregate_manifest_persisted: aggregateManifestPersisted }
              : {}),
            ...(archiveReferencePersisted !== undefined ? { archive_reference_persisted: archiveReferencePersisted } : {}),
            ...(archivePersistenceWarning ? { warning: archivePersistenceWarning } : {}),
            ...(write_to_disk ? { output_dir: join(output_dir, config.id) } : {}),
            ...(diskPublication ? {
              generation_id: diskPublication.generation_id,
              generation_committed: diskPublication.generation_committed,
              generation_pointer_visible: diskPublication.pointer_visible,
              generation_path: diskPublication.generation_path,
              generation_manifest: diskPublication.generation_manifest,
              pointer_path: diskPublication.pointer_path,
              generation_commit_durability: diskPublication.commit_durability,
              legacy_mirror_complete: diskPublication.legacy_mirror_complete,
            } : {}),
            ...(diskPublication?.warning ? {
              output_warning: diskPublication.warning,
            } : {}),
          }, null, 2),
        }],
      };
    })
  );
}
