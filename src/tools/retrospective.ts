import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import type { SkillIndex } from '../services/skill-index.js';
import { runRetrospective } from '../services/retrospective.js';
import type { RetrospectiveInput } from '../services/retrospective.js';
import { join } from 'path';
import { withErrorBoundary, getTelemetry } from './error-boundary.js';
import { validateFilePath } from '../utils/path-validation.js';
import {
  publishArtifactGenerationDurable,
  type ArtifactGenerationPublication,
} from '../services/artifact-generation.js';

export function registerRetrospectiveTools(server: McpServer, engine: GraphEngine, skills: SkillIndex, getToolNames?: () => string[]): void {

  // ============================================================
  // Tool: run_retrospective
  // Post-engagement analysis producing structured outputs
  // ============================================================
  server.registerTool(
    'run_retrospective',
    {
      title: 'Run Retrospective Analysis',
      description: `Perform a structured post-engagement retrospective analysis.

Produces five outputs:
1. **Inference rule suggestions** — patterns the graph shows that existing rules missed
2. **Skill gap analysis** — skills unused vs. techniques attempted without skills
3. **Context-improvement recommendations** — where context, logging, validation, and coverage should improve
4. **Attack path report** — client-deliverable markdown (timeline, findings, recommendations)
5. **Heuristic RLVR traces** — state→action→outcome triplets with explicit confidence and trace quality

Use this at the end of an engagement or after significant progress to:
- Identify patterns that should become inference rules
- Find methodology gaps in the skill library
- Improve context, evidence quality, validation guidance, and logging for future runs
- Generate a structured report
- Export heuristic training telemetry for model improvement

Optionally write all outputs to disk for archival. The returned generation_path
and pointer_path identify the checksummed authoritative set; fixed filenames are
post-commit compatibility mirrors.`,
      inputSchema: {
        write_to_disk: z.boolean().default(false)
          .describe('Save report + traces to files in output_dir'),
        output_dir: z.string().default('./retrospective/')
          .describe('Directory for output files (used when write_to_disk is true)'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      }
    },
    withErrorBoundary('run_retrospective', async ({ write_to_disk, output_dir }) => {
      const config = engine.getConfig();
      const graph = engine.exportGraph();
      const history = engine.getFullHistory();
      const inferenceRules = engine.getInferenceRules();
      const agents = engine.getAllAgents();
      const allSkills = skills.listSkills();
      const skillNames = allSkills.map(s => s.name);
      const skillTags = allSkills.flatMap(s => s.tags);

      const input: RetrospectiveInput = {
        config,
        graph,
        history,
        inferenceRules,
        agents,
        skillNames,
        skillTags,
      };

      const result = runRetrospective(input);

      // Attach tool telemetry if available
      const telemetry = getTelemetry();
      if (telemetry) {
        result.tool_telemetry = telemetry.summarize(getToolNames ? getToolNames() : []);
      }

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
        // Analysis can remain read-only, but the filesystem commit must be
        // rejected if recovery degraded while the retrospective was running.
        engine.assertPersistenceWritable();
        const files: Record<string, { content: string; media_type?: string }> = {
          'report.md': { content: result.report_markdown, media_type: 'text/markdown' },
          'inference-suggestions.json': { content: `${JSON.stringify(result.inference_suggestions, null, 2)}\n`, media_type: 'application/json' },
          'skill-gaps.json': { content: `${JSON.stringify(result.skill_gaps, null, 2)}\n`, media_type: 'application/json' },
          'context-improvements.json': { content: `${JSON.stringify(result.context_improvements, null, 2)}\n`, media_type: 'application/json' },
          'training-traces.json': { content: `${JSON.stringify(result.training_traces, null, 2)}\n`, media_type: 'application/json' },
          'trace-quality.json': { content: `${JSON.stringify(result.trace_quality, null, 2)}\n`, media_type: 'application/json' },
          'summary.txt': { content: result.summary, media_type: 'text/plain' },
        };
        if (result.tool_telemetry) {
          files['tool-telemetry.json'] = { content: `${JSON.stringify(result.tool_telemetry, null, 2)}\n`, media_type: 'application/json' };
        }
        const legacyNames = [
          'report.md', 'inference-suggestions.json', 'skill-gaps.json',
          'context-improvements.json', 'training-traces.json',
          'trace-quality.json', 'summary.txt', 'tool-telemetry.json',
        ];
        engine.registerArtifactGenerationRecovery({
          root: validatedDir,
          namespace: 'retrospective',
          legacy_names: legacyNames,
        });
        diskPublication = publishArtifactGenerationDurable({
          root: validatedDir,
          namespace: 'retrospective',
          files,
          legacy_names: legacyNames,
        });
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            summary: result.summary,
            inference_suggestions: result.inference_suggestions,
            skill_gaps: result.skill_gaps,
            context_improvements: result.context_improvements,
            training_traces_count: result.training_traces.length,
            trace_quality: result.trace_quality,
            tool_telemetry: result.tool_telemetry,
            report_preview: result.report_markdown.slice(0, 500) + '...',
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
            ...(diskPublication?.warning ? { output_warning: diskPublication.warning } : {}),
          }, null, 2)
        }]
      };
    })
  );
}
