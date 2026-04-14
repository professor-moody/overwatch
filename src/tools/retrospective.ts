import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import type { SkillIndex } from '../services/skill-index.js';
import { runRetrospective } from '../services/retrospective.js';
import type { RetrospectiveInput } from '../services/retrospective.js';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { withErrorBoundary } from './error-boundary.js';
import { validateFilePath } from '../utils/path-validation.js';

export function registerRetrospectiveTools(server: McpServer, engine: GraphEngine, skills: SkillIndex): void {

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

Optionally write all outputs to disk for archival.`,
      inputSchema: {
        write_to_disk: z.boolean().default(false)
          .describe('Save report + traces to files in output_dir'),
        output_dir: z.string().default('./retrospective/')
          .describe('Directory for output files (used when write_to_disk is true)'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
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
        if (!existsSync(validatedDir)) {
          mkdirSync(validatedDir, { recursive: true });
        }
        writeFileSync(join(validatedDir, 'report.md'), result.report_markdown);
        writeFileSync(join(validatedDir, 'inference-suggestions.json'), JSON.stringify(result.inference_suggestions, null, 2));
        writeFileSync(join(validatedDir, 'skill-gaps.json'), JSON.stringify(result.skill_gaps, null, 2));
        writeFileSync(join(validatedDir, 'context-improvements.json'), JSON.stringify(result.context_improvements, null, 2));
        writeFileSync(join(validatedDir, 'training-traces.json'), JSON.stringify(result.training_traces, null, 2));
        writeFileSync(join(validatedDir, 'trace-quality.json'), JSON.stringify(result.trace_quality, null, 2));
        writeFileSync(join(validatedDir, 'summary.txt'), result.summary);
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
            report_preview: result.report_markdown.slice(0, 500) + '...',
            ...(write_to_disk ? { output_dir: join(output_dir, config.id) } : {}),
          }, null, 2)
        }]
      };
    })
  );
}
