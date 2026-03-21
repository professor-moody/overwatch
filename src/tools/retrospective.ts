import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import type { SkillIndex } from '../services/skill-index.js';
import { runRetrospective } from '../services/retrospective.js';
import type { RetrospectiveInput } from '../services/retrospective.js';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';

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
3. **Scoring weight recommendations** — which frontier metrics correlated with success
4. **Attack path report** — client-deliverable markdown (timeline, findings, recommendations)
5. **RLVR training traces** — state→action→outcome triplets with reward signals

Use this at the end of an engagement or after significant progress to:
- Identify patterns that should become inference rules
- Find methodology gaps in the skill library
- Tune scoring weights for future engagements
- Generate a structured report
- Export training data for model improvement

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
    async ({ write_to_disk, output_dir }) => {
      const config = engine.getConfig();
      const graph = engine.exportGraph();
      const history = engine.getFullHistory();
      const inferenceRules = engine.getInferenceRules();
      const agents = engine.getAllAgents();
      const skillNames = skills.listSkills().map(s => s.name);

      const input: RetrospectiveInput = {
        config,
        graph,
        history,
        inferenceRules,
        agents,
        skillNames,
      };

      const result = runRetrospective(input);

      if (write_to_disk) {
        const dir = join(output_dir, config.id);
        if (!existsSync(dir)) {
          mkdirSync(dir, { recursive: true });
        }
        writeFileSync(join(dir, 'report.md'), result.report_markdown);
        writeFileSync(join(dir, 'inference-suggestions.json'), JSON.stringify(result.inference_suggestions, null, 2));
        writeFileSync(join(dir, 'skill-gaps.json'), JSON.stringify(result.skill_gaps, null, 2));
        writeFileSync(join(dir, 'scoring-recommendations.json'), JSON.stringify(result.scoring, null, 2));
        writeFileSync(join(dir, 'training-traces.json'), JSON.stringify(result.training_traces, null, 2));
        writeFileSync(join(dir, 'summary.txt'), result.summary);
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            summary: result.summary,
            inference_suggestions: result.inference_suggestions,
            skill_gaps: result.skill_gaps,
            scoring: result.scoring,
            training_traces_count: result.training_traces.length,
            report_preview: result.report_markdown.slice(0, 500) + '...',
            ...(write_to_disk ? { output_dir: join(output_dir, config.id) } : {}),
          }, null, 2)
        }]
      };
    }
  );
}
