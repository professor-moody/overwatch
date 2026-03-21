import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SkillIndex } from '../services/skill-index.js';

export function registerSkillTools(server: McpServer, skills: SkillIndex): void {

  // ============================================================
  // Tool: get_skill
  // RAG-based skill retrieval for methodology guidance.
  // ============================================================
  server.registerTool(
    'get_skill',
    {
      title: 'Get Skill',
      description: `Search the skill library for methodology guidance relevant to a scenario.

Use when you encounter a service, vulnerability, or attack scenario and want structured
guidance on how to approach it. Examples:
- "smb relay signing disabled" → returns SMB relay methodology
- "kerberos service accounts" → returns Kerberoasting methodology
- "web application tomcat" → returns web discovery methodology

You can also list all available skills or retrieve a specific skill by ID.`,
      inputSchema: {
        query: z.string().optional().describe('Search query to find relevant skills'),
        skill_id: z.string().optional().describe('Retrieve a specific skill by ID'),
        list_all: z.boolean().default(false).describe('List all available skills'),
        max_results: z.number().int().min(1).max(10).default(3)
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async ({ query, skill_id, list_all, max_results }) => {
      if (list_all) {
        const allSkills = skills.listSkills();
        return {
          content: [{ type: 'text', text: JSON.stringify({ skills: allSkills }, null, 2) }]
        };
      }

      if (skill_id) {
        const content = skills.getSkillContent(skill_id);
        if (!content) {
          return { content: [{ type: 'text', text: `Skill not found: ${skill_id}` }] };
        }
        return { content: [{ type: 'text', text: content }] };
      }

      if (query) {
        const matches = skills.search(query, max_results);
        if (matches.length === 0) {
          return { content: [{ type: 'text', text: `No skills found matching: ${query}` }] };
        }

        // Return the top match's full content, plus summaries of others
        const topContent = skills.getSkillContent(matches[0].id);
        const result = {
          top_match: {
            id: matches[0].id,
            name: matches[0].name,
            score: matches[0].score,
            content: topContent
          },
          other_matches: matches.slice(1).map(m => ({
            id: m.id,
            name: m.name,
            score: m.score,
            excerpt: m.excerpt
          }))
        };
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      }

      return { content: [{ type: 'text', text: 'Provide a query, skill_id, or set list_all=true' }] };
    }
  );
}
