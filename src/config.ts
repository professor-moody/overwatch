import { readFileSync, readdirSync, existsSync } from 'fs';
import { join, resolve } from 'path';
import { ZodError } from 'zod';
import { engagementConfigSchema, type EngagementConfig, type EngagementPhase } from './types.js';

export function parseEngagementConfig(raw: string): EngagementConfig {
  return engagementConfigSchema.parse(JSON.parse(raw));
}

export function loadEngagementConfigFile(configPath: string): EngagementConfig {
  return parseEngagementConfig(readFileSync(configPath, 'utf-8'));
}

// --- Engagement Templates ---

export interface EngagementTemplate {
  id: string;
  name: string;
  description: string;
  profile: string;
  opsec: Record<string, unknown>;
  scope: Record<string, unknown>;
  objectives: Record<string, unknown>[];
  recommended_skills: string[];
  phases?: EngagementPhase[];
}

function getTemplatesDir(): string {
  return resolve(join(__dirname, '..', 'engagement-templates'));
}

export function listTemplates(): EngagementTemplate[] {
  const dir = getTemplatesDir();
  if (!existsSync(dir)) return [];
  const files = readdirSync(dir).filter(f => f.endsWith('.json'));
  return files.map(f => {
    const raw = JSON.parse(readFileSync(join(dir, f), 'utf-8'));
    return {
      id: raw.id,
      name: raw.name,
      description: raw.description || '',
      profile: raw.profile || '',
      opsec: raw.opsec || {},
      scope: raw.scope || {},
      objectives: raw.objectives || [],
      recommended_skills: raw.recommended_skills || [],
      phases: raw.phases,
    };
  });
}

export function loadTemplate(templateId: string): EngagementTemplate | null {
  const dir = getTemplatesDir();
  const filePath = join(dir, `${templateId}.json`);
  if (!existsSync(filePath)) return null;
  const raw = JSON.parse(readFileSync(filePath, 'utf-8'));
  return {
    id: raw.id,
    name: raw.name,
    description: raw.description || '',
    profile: raw.profile || '',
    opsec: raw.opsec || {},
    scope: raw.scope || {},
    objectives: raw.objectives || [],
    recommended_skills: raw.recommended_skills || [],
    phases: raw.phases,
  };
}

export function mergeTemplateWithConfig(
  template: EngagementTemplate,
  overrides: Partial<EngagementConfig> & { id: string; name: string; created_at: string },
): EngagementConfig {
  const merged = {
    id: overrides.id,
    name: overrides.name,
    created_at: overrides.created_at,
    template: template.id,
    profile: overrides.profile ?? template.profile,
    scope: {
      cidrs: overrides.scope?.cidrs ?? (template.scope as any).cidrs ?? [],
      domains: overrides.scope?.domains ?? (template.scope as any).domains ?? [],
      exclusions: overrides.scope?.exclusions ?? (template.scope as any).exclusions ?? [],
      ...overrides.scope,
    },
    objectives: overrides.objectives ?? template.objectives as any[],
    opsec: {
      ...template.opsec,
      ...overrides.opsec,
    },
    phases: overrides.phases ?? template.phases,
  };
  return engagementConfigSchema.parse(merged);
}

export function formatConfigError(error: unknown, source: string): string {
  if (error instanceof SyntaxError) {
    return `Invalid JSON in engagement config (${source}): ${error.message}`;
  }

  if (error instanceof ZodError) {
    const issues = error.issues.map(issue => {
      const path = issue.path.length > 0 ? issue.path.join('.') : '(root)';
      return `- ${path}: ${issue.message}`;
    });
    return [
      `Invalid engagement config (${source}):`,
      ...issues,
    ].join('\n');
  }

  return `Failed to load engagement config (${source}): ${error instanceof Error ? error.message : String(error)}`;
}
