import { readFileSync } from 'fs';
import { ZodError } from 'zod';
import { engagementConfigSchema, type EngagementConfig } from './types.js';

export function parseEngagementConfig(raw: string): EngagementConfig {
  return engagementConfigSchema.parse(JSON.parse(raw));
}

export function loadEngagementConfigFile(configPath: string): EngagementConfig {
  return parseEngagementConfig(readFileSync(configPath, 'utf-8'));
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
