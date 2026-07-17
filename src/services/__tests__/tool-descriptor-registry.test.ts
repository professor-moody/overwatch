import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import {
  buildToolDescriptor,
  buildToolRegistryManifest,
  toolRequiresWritablePersistence,
} from '../tool-descriptor-registry.js';

const annotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};

describe('canonical tool descriptor registry', () => {
  it('hashes semantically identical input schemas deterministically', () => {
    const left = buildToolDescriptor('get_state', {
      description: 'Operational briefing.',
      inputSchema: { snapshot: z.boolean().optional(), activity_count: z.number().optional() },
      annotations,
    });
    const right = buildToolDescriptor('get_state', {
      description: 'Operational briefing.',
      inputSchema: { activity_count: z.number().optional(), snapshot: z.boolean().optional() },
      annotations,
    });

    expect(left.input_schema_sha256).toBe(right.input_schema_sha256);
    expect(left.output_schema).toBeNull();
    expect(left.output_schema_sha256).toBeNull();
  });

  it('normalizes required-field declaration order as a schema set', () => {
    const left = buildToolDescriptor('get_state', {
      description: 'Operational briefing.',
      inputSchema: { snapshot: z.boolean(), activity_count: z.number() },
      annotations,
    });
    const right = buildToolDescriptor('get_state', {
      description: 'Operational briefing.',
      inputSchema: { activity_count: z.number(), snapshot: z.boolean() },
      annotations,
    });

    expect(left.input_schema_sha256).toBe(right.input_schema_sha256);
  });

  it('changes the registry hash when a public schema changes', () => {
    const before = buildToolDescriptor('get_state', {
      description: 'Operational briefing.',
      inputSchema: { snapshot: z.boolean().optional() },
      annotations,
    });
    const after = buildToolDescriptor('get_state', {
      description: 'Operational briefing.',
      inputSchema: { snapshot: z.boolean().optional(), activity_count: z.number().optional() },
      annotations,
    });

    expect(buildToolRegistryManifest([before]).registry_sha256)
      .not.toBe(buildToolRegistryManifest([after]).registry_sha256);
  });

  it('rejects uncategorized tools and incomplete annotation metadata', () => {
    expect(() => buildToolDescriptor('not_registered', {
      description: 'unknown',
      inputSchema: {},
      annotations,
    })).toThrow('no canonical category');
    expect(() => buildToolDescriptor('get_state', {
      description: 'incomplete',
      inputSchema: {},
      annotations: { readOnlyHint: true },
    })).toThrow('all four MCP annotations');
  });

  it('models conditional snapshot writes and the recovery-only reconciliation command', () => {
    const state = buildToolDescriptor('get_state', {
      description: 'Operational briefing.',
      inputSchema: { snapshot: z.boolean().optional() },
      annotations,
    });
    const reconcile = buildToolDescriptor('resolve_config_divergence', {
      description: 'Reconcile config.',
      inputSchema: {},
      annotations: { ...annotations, readOnlyHint: false },
    });

    expect(toolRequiresWritablePersistence(state, { snapshot: false })).toBe(false);
    expect(toolRequiresWritablePersistence(state, { snapshot: true })).toBe(true);
    expect(toolRequiresWritablePersistence(reconcile, {})).toBe(false);
  });

  it('gates only report/retrospective publication while allowing diagnostic bundles', () => {
    const mutatingAnnotations = { ...annotations, readOnlyHint: false };
    const report = buildToolDescriptor('generate_report', {
      description: 'Generate report.', inputSchema: {}, annotations: mutatingAnnotations,
    });
    const retrospective = buildToolDescriptor('run_retrospective', {
      description: 'Run retrospective.', inputSchema: {}, annotations: mutatingAnnotations,
    });
    const bundle = buildToolDescriptor('bundle_engagement', {
      description: 'Bundle engagement.', inputSchema: {}, annotations: mutatingAnnotations,
    });
    expect(toolRequiresWritablePersistence(report, {
      write_to_disk: false, persist_to_archive: false,
    })).toBe(false);
    expect(toolRequiresWritablePersistence(report, { persist_to_archive: true })).toBe(true);
    expect(toolRequiresWritablePersistence(retrospective, { write_to_disk: false })).toBe(false);
    expect(toolRequiresWritablePersistence(retrospective, { write_to_disk: true })).toBe(true);
    expect(toolRequiresWritablePersistence(bundle, {})).toBe(false);
  });
});
