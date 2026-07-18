import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import {
  buildToolDescriptor,
  buildToolRegistryManifest,
  toolCanMutateDurableState,
  toolInvocationMutatesDurableState,
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

  it('classifies every conditional invocation independently from descriptor capability', () => {
    const conditional = (name: string) => buildToolDescriptor(name, {
      description: `${name} conditional mutation.`,
      inputSchema: {},
      annotations: { ...annotations, readOnlyHint: false },
    });

    const state = conditional('get_state');
    const prompt = conditional('get_system_prompt');
    const report = conditional('generate_report');
    const retrospective = conditional('run_retrospective');
    const engagement = conditional('create_engagement');
    const scope = conditional('update_scope');
    const opsec = conditional('set_opsec');
    const campaign = conditional('manage_campaign');
    const bundle = conditional('bundle_engagement');

    for (const descriptor of [
      state,
      prompt,
      report,
      retrospective,
      engagement,
      scope,
      opsec,
      campaign,
      bundle,
    ]) {
      expect(toolCanMutateDurableState(descriptor)).toBe(true);
    }
    expect(toolInvocationMutatesDurableState(state, { snapshot: false })).toBe(false);
    expect(toolInvocationMutatesDurableState(state, { snapshot: true })).toBe(true);
    expect(toolInvocationMutatesDurableState(prompt, { snapshot: false })).toBe(false);
    expect(toolInvocationMutatesDurableState(prompt, {})).toBe(true);
    expect(toolInvocationMutatesDurableState(report, {
      write_to_disk: false,
      persist_to_archive: false,
    })).toBe(false);
    expect(toolInvocationMutatesDurableState(report, { persist_to_archive: true })).toBe(true);
    expect(toolInvocationMutatesDurableState(retrospective, { write_to_disk: false })).toBe(false);
    expect(toolInvocationMutatesDurableState(retrospective, { write_to_disk: true })).toBe(true);
    expect(toolInvocationMutatesDurableState(engagement, { dry_run: true })).toBe(false);
    expect(toolInvocationMutatesDurableState(engagement, { dry_run: false })).toBe(true);
    expect(toolInvocationMutatesDurableState(scope, { confirm: false })).toBe(false);
    expect(toolInvocationMutatesDurableState(scope, { confirm: true })).toBe(true);
    expect(toolInvocationMutatesDurableState(opsec, { confirm: false })).toBe(false);
    expect(toolInvocationMutatesDurableState(opsec, { confirm: true })).toBe(true);
    for (const action of ['status', 'check_abort', 'children', 'parent_progress']) {
      expect(toolInvocationMutatesDurableState(campaign, { action })).toBe(false);
    }
    for (const action of ['create', 'activate', 'pause', 'resume', 'abort', 'clone']) {
      expect(toolInvocationMutatesDurableState(campaign, { action })).toBe(true);
    }
    expect(toolInvocationMutatesDurableState(bundle, {})).toBe(true);
  });
});
