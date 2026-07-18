import { describe, expect, it } from 'vitest';
import {
  AgentDtoSchema,
  AgentDuplicatesResponseSchema,
  AgentHandoffRequestSchema,
  AgentHandoffResponseSchema,
  AgentMergeRequestSchema,
  AgentMergeResponseSchema,
  AgentSplitRequestSchema,
  AgentSplitResponseSchema,
  CampaignActionRequestSchema,
  CampaignCreateRequestSchema,
  CampaignListResponseSchema,
  CampaignSplitRequestSchema,
  ConfigDivergenceResolveRequestSchema,
  ConfigDivergenceResolveResponseSchema,
  FRONTIER_TYPES,
  FrontierListDtoSchema,
  ObjectiveCreateRequestSchema,
  RecoveryStatusResponseSchema,
  SettingsPatchSchema,
} from '../dashboard-v1.js';

const metrics = (confidence: number) => ({
  hops_to_objective: 1,
  fan_out_estimate: 2,
  node_degree: 3,
  confidence,
});

const base = (id: string, type: string, confidence: number) => ({
  id,
  type,
  description: `${type} candidate`,
  graph_metrics: metrics(confidence),
  opsec_noise: 0.2,
  staleness_seconds: 0,
});

const frontierFixtures = [
  { ...base('z-node', 'incomplete_node', 0.2), node_id: 'host-1' },
  { ...base('a-untested', 'untested_edge', 9), edge_source: 'cred-1', edge_target: 'host-1', edge_type: 'VALID_ON' },
  { ...base('m-inferred', 'inferred_edge', 1.2), edge_source: 'user-1', edge_target: 'host-2', edge_type: 'ADMIN_TO' },
  { ...base('b-cidr', 'network_discovery', 0.1), target_cidr: '10.0.0.0/24' },
  { ...base('pivot', 'network_pivot', 0.6), node_id: 'host-3', pivot_host_id: 'host-2', via_pivot: 'user-1' },
  { ...base('credential', 'credential_test', 0.5), node_id: 'service-1', credential_id: 'cred-1' },
  { ...base('idp', 'idp_enumeration', 0.7), node_id: 'idp-1' },
  { ...base('mfa', 'mfa_bypass_candidate', 0.4), node_id: 'cred-2', credential_id: 'cred-2' },
  { ...base('tier', 'cross_tier_pivot', 0.8), edge_source: 'app-1', edge_target: 'cloud-1', edge_type: 'BACKED_BY' },
  { ...base('cve', 'cve_research', 0.9), node_id: 'service-2' },
  { ...base('domain', 'domain_enumeration', 1), node_id: 'domain-1' },
];

describe('dashboard v1 contracts', () => {
  it('accepts every canonical frontier kind and target shape', () => {
    const parsed = FrontierListDtoSchema.parse(frontierFixtures);
    expect(parsed.map(item => item.type)).toEqual(FRONTIER_TYPES);
  });

  it('preserves server order regardless of ids and score multipliers', () => {
    const parsed = FrontierListDtoSchema.parse(frontierFixtures);
    expect(parsed.map(item => item.id)).toEqual(frontierFixtures.map(item => item.id));
    expect(parsed.map(item => item.graph_metrics.confidence)).toEqual(frontierFixtures.map(item => item.graph_metrics.confidence));
  });

  it('keeps mutation bodies strict', () => {
    expect(CampaignCreateRequestSchema.safeParse({ name: 'x', strategy: 'custom', item_ids: ['fi-1'], items: [] }).success).toBe(false);
    expect(CampaignActionRequestSchema.safeParse({ action: 'complete' }).success).toBe(false);
    expect(CampaignSplitRequestSchema.safeParse({ count: 1 }).success).toBe(false);
    expect(SettingsPatchSchema.safeParse({ enabled: true, time_window: null, ignored: true }).success).toBe(false);
    expect(ConfigDivergenceResolveRequestSchema.safeParse({
      resolution: 'use_state',
      expected_file_hash: 'a'.repeat(64),
      expected_state_hash: 'b'.repeat(64),
      ignored: true,
    }).success).toBe(false);
  });

  it('keeps terminal-source work-shaping inputs strict and bounded', () => {
    const successor = {
      archetype: 'web_tester',
      objective: 'Continue from the retained evidence',
    };
    expect(AgentHandoffRequestSchema.safeParse({
      ...successor,
      summary: 'The source completed discovery and is ready for a specialist.',
    }).success).toBe(true);
    expect(AgentHandoffRequestSchema.safeParse({
      ...successor,
      summary: 'ready',
      source_task_id: 'source-is-owned-by-the-path',
    }).success).toBe(false);
    expect(AgentHandoffRequestSchema.safeParse({ ...successor, summary: 'x'.repeat(4_097) }).success).toBe(false);

    const child = (id: number) => ({
      archetype: 'recon_scanner',
      objective: `Survey partition ${id}`,
      target_node_ids: [`node-${id}`],
    });
    expect(AgentSplitRequestSchema.safeParse({
      summary: 'Partition the terminal source scope.',
      children: [child(1), child(2)],
    }).success).toBe(true);
    expect(AgentSplitRequestSchema.safeParse({ summary: 'too small', children: [child(1)] }).success).toBe(false);
    expect(AgentSplitRequestSchema.safeParse({
      summary: 'too large',
      children: Array.from({ length: 21 }, (_, index) => child(index)),
    }).success).toBe(false);
    expect(AgentSplitRequestSchema.safeParse({
      summary: 'strict children',
      children: [{ ...child(1), parent_task_id: 'path-owned' }, child(2)],
    }).success).toBe(false);

    expect(AgentMergeRequestSchema.safeParse({
      summary: 'Retain one canonical result.',
      duplicate_task_ids: ['duplicate-1'],
    }).success).toBe(true);
    expect(AgentMergeRequestSchema.safeParse({
      summary: 'No repeated task IDs.',
      duplicate_task_ids: ['duplicate-1', 'duplicate-1'],
    }).success).toBe(false);
    expect(AgentMergeRequestSchema.safeParse({
      summary: 'Canonical identity is path-owned.',
      duplicate_task_ids: ['duplicate-1'],
      canonical_task_id: 'canonical-1',
    }).success).toBe(false);
  });

  it('projects additive durable work metadata through agents and work-shaping envelopes', () => {
    const signature = 'a'.repeat(64);
    const work = {
      version: 1 as const,
      root_task_id: 'root-task',
      signature,
      origin_frontier_item_id: 'frontier-1',
      relation: {
        kind: 'handoff' as const,
        source_task_id: 'source-task',
        created_at: '2026-07-17T12:00:00.000Z',
        summary: 'Discovery handed to a specialist.',
        key_finding_ids: ['finding-1'],
        key_evidence_ids: ['evidence-1'],
        key_event_ids: ['event-1'],
      },
      future_work_field: 'additive',
    };
    const task = {
      task_id: 'successor-task',
      agent_label: 'specialist',
      id: 'successor-task',
      agent_id: 'specialist',
      status: 'pending' as const,
      assigned_at: '2026-07-17T12:00:00.000Z',
      queued: true,
      lifecycle: 'queued' as const,
      live: false,
      subgraph_node_ids: ['node-1'],
      findings_count: 0,
      work,
      merged_source_task_ids: ['duplicate-task'],
    };
    const parsedTask = AgentDtoSchema.parse(task);
    expect(parsedTask.work?.relation?.source_task_id).toBe('source-task');
    expect(parsedTask.work?.signature).toBe(signature);
    expect((parsedTask.work as unknown as Record<string, unknown>).future_work_field).toBe('additive');
    expect(AgentDtoSchema.safeParse({
      ...task,
      work: {
        ...work,
        relation: {
          ...work.relation,
          summary: undefined,
        },
      },
    }).success).toBe(false);

    const createdTask = {
      task_id: task.task_id,
      agent_label: task.agent_label,
      id: task.id,
      agent_id: task.agent_id,
      status: task.status,
      assigned_at: task.assigned_at,
      subgraph_node_ids: task.subgraph_node_ids,
      work,
    };
    const command = { command_id: 'command-1', idempotency_key: 'key-1', replayed: false };
    expect(AgentHandoffResponseSchema.safeParse({
      operation: 'handoff', source_task_id: 'source-task', created_tasks: [createdTask], warnings: [], reused_existing: false, ...command,
      future_response_field: 'additive',
    }).success).toBe(true);
    expect(AgentHandoffResponseSchema.safeParse({
      operation: 'handoff', source_task_id: 'source-task', created_tasks: [{ ...createdTask, work: undefined }], warnings: [], reused_existing: false, ...command,
    }).success).toBe(false);
    expect(AgentSplitResponseSchema.safeParse({
      operation: 'split', source_task_id: 'source-task', created_tasks: [createdTask, { ...createdTask, id: 'child-2', task_id: 'child-2' }], warnings: [], reused_existing: false, ...command,
    }).success).toBe(true);
    expect(AgentMergeResponseSchema.safeParse({
      operation: 'merge', canonical_task_id: 'successor-task', updated_tasks: [createdTask, { ...createdTask, id: 'duplicate-task', task_id: 'duplicate-task', work: { ...work, merged_into_task_id: 'successor-task' } }], warnings: [], reused_existing: false, ...command,
    }).success).toBe(true);
    expect(AgentHandoffResponseSchema.safeParse({
      operation: 'handoff', source_task_id: 'source-task', created_tasks: [createdTask], warnings: [], ...command,
    }).success).toBe(false);
    expect(AgentDuplicatesResponseSchema.safeParse({
      groups: [{
        signature: work.signature,
        canonical_task_id: task.task_id,
        candidate_task_ids: [task.task_id, 'duplicate-task'],
        tasks: [task, { ...task, task_id: 'duplicate-task', id: 'duplicate-task' }],
        future_group_field: 'additive',
      }],
      total: 1,
      future_response_field: 'additive',
    }).success).toBe(true);
    expect(AgentDuplicatesResponseSchema.safeParse({
      groups: [{
        signature,
        canonical_task_id: 'missing-canonical',
        candidate_task_ids: [task.task_id, 'duplicate-task'],
        tasks: [task, { ...task, task_id: 'duplicate-task', id: 'duplicate-task' }],
      }],
      total: 1,
    }).success).toBe(false);
    expect(AgentDuplicatesResponseSchema.safeParse({
      groups: [{
        signature,
        canonical_task_id: task.task_id,
        candidate_task_ids: [task.task_id, 'duplicate-task'],
        tasks: [task, {
          ...task,
          task_id: 'duplicate-task',
          id: 'duplicate-task',
          work: { ...work, signature: 'b'.repeat(64) },
        }],
      }],
      total: 1,
    }).success).toBe(false);
  });

  it('validates recovery reconciliation hashes and permits additive status fields', () => {
    expect(ConfigDivergenceResolveRequestSchema.safeParse({
      resolution: 'use_file',
      expected_file_hash: 'not-a-hash',
      expected_state_hash: 'b'.repeat(64),
    }).success).toBe(false);
    expect(ConfigDivergenceResolveRequestSchema.safeParse({
      resolution: 'use_file',
      expected_file_hash: 'a'.repeat(64),
      expected_state_hash: 'b'.repeat(64),
    }).success).toBe(true);

    const parsed = RecoveryStatusResponseSchema.parse({
      recovery: {
        outcome: 'incomplete',
        source: 'state',
        complete: false,
        writable: false,
        state_recovery: {
          outcome: 'clean',
          source: 'state',
          complete: true,
          writable: true,
          highest_allocated_logical_seq: 2,
          highest_allocated_frame_seq: 8,
          highest_physical_frame_seq: 8,
          highest_contiguous_applied_logical_seq: 2,
        },
        reason: 'configuration reconciliation is required',
        base_checkpoint: 2,
        highest_allocated_seq: 2,
        highest_allocated_logical_seq: 2,
        highest_allocated_frame_seq: 8,
        highest_on_disk_seq: 2,
        highest_physical_frame_seq: 8,
        highest_contiguous_applied_seq: 2,
        highest_contiguous_applied_logical_seq: 2,
        consecutive_persistence_failures: 0,
        journal: {
          enabled: true,
          format_version: 1,
          read: 0,
          attempted: 0,
          applied: 0,
          skipped: 0,
          failed: 0,
          malformed: false,
          preserved: true,
          future_journal_field: true,
        },
        state_migration: {
          status: 'blocked',
          supported_state_version: 1,
          supported_journal_version: 1,
          observed_state_version: 2,
          observed_journal_version: 0,
          migration_required: false,
          reason: 'future state version',
          future_migration_field: 'additive',
        },
        runtime_ownership_warnings: [{
          run_id: 'run-unresolved',
          pid: 4242,
          lifecycle: 'unknown',
          message: 'PID identity could not be verified.',
          future_runtime_field: 'additive',
        }],
        artifact_recovery: {
          reports: {
            writable: false,
            uncertain_deletion_ids: ['report-ambiguous'],
            reason: 'ambiguous deletion tombstone',
            future_report_recovery_field: 'additive',
          },
          generation_warnings: [{
            root: '/tmp/reports',
            namespace: 'report',
            message: 'mirror refresh pending',
            future_generation_field: 'additive',
          }],
          future_artifact_field: 'additive',
        },
        config_recovery: {
          status: 'diverged',
          resolution_required: true,
          intent_present: false,
          file_valid: true,
          file_revision: 2,
          state_revision: 1,
          file_hash: 'a'.repeat(64),
          state_hash: 'b'.repeat(64),
          allowed_resolutions: ['use_file', 'use_state'],
          conflicted_intent: {
            archive_path: '/tmp/engagement.json.write-intent.json.conflict-audit.json',
            intent_sha256: 'c'.repeat(64),
            intent_checksum: 'd'.repeat(64),
            reason: 'intent and file describe different durable states',
            observed_file_hash: 'a'.repeat(64),
            observed_state_hash: 'b'.repeat(64),
            future_conflict_field: 'additive',
          },
          future_config_field: 'additive',
        },
        future_recovery_field: 'additive',
      },
      future_envelope_field: 'additive',
    });
    expect(parsed.recovery.config_recovery?.future_config_field).toBe('additive');
    expect(parsed.recovery.state_migration?.future_migration_field).toBe('additive');
    expect(parsed.recovery.runtime_ownership_warnings?.[0]).toMatchObject({
      run_id: 'run-unresolved',
      pid: 4242,
      future_runtime_field: 'additive',
    });
    expect(parsed.recovery.artifact_recovery).toMatchObject({
      reports: { writable: false, future_report_recovery_field: 'additive' },
      generation_warnings: [{ future_generation_field: 'additive' }],
      future_artifact_field: 'additive',
    });
    expect(parsed.recovery.config_recovery?.conflicted_intent?.future_conflict_field).toBe('additive');
    expect(parsed.recovery.future_recovery_field).toBe('additive');
    expect(parsed.recovery).toMatchObject({
      highest_allocated_logical_seq: 2,
      highest_allocated_frame_seq: 8,
      highest_physical_frame_seq: 8,
      highest_contiguous_applied_logical_seq: 2,
      state_recovery: {
        highest_allocated_frame_seq: 8,
        highest_physical_frame_seq: 8,
      },
    });
    expect(RecoveryStatusResponseSchema.safeParse({
      recovery: {
        ...parsed.recovery,
        config_recovery: {
          ...parsed.recovery.config_recovery,
          conflicted_intent: {
            ...parsed.recovery.config_recovery?.conflicted_intent,
            intent_sha256: 'not-a-hash',
          },
        },
      },
    }).success).toBe(false);

    const resolution = ConfigDivergenceResolveResponseSchema.parse({
      resolved: true,
      mode: 'use_file',
      config: {
        id: 'engagement-1',
        config_revision: 3,
        config_hash: 'c'.repeat(64),
        future_config_key: true,
      },
      recovery: {
        status: 'recovered',
        resolution_required: false,
        intent_present: false,
        future_status_key: 'additive',
      },
      future_response_key: 'additive',
    });
    expect(resolution.recovery.future_status_key).toBe('additive');
    expect(resolution.future_response_key).toBe('additive');
    expect(ConfigDivergenceResolveResponseSchema.safeParse({
      resolved: true,
      mode: 'use_file',
      config: { id: 'engagement-1' },
      recovery: { status: 'recovered', resolution_required: false, intent_present: false },
    }).success).toBe(false);
  });

  it('matches core settings bounds without narrowing existing timeout compatibility', () => {
    expect(SettingsPatchSchema.safeParse({ max_noise: 1.5 }).success).toBe(false);
    expect(SettingsPatchSchema.safeParse({ time_window: { start_hour: 99, end_hour: 2.5 } }).success).toBe(false);
    expect(SettingsPatchSchema.safeParse({ approval_timeout_ms: 5_000 }).success).toBe(true);
    expect(SettingsPatchSchema.safeParse({ approval_timeout_ms: 7_200_000 }).success).toBe(true);
  });

  it('rejects objective graph vocabulary outside the canonical node and edge enums', () => {
    expect(ObjectiveCreateRequestSchema.safeParse({
      description: 'Reach admin', target_node_type: 'not_a_node',
    }).success).toBe(false);
    expect(ObjectiveCreateRequestSchema.safeParse({
      description: 'Reach admin', achievement_edge_types: ['NOT_AN_EDGE'],
    }).success).toBe(false);
    expect(ObjectiveCreateRequestSchema.safeParse({
      description: 'Reach admin', target_node_type: 'host', achievement_edge_types: ['ADMIN_TO'],
    }).success).toBe(true);
  });

  it('permits additive response fields while validating campaign envelopes', () => {
    const campaign = {
      id: 'camp-1', name: 'Campaign', strategy: 'custom', status: 'draft', items: ['fi-1'],
      abort_conditions: [], progress: { total: 1, completed: 0, succeeded: 0, failed: 0, consecutive_failures: 0 },
      findings: [], created_at: '2026-07-15T00:00:00Z',
      agent_count: 0, running_agents: 0, agents_total: 0, agents_active: 0,
      completion_pct: 0, findings_count: 0,
      opsec: {
        global_noise_spent: 0, noise_budget_remaining: 1, max_noise: 1,
        recommended_approach: 'normal', defensive_signals: [],
      },
      future_field: 'additive',
    };
    const parsed = CampaignListResponseSchema.parse({ campaigns: [campaign], total: 1, next_cursor: null });
    expect(parsed.campaigns[0].future_field).toBe('additive');
  });
});
