import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { EngagementConfig } from '../../types.js';
import { registerFindingTools } from '../../tools/findings.js';
import { AgentLifecycleCommandService } from '../agent-lifecycle-command-service.js';
import { DashboardServer } from '../dashboard-server.js';
import { GraphCorrectionCommandService } from '../graph-correction-command-service.js';
import { GraphEngine } from '../graph-engine.js';
import type { PersistedPlaybookDefinitionV1 } from '../persisted-state.js';
import { PlaybookRunService } from '../playbook-run-service.js';

function config(
  objectives: EngagementConfig['objectives'] = [],
): EngagementConfig {
  return {
    id: 'pr14-restart-journeys',
    name: 'PR14 restart journeys',
    created_at: '2026-07-16T00:00:00.000Z',
    scope: { cidrs: ['10.88.0.0/24'], domains: [], exclusions: [] },
    objectives,
    opsec: { name: 'pentest', enabled: false, max_noise: 1 },
  };
}

const playbookDefinition: PersistedPlaybookDefinitionV1 = {
  definition_id: 'pr14-credential',
  definition_version: 1,
  provider: 'aws',
  title: 'PR14 credential expansion',
};

function playbookSteps(): Array<Record<string, unknown>> {
  return [{
    step: 1,
    step_id: 'identity',
    description: 'Resolve identity',
    runner: 'run_bash',
    command: 'identity-command',
    parse_with: 'identity-parser',
    parser_context: { source_credential_id: 'credential-pr14' },
    depends_on: [],
    required_bindings: [],
    produces_bindings: ['account_id'],
    ready: true,
    status: 'ready',
  }];
}

function parseToolResult(result: { content: Array<{ text?: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0]?.text ?? '{}') as Record<string, unknown>;
}

describe('PR14 explicit restart journeys', () => {
  let directory: string;
  let statePath: string;
  const engines = new Set<GraphEngine>();
  const dashboards = new Set<DashboardServer>();

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'overwatch-pr14-restart-'));
    statePath = join(directory, 'state.json');
  });

  afterEach(async () => {
    for (const dashboard of dashboards) {
      await dashboard.stop().catch(() => undefined);
    }
    dashboards.clear();
    for (const engine of engines) engine.dispose();
    engines.clear();
    rmSync(directory, { recursive: true, force: true });
  });

  function open(engagement: EngagementConfig = config()): GraphEngine {
    const engine = new GraphEngine(engagement, statePath);
    engines.add(engine);
    return engine;
  }

  function crash(engine: GraphEngine): void {
    engine.dispose();
    engines.delete(engine);
  }

  async function startDashboard(engine: GraphEngine): Promise<DashboardServer> {
    const dashboard = new DashboardServer(engine, 0, '127.0.0.1');
    dashboards.add(dashboard);
    const started = await dashboard.start();
    expect(started.started).toBe(true);
    return dashboard;
  }

  it('restores a running split-campaign child and preserves the parent roll-up', async () => {
    const first = open();
    const parent = first.createCampaign({
      name: 'Restarting split campaign',
      strategy: 'enumeration',
      item_ids: ['frontier-campaign-complete', 'frontier-campaign-running'],
      abort_conditions: [],
    });
    first.activateCampaign(parent.id);
    first.updateCampaignProgress(
      parent.id,
      'frontier-campaign-complete',
      'success',
      'finding-before-restart',
    );
    expect(first.registerAgent({
      id: 'task-campaign-running',
      agent_id: 'campaign-agent',
      assigned_at: first.now(),
      status: 'running',
      frontier_item_id: 'frontier-campaign-running',
      campaign_id: parent.id,
      subgraph_node_ids: [],
    }).ok).toBe(true);

    const children = first.splitCampaign(parent.id, 2)!;
    const completedChild = children.find(child =>
      child.items.includes('frontier-campaign-complete'))!;
    const runningChild = children.find(child =>
      child.items.includes('frontier-campaign-running'))!;
    expect(first.getTask('task-campaign-running')?.campaign_id).toBe(runningChild.id);
    expect(completedChild.status).toBe('completed');
    expect(runningChild.status).toBe('active');
    crash(first);

    const second = open();
    expect(second.getTask('task-campaign-running')).toMatchObject({
      status: 'interrupted',
      campaign_id: runningChild.id,
      frontier_item_id: 'frontier-campaign-running',
    });
    expect(second.getCampaign(completedChild.id)).toMatchObject({
      status: 'completed',
      progress: { total: 1, completed: 1, succeeded: 1, failed: 0 },
    });
    expect(second.getCampaign(runningChild.id)).toMatchObject({
      status: 'active',
      progress: { total: 1, completed: 0, succeeded: 0, failed: 0 },
    });
    expect(second.getCampaignParentProgress(parent.id)).toMatchObject({
      total: 2,
      completed: 1,
      succeeded: 1,
      failed: 0,
    });
    expect(second.deriveCampaignParentStatus(parent.id)).toBe('active');

    const dashboard = await startDashboard(second);
    const response = await fetch(`${dashboard.address}/api/campaigns/${parent.id}/children`);
    expect(response.status).toBe(200);
    const projected = await response.json() as {
      derived_status: string;
      aggregated_progress: { total: number; completed: number; succeeded: number; failed: number };
      children: Array<{ id: string; status: string; agents_total: number; agents_active: number }>;
    };
    expect(projected).toMatchObject({
      derived_status: 'active',
      aggregated_progress: { total: 2, completed: 1, succeeded: 1, failed: 0 },
    });
    expect(projected.children).toContainEqual(expect.objectContaining({
      id: runningChild.id,
      status: 'active',
      agents_total: 1,
      agents_active: 0,
    }));
  });

  it('retains an interrupted agent finding, evidence, and transcript across restart', async () => {
    const first = open();
    expect(first.registerAgent({
      id: 'task-interrupted-finding',
      agent_id: 'interrupted-agent',
      assigned_at: first.now(),
      status: 'running',
      subgraph_node_ids: [],
    }).ok).toBe(true);

    const handlers: Record<string, (args: any) => Promise<any>> = {};
    const fakeServer = {
      registerTool(name: string, _definition: unknown, handler: (args: any) => Promise<any>) {
        handlers[name] = handler;
      },
    } as unknown as McpServer;
    registerFindingTools(fakeServer, first);
    const findingOutput = 'service 443/tcp open https on 10.88.0.40';
    const findingResult = parseToolResult(await handlers.report_finding({
      agent_id: 'interrupted-agent',
      action_id: 'action-interrupted-finding',
      tool_name: 'restart-journey',
      target_node_ids: [],
      nodes: [{
        id: 'host-interrupted-finding',
        type: 'host',
        label: '10.88.0.40',
        properties: { ip: '10.88.0.40', alive: true },
      }],
      edges: [],
      raw_output: findingOutput,
    }));
    const findingId = findingResult.finding_id as string;
    const findingEvidenceId = findingResult.evidence_id as string;
    expect(findingId).toEqual(expect.any(String));
    expect(findingEvidenceId).toEqual(expect.any(String));

    const transcript = '{"role":"assistant","text":"partial result retained"}\n';
    const submitted = new AgentLifecycleCommandService(first).submitTranscript({
      task_reference: 'task-interrupted-finding',
      summary: 'Recorded the live HTTPS service before interruption.',
      transcript_jsonl: transcript,
      key_finding_ids: [findingId],
    }, {
      command_id: 'command-interrupted-transcript',
      idempotency_key: 'command-interrupted-transcript',
    });
    const transcriptEvidenceId = submitted.result?.evidence_id;
    expect(transcriptEvidenceId).toEqual(expect.any(String));
    crash(first);

    const second = open();
    expect(second.getTask('task-interrupted-finding')?.status).toBe('interrupted');
    expect(second.exportGraph().cold_nodes).toContainEqual(expect.objectContaining({
      id: 'host-10-88-0-40',
      type: 'host',
      ip: '10.88.0.40',
      alive: true,
    }));
    expect(second.getEvidenceStore().getRawOutput(findingEvidenceId)).toBe(findingOutput);
    expect(second.getEvidenceStore().getContent(transcriptEvidenceId!)).toBe(transcript);

    const findingEvent = second.getFullHistory().find(event =>
      event.event_type === 'finding_reported'
      && event.linked_finding_ids?.includes(findingId));
    expect(findingEvent).toMatchObject({
      agent_id: 'interrupted-agent',
      details: { evidence_id: findingEvidenceId },
    });
    const transcriptEvent = second.getFullHistory().find(event =>
      event.event_type === 'agent_transcript_submitted'
      && event.linked_agent_task_id === 'task-interrupted-finding');
    expect(transcriptEvent).toMatchObject({
      linked_finding_ids: [findingId],
      details: { evidence_id: transcriptEvidenceId },
    });
  });

  it('retries a failed playbook after restart without rewriting prior attempt references', () => {
    const first = open();
    const firstService = new PlaybookRunService(first);
    const opened = firstService.open({
      definition: playbookDefinition,
      credential_id: 'credential-pr14',
      normalized_inputs: {},
      steps: playbookSteps(),
    });
    const claim = firstService.startStep(opened.run.run_id, 'identity');
    firstService.beginAttemptExecution(claim.execution);
    const evidenceId = first.getEvidenceStore().store({
      action_id: claim.attempt.execution_action_id,
      finding_id: 'finding-playbook-failed',
      evidence_type: 'command_output',
      raw_output: 'identity parser returned no usable records',
    });
    const failed = firstService.finishAttempt(
      opened.run.run_id,
      'identity',
      claim.attempt.attempt_id,
      {
        execution_outcome: 'succeeded',
        parse_outcome: 'no_data',
        action_id: claim.attempt.execution_action_id,
        evidence_ids: [evidenceId],
        finding_ids: ['finding-playbook-failed'],
        error: 'The requested parser yielded no artifacts.',
      },
    );
    expect(failed.steps[0]).toMatchObject({ status: 'failed' });
    crash(first);

    const second = open();
    const secondService = new PlaybookRunService(second);
    const recoveredAttempt = secondService.getDurable(opened.run.run_id).steps[0].attempts[0];
    expect(recoveredAttempt).toMatchObject({
      attempt_id: claim.attempt.attempt_id,
      status: 'failed',
      action_id: claim.attempt.execution_action_id,
      evidence_ids: [evidenceId],
      finding_ids: ['finding-playbook-failed'],
      parse_outcome: 'no_data',
    });

    const retry = secondService.retryStep(opened.run.run_id, 'identity');
    const retried = secondService.getDurable(opened.run.run_id);
    expect(retried.steps[0].attempts).toHaveLength(2);
    expect(retried.steps[0].attempts[0]).toEqual(recoveredAttempt);
    expect(retry.attempt).toMatchObject({
      attempt_number: 2,
      status: 'claimed',
      evidence_ids: [],
      finding_ids: [],
    });
    expect(retry.attempt.attempt_id).not.toBe(claim.attempt.attempt_id);
    expect(retry.attempt.execution_action_id).not.toBe(claim.attempt.execution_action_id);
    expect(second.getEvidenceStore().getRawOutput(evidenceId))
      .toBe('identity parser returned no usable records');
  });

  it('propagates a graph correction through frontier, objective, and dashboard state after restart', async () => {
    const engagement = config([{
      id: 'objective-corrected-host',
      description: 'Obtain the corrected host',
      target_node_type: 'host',
      target_criteria: { hostname: 'corrected.internal' },
      achieved: false,
    }]);
    const first = open(engagement);
    first.addNode({
      id: 'host-correction-journey',
      type: 'host',
      label: 'Incorrect host state',
      hostname: 'corrected.internal',
      ip: '10.88.0.50',
      alive: true,
      discovered_at: '2026-07-16T00:00:01.000Z',
      confidence: 1,
    });
    expect(first.getState().objectives[0].achieved).toBe(false);
    expect(first.getState().frontier.some(item =>
      item.node_id === 'host-correction-journey')).toBe(true);

    const corrected = new GraphCorrectionCommandService(first).correct({
      reason: 'Correct liveness and record obtained access',
      action_id: 'action-correction-journey',
      operations: [{
        kind: 'patch_node',
        node_id: 'host-correction-journey',
        set_properties: {
          label: 'Corrected host state',
          alive: false,
          obtained: true,
        },
      }],
    }, {
      command_id: 'command-correction-journey',
      idempotency_key: 'command-correction-journey',
      transport: 'dashboard',
    });
    expect(corrected.result?.patched_nodes).toEqual(['host-correction-journey']);
    crash(first);

    const second = open(engagement);
    expect(second.getNode('host-correction-journey')).toMatchObject({
      label: 'Corrected host state',
      alive: false,
      obtained: true,
    });
    expect(second.getConfig().objectives[0]).toMatchObject({
      id: 'objective-corrected-host',
      achieved: true,
    });
    expect(second.getState().frontier.some(item =>
      item.node_id === 'host-correction-journey')).toBe(false);

    const dashboard = await startDashboard(second);
    const response = await fetch(`${dashboard.address}/api/state`);
    expect(response.status).toBe(200);
    const snapshot = await response.json() as {
      state: {
        objectives: Array<{ id: string; achieved: boolean }>;
        frontier: Array<{ node_id?: string }>;
      };
      graph: {
        nodes: Array<{ id: string; properties: Record<string, unknown> }>;
      };
    };
    expect(snapshot.state.objectives).toContainEqual(expect.objectContaining({
      id: 'objective-corrected-host',
      achieved: true,
    }));
    expect(snapshot.state.frontier.some(item =>
      item.node_id === 'host-correction-journey')).toBe(false);
    expect(snapshot.graph.nodes).toContainEqual(expect.objectContaining({
      id: 'host-correction-journey',
      properties: expect.objectContaining({
        label: 'Corrected host state',
        alive: false,
        obtained: true,
      }),
    }));
  });
});
