import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '..', '..');

function source(path: string): string {
  return readFileSync(resolve(root, path), 'utf8');
}

const agentToolModules = [
  'tools/agents.ts',
  'tools/agent-dispatch-tools.ts',
  'tools/agent-context-tools.ts',
  'tools/agent-transcript-tools.ts',
  'tools/agent-lifecycle-tools.ts',
  'tools/agent-steering-tools.ts',
];

describe('application-command architecture', () => {
  it('keeps dashboard domain mutations behind transport-neutral services', () => {
    const dashboard = source('services/dashboard-server.ts');
    const forbidden = [
      'this.engine.registerAgent(',
      'this.engine.updateAgentStatus(',
      'this.engine.manageCampaign(',
      'this.engine.updateConfig(',
      'this.engine.updateScope(',
      'this.engine.addObjective(',
      'this.engine.updateObjective(',
      'this.engine.removeObjective(',
      'this.engine.resolveConfigDivergence(',
      'this.engine.correctGraph(',
    ];
    for (const call of forbidden) expect(dashboard).not.toContain(call);
    for (const service of [
      'DispatchCommandService',
      'AgentLifecycleCommandService',
      'CampaignCommandService',
      'OperatorCommandService',
      'EngagementCommandService',
      'RecoveryCommandService',
      'GraphCorrectionCommandService',
      'ParseCommandService',
    ]) {
      expect(dashboard).toContain(service);
    }
  });

  it('keeps MCP mutation adapters off direct domain-engine entry points', () => {
    const adapters = [
      ...agentToolModules,
      'tools/engagement.ts',
      'tools/scope.ts',
      'tools/recovery.ts',
      'tools/remediation.ts',
      'tools/propose-plan.ts',
    ].map(source).join('\n');
    for (const call of [
      'engine.registerAgent(',
      'engine.updateAgentStatus(',
      'engine.manageCampaign(',
      'engine.updateConfig(',
      'engine.updateScope(',
      'engine.addObjective(',
      'engine.resolveConfigDivergence(',
      'engine.correctGraph(',
    ]) {
      expect(adapters).not.toContain(call);
    }
  });

  it('keeps the agent facade ordered and focused adapters independently reviewable', () => {
    const facade = source('tools/agents.ts');
    const registrations = [
      'registerSingleAgentTool',
      'registerDispatchAgentsTool',
      'registerAgentContextTool',
      'registerAgentTranscriptTool',
      'registerUpdateAgentTool',
      'registerDispatchSubnetAgentsTool',
      'registerDispatchCampaignAgentsTool',
      'registerAgentHeartbeatTool',
      'registerAskOperatorTool',
      'registerManageAgentDirectiveTool',
      'registerAcknowledgeAgentDirectiveTool',
    ];
    let previous = -1;
    for (const registration of registrations) {
      const index = facade.indexOf(`${registration}(server`);
      expect(index).toBeGreaterThan(previous);
      previous = index;
    }
    expect(facade.split('\n').length).toBeLessThan(100);
  });

  it('types high-traffic command services against explicit capability ports', () => {
    const boundaries = [
      {
        path: 'services/application-command-service.ts',
        port: 'ApplicationCommandHost',
      },
      {
        path: 'services/dispatch-command-service.ts',
        port: 'DispatchCommandPort',
      },
      {
        path: 'services/agent-lifecycle-command-service.ts',
        port: 'AgentLifecycleCommandPort',
      },
      {
        path: 'services/operator-command-service.ts',
        port: 'OperatorCommandPort',
      },
    ];
    for (const { path, port } of boundaries) {
      const commandService = source(path);
      expect(commandService).toContain(`export interface ${port}`);
      expect(commandService).toContain(`private readonly engine: ${port}`);
      expect(commandService).not.toContain("from './graph-engine.js'");
      expect(commandService).not.toMatch(/\bengine\s*:\s*GraphEngine\b/);
      expect(commandService).not.toMatch(/\bPick\s*<\s*GraphEngine\b/);
      expect(commandService).not.toMatch(/\bas\s+GraphEngine\b/);
      // An index signature would defeat the port: TypeScript must reject any
      // this.engine capability that was not deliberately declared.
      expect(commandService).not.toMatch(/\[\s*key\s*:\s*string\s*\]\s*:/);
    }
  });

  it('routes every audited external-effect surface through a durable command service', () => {
    expect(source('tools/_process-runner.ts')).toContain('ProcessCommandService');
    expect(source('tools/parse-output.ts')).toContain('ParseCommandService');
    expect(source('tools/sessions.ts')).toContain('SessionCommandService');
    expect(source('services/scripted-agent-runner.ts')).toContain(
      "command_transport: 'scripted_runner'",
    );
    expect(source('services/scripted-agent-runner.ts')).toContain(
      'idempotency_key:',
    );
  });

  it('exposes additive command identity on public retryable execution tools', () => {
    for (const path of [
      'tools/run-tool.ts',
      'tools/run-bash.ts',
      'tools/parse-output.ts',
      'tools/sessions.ts',
    ]) {
      const adapter = source(path);
      expect(adapter).toContain('command_id: z.string()');
      expect(adapter).toContain('idempotency_key: z.string()');
    }
  });

  it('contains no remaining direct config writes in tool adapters', () => {
    const adapters = [
      'tools/logging.ts',
      'tools/postgres.ts',
      ...agentToolModules,
      'tools/engagement.ts',
      'tools/scope.ts',
      'tools/recovery.ts',
      'tools/remediation.ts',
    ].map(source).join('\n');
    expect(adapters).not.toMatch(/\bengine\.updateConfig\s*\(/);
  });
});
