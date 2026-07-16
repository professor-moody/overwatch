import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '..', '..');

function source(path: string): string {
  return readFileSync(resolve(root, path), 'utf8');
}

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
      'tools/agents.ts',
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
      'tools/agents.ts',
      'tools/engagement.ts',
      'tools/scope.ts',
      'tools/recovery.ts',
      'tools/remediation.ts',
    ].map(source).join('\n');
    expect(adapters).not.toMatch(/\bengine\.updateConfig\s*\(/);
  });
});
