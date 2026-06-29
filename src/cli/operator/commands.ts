// ============================================================
// Operator CLI — command table (read commands)
// ============================================================

import type { ApiClient } from './client.js';
import * as render from './render.js';

export interface CommandContext {
  client: ApiClient;
  /** Command-specific args (after the command name, global flags stripped). */
  args: string[];
}

/** A command returns the subject `data` (for --json) and rendered `text`. */
export interface CommandResult {
  data: unknown;
  text: string;
}

export interface Command {
  summary: string;
  usage?: string;
  run(ctx: CommandContext): Promise<CommandResult>;
}

function flagValue(args: string[], name: string): string | undefined {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : undefined;
}

interface StateResp { state?: { frontier?: Array<{ type: string }> } }

export const READ_COMMANDS: Record<string, Command> = {
  status: {
    summary: 'Engagement snapshot: graph, objectives, agents, approvals, frontier',
    async run({ client }) {
      const data = await client.get<unknown>('/api/state');
      return { data, text: render.renderStatus(data as never) };
    },
  },
  frontier: {
    summary: 'Candidate next actions (the deterministic frontier)',
    usage: 'frontier [--max N] [--type TYPE]',
    async run({ client, args }) {
      const resp = await client.get<StateResp>('/api/state');
      let items = resp.state?.frontier ?? [];
      const type = flagValue(args, 'type');
      if (type) items = items.filter(i => i.type === type);
      const max = Number(flagValue(args, 'max') ?? '25');
      const limited = items.slice(0, Number.isFinite(max) && max > 0 ? max : 25);
      return { data: limited, text: render.renderFrontier(limited as never) };
    },
  },
  findings: {
    summary: 'Classified findings + severity summary',
    usage: 'findings [--severity critical|high|medium|low|info]',
    async run({ client, args }) {
      const resp = await client.get<{ findings: Array<{ severity: string }>; total: number; severity_summary: Record<string, number> }>('/api/findings');
      const sevFilter = flagValue(args, 'severity');
      const filtered = sevFilter ? { ...resp, findings: resp.findings.filter(f => f.severity === sevFilter) } : resp;
      return { data: filtered, text: render.renderFindings(filtered as never) };
    },
  },
  agents: {
    summary: 'Running agent roster',
    async run({ client }) {
      const resp = await client.get<{ agents: unknown[] }>('/api/agents');
      return { data: resp.agents ?? [], text: render.renderAgents((resp.agents ?? []) as never) };
    },
  },
  approvals: {
    summary: 'Pending operator approvals',
    async run({ client }) {
      const resp = await client.get<{ pending: unknown[] }>('/api/actions/pending');
      return { data: resp.pending ?? [], text: render.renderApprovals((resp.pending ?? []) as never) };
    },
  },
  opsec: {
    summary: 'OPSEC noise budget + recommended approach',
    async run({ client }) {
      const data = await client.get<unknown>('/api/opsec/budget');
      return { data, text: render.renderOpsec(data as never) };
    },
  },
  sessions: {
    summary: 'Interactive sessions',
    async run({ client }) {
      const resp = await client.get<{ sessions: unknown[] }>('/api/sessions');
      return { data: resp.sessions ?? [], text: render.renderSessions((resp.sessions ?? []) as never) };
    },
  },
  queries: {
    summary: 'Open questions agents are waiting on',
    async run({ client }) {
      const resp = await client.get<{ queries: unknown[] }>('/api/agent-queries');
      return { data: resp.queries ?? [], text: render.renderQueries((resp.queries ?? []) as never) };
    },
  },
};
