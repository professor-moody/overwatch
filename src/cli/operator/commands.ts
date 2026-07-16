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

// Flags that take a value (so their value isn't mistaken for a positional).
const VALUE_FLAGS = new Set([
  'url', 'token', 'reason', 'archetype', 'skill', 'type', 'max', 'severity', 'node',
  'file-hash', 'state-hash',
]);

const SHA256_RE = /^[0-9a-f]{64}$/;

/** Positional (non-flag) args, skipping `--flag value` pairs and boolean flags. */
function positionals(args: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) {
      if (VALUE_FLAGS.has(a.slice(2))) i++; // skip its value
      continue;
    }
    out.push(a);
  }
  return out;
}

/** All values of a repeatable value-flag (e.g. --node a --node b). */
function multiFlag(args: string[], name: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === `--${name}` && i + 1 < args.length) out.push(args[++i]);
  }
  return out;
}

function requireFirst(args: string[], label: string): string {
  const p = positionals(args)[0];
  if (!p) throw new Error(`Missing required <${label}>.`);
  return p;
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
  recovery: {
    summary: 'Persistence and active configuration recovery status',
    async run({ client }) {
      const data = await client.get<unknown>('/api/recovery');
      return { data, text: render.renderRecovery(data as never) };
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

export const WRITE_COMMANDS: Record<string, Command> = {
  config: {
    summary: 'Reconcile active configuration using explicit file or state authority',
    usage: 'config reconcile <use_file|use_state> --file-hash SHA256 --state-hash SHA256',
    async run({ client, args }) {
      const positional = positionals(args);
      if (positional[0] !== 'reconcile') {
        throw new Error('Expected `config reconcile <use_file|use_state>`.');
      }
      const resolution = positional[1];
      if (resolution !== 'use_file' && resolution !== 'use_state') {
        throw new Error('Resolution must be `use_file` or `use_state`.');
      }
      const expectedFileHash = flagValue(args, 'file-hash');
      const expectedStateHash = flagValue(args, 'state-hash');
      if (!expectedFileHash || !SHA256_RE.test(expectedFileHash)) {
        throw new Error('Missing or invalid --file-hash; inspect `overwatch recovery` and pass its 64-character lowercase SHA-256 observation.');
      }
      if (!expectedStateHash || !SHA256_RE.test(expectedStateHash)) {
        throw new Error('Missing or invalid --state-hash; inspect `overwatch recovery` and pass its 64-character lowercase SHA-256 hash.');
      }
      const data = await client.post<unknown>('/api/recovery/config/resolve', {
        resolution,
        expected_file_hash: expectedFileHash,
        expected_state_hash: expectedStateHash,
      });
      return { data, text: render.ok(`Configuration reconciled using ${resolution === 'use_file' ? 'file' : 'durable state'} authority.`) };
    },
  },
  approve: {
    summary: 'Approve a pending action',
    usage: 'approve <action-id>',
    async run({ client, args }) {
      const id = requireFirst(args, 'action-id');
      const data = await client.post<unknown>(`/api/actions/${encodeURIComponent(id)}/approve`, {});
      return { data, text: render.ok(`Approved ${id}`) };
    },
  },
  deny: {
    summary: 'Deny a pending action',
    usage: 'deny <action-id> [--reason TEXT]',
    async run({ client, args }) {
      const id = requireFirst(args, 'action-id');
      const reason = flagValue(args, 'reason');
      const data = await client.post<unknown>(`/api/actions/${encodeURIComponent(id)}/deny`, { reason });
      return { data, text: render.ok(`Denied ${id}${reason ? ` (${reason})` : ''}`) };
    },
  },
  answer: {
    summary: 'Answer an agent\'s question',
    usage: 'answer <query-id> <answer text…>',
    async run({ client, args }) {
      const pos = positionals(args);
      const id = pos[0];
      const answer = pos.slice(1).join(' ');
      if (!id) throw new Error('Missing required <query-id>.');
      if (!answer) throw new Error('Missing required <answer text>.');
      const data = await client.post<{ ok: boolean }>(`/api/agent-queries/${encodeURIComponent(id)}/answer`, { answer });
      return { data, text: render.ok(`Answered ${id}`) };
    },
  },
  deploy: {
    summary: 'Quick-deploy an agent at a raw IP/CIDR/domain (auto-scopes)',
    usage: 'deploy <target> [--archetype TYPE]',
    async run({ client, args }) {
      const target = requireFirst(args, 'target');
      const archetype = flagValue(args, 'archetype');
      const data = await client.post<unknown>('/api/agents/quick-deploy', { target, archetype });
      return { data, text: render.renderDeploy(data as never, target) };
    },
  },
  dispatch: {
    summary: 'Dispatch an agent at existing graph node(s)',
    usage: 'dispatch --node <id> [--node <id>…] [--skill S] [--archetype A]',
    async run({ client, args }) {
      const nodes = multiFlag(args, 'node');
      if (!nodes.length) throw new Error('Missing required --node <id> (repeatable).');
      const body = { target_node_ids: nodes, skill: flagValue(args, 'skill'), archetype: flagValue(args, 'archetype') };
      const data = await client.post<unknown>('/api/agents/dispatch', body);
      return { data, text: render.renderDispatch(data as never) };
    },
  },
};
