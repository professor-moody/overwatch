// ============================================================
// Operator CLI — command table (read commands)
// ============================================================

import type { ApiClient } from './client.js';
import * as render from './render.js';
import { existsSync, readFileSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { engagementConfigSchema } from '../../types.js';
import { inspectStateMigration } from '../../services/state-migration.js';

export interface CommandContext {
  client: ApiClient;
  /** Command-specific args (after the command name, global flags stripped). */
  args: string[];
}

/** A command returns the subject `data` (for --json) and rendered `text`. */
export interface CommandResult {
  data: unknown;
  text: string;
  exitCode?: number;
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
  'state-file', 'config-file',
  'credential', 'status',
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

function readLocalRuntimeProfile(): { config_path?: string; state_file_path?: string } | undefined {
  const profilePath = resolve(
    process.env.OVERWATCH_RUNTIME_PROFILE
      ?? join(process.cwd(), '.overwatch-runtime', 'profile.json'),
  );
  if (!existsSync(profilePath)) return undefined;
  try {
    const value = JSON.parse(readFileSync(profilePath, 'utf8')) as Record<string, unknown>;
    if (value.schema_version !== 1) return undefined;
    return {
      ...(typeof value.config_path === 'string' ? { config_path: value.config_path } : {}),
      ...(typeof value.state_file_path === 'string'
        ? { state_file_path: value.state_file_path }
        : {}),
    };
  } catch (error) {
    throw new Error(
      `Runtime profile ${profilePath} is invalid: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

export const READ_COMMANDS: Record<string, Command> = {
  state: {
    summary: 'Inspect local persisted-state version and migration readiness',
    usage: 'state migrate --check [--state-file PATH] [--config-file PATH]',
    async run({ args }) {
      const positional = positionals(args);
      if (positional[0] !== 'migrate' || !args.includes('--check')) {
        throw new Error('Expected `state migrate --check`.');
      }
      const profile = readLocalRuntimeProfile();
      const configFile = resolve(
        flagValue(args, 'config-file')
          ?? process.env.OVERWATCH_CONFIG
          ?? profile?.config_path
          ?? './engagement.json',
      );
      let stateFile = flagValue(args, 'state-file')
        ?? process.env.OVERWATCH_STATE_FILE
        ?? profile?.state_file_path;
      if (!stateFile) {
        if (!existsSync(configFile)) {
          throw new Error('Cannot derive the state path because the config file is missing; pass --state-file PATH.');
        }
        const config = engagementConfigSchema.parse(
          JSON.parse(readFileSync(configFile, 'utf8')),
        );
        stateFile = join(dirname(configFile), `state-${config.id}.json`);
      }
      const inspection = inspectStateMigration({
        stateFilePath: resolve(stateFile),
        configFilePath: configFile,
      });
      return {
        data: inspection,
        text: render.renderStateMigrationInspection(inspection),
        exitCode: inspection.ready ? 0 : 1,
      };
    },
  },
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
  playbooks: {
    summary: 'Durable credential playbook runs and step progress',
    usage: 'playbooks [--credential ID] [--status STATUS] [--open]',
    async run({ client, args }) {
      const query = new URLSearchParams();
      const credential = flagValue(args, 'credential');
      const status = flagValue(args, 'status');
      if (credential) query.set('credential_id', credential);
      if (status) query.set('status', status);
      if (args.includes('--open')) query.set('open_only', 'true');
      const suffix = query.size > 0 ? `?${query.toString()}` : '';
      const response = await client.get<{ runs: unknown[]; total: number }>(`/api/playbook-runs${suffix}`);
      return { data: response, text: render.renderPlaybooks(response as never) };
    },
  },
};

export const WRITE_COMMANDS: Record<string, Command> = {
  playbook: {
    summary: 'Prepare, resume, retry, release, or skip durable playbook work',
    usage: 'playbook <start RUN STEP|resume RUN|retry RUN STEP|interrupt RUN STEP [--reason TEXT]|skip RUN STEP [--reason TEXT]>',
    async run({ client, args }) {
      const positional = positionals(args);
      const action = positional[0];
      const runId = positional[1];
      const stepId = positional[2];
      if (!action || !runId) throw new Error('Expected `playbook <start|resume|retry|interrupt|skip> <run-id> [step-id]`.');
      if (action === 'resume') {
        const data = await client.post<{ run: { status: string } }>(`/api/playbook-runs/${encodeURIComponent(runId)}/resume`, {});
        return { data, text: render.ok(`Playbook ${runId} resumed (${data.run.status}).`) };
      }
      if (!stepId) throw new Error(`Missing required <step-id> for playbook ${action}.`);
      const base = `/api/playbook-runs/${encodeURIComponent(runId)}/steps/${encodeURIComponent(stepId)}`;
      if (action === 'start' || action === 'retry') {
        const data = await client.post<{ attempt: { attempt_id: string }; execution: unknown }>(`${base}/${action}`, {});
        return {
          data,
          text: render.ok(`${action === 'start' ? 'Prepared' : 'Prepared retry for'} ${stepId} as attempt ${data.attempt.attempt_id}. This does not execute the step; use --json to copy its resolved descriptor, or interrupt the claim if you will not run it.`),
        };
      }
      if (action === 'interrupt') {
        const data = await client.post<{ run: { status: string } }>(`${base}/interrupt`, { reason: flagValue(args, 'reason') });
        return { data, text: render.ok(`Released ${stepId}; its active attempt is interrupted and can be retried.`) };
      }
      if (action === 'skip') {
        const data = await client.post<{ run: { status: string } }>(`${base}/skip`, { reason: flagValue(args, 'reason') });
        return { data, text: render.ok(`Skipped ${stepId}; playbook is now ${data.run.status}.`) };
      }
      throw new Error(`Unknown playbook action: ${action}.`);
    },
  },
  session: {
    summary: 'Resume a recovered listener',
    usage: 'session resume <session-id>',
    async run({ client, args }) {
      const positional = positionals(args);
      if (positional[0] !== 'resume') {
        throw new Error('Expected `session resume <session-id>`.');
      }
      const id = positional[1];
      if (!id) throw new Error('Missing required <session-id>.');
      const data = await client.post<unknown>(
        `/api/sessions/${encodeURIComponent(id)}/resume`,
        {},
      );
      return { data, text: render.ok(`Listener ${id} resumed and is waiting for a connection.`) };
    },
  },
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
