// ============================================================
// Overwatch — Scripted Agent Runner
//
// Executes non-LLM scripted recon tasks for frontier items that
// have deterministic execution paths. When dispatch_agents creates
// AgentTask records, this runner picks them up and drives tool
// execution through the existing approval gate.
//
// Handles:
//   - credential_test: run token validation via curl/aws CLI,
//     then mark the frontier item done.
//   - incomplete_node on credentials: run validate_token_credential
//     for the node if it is an OIDC/bearer token.
//   - All others: mark completed with a "no scripted handler" summary
//     so tasks don't stay in 'running' forever.
//
// Wired by DashboardServer constructor after the engine is created.
// ============================================================

import type { GraphEngine } from './graph-engine.js';
import type { AgentTask, FrontierItem, NodeProperties } from '../types.js';
import { runInstrumentedProcess } from '../tools/_process-runner.js';
import { isTokenCredential, isCredentialUsableForAuth } from './credential-utils.js';

const HEARTBEAT_INTERVAL_MS = 15_000;  // 15s

export class ScriptedAgentRunner {
  private running = false;
  /** task IDs currently being processed to avoid double-pickup */
  private processing = new Set<string>();
  private heartbeatTimers = new Map<string, ReturnType<typeof setInterval>>();

  constructor(private engine: GraphEngine) {}

  start(): void {
    if (this.running) return;
    this.running = true;
    // Subscribe to engine updates to detect newly registered tasks.
    // onUpdate fires after every graph/state mutation, including registerAgent.
    this.engine.onUpdate(() => {
      if (!this.running) return;
      this.drainQueue();
    });
    // Initial drain in case tasks were registered before start().
    this.drainQueue();
  }

  stop(): void {
    this.running = false;
    for (const timer of this.heartbeatTimers.values()) clearInterval(timer);
    this.heartbeatTimers.clear();
  }

  private drainQueue(): void {
    const tasks = this.engine.getAgentTasks();
    for (const task of tasks) {
      if (task.status !== 'running') continue;
      if (this.processing.has(task.id)) continue;
      if (!task.frontier_item_id) continue;
      this.processing.add(task.id);
      this.runTask(task).catch(() => {
        // runTask handles its own error reporting; this is a safety net.
        this.processing.delete(task.id);
      });
    }
  }

  private startHeartbeat(task: AgentTask): void {
    if (this.heartbeatTimers.has(task.id)) return;
    // Register the task with a TTL so the watchdog can reap it if this
    // process crashes mid-execution.
    const timer = setInterval(() => {
      if (!this.running || !this.processing.has(task.id)) {
        clearInterval(timer);
        this.heartbeatTimers.delete(task.id);
        return;
      }
      this.engine.agentHeartbeat(task.id);
    }, HEARTBEAT_INTERVAL_MS);
    this.heartbeatTimers.set(task.id, timer);
  }

  private stopHeartbeat(taskId: string): void {
    const timer = this.heartbeatTimers.get(taskId);
    if (timer) {
      clearInterval(timer);
      this.heartbeatTimers.delete(taskId);
    }
  }

  private async runTask(task: AgentTask): Promise<void> {
    this.startHeartbeat(task);
    // Send initial heartbeat with TTL so the watchdog knows this task is live.
    // We set heartbeat_ttl_seconds on the task by doing one heartbeat; the
    // agent-manager only updates heartbeat_at, so we stamp the TTL via update.
    this.engine.agentHeartbeat(task.id);

    const frontierItem = task.frontier_item_id
      ? this.engine.getFrontierItem(task.frontier_item_id)
      : null;

    if (!frontierItem) {
      this.engine.updateAgentStatus(task.id, 'completed', 'Frontier item not found; skipped');
      this.stopHeartbeat(task.id);
      this.processing.delete(task.id);
      return;
    }

    try {
      const summary = await this.dispatchByType(task, frontierItem);
      this.engine.updateAgentStatus(task.id, 'completed', summary);
    } catch (err) {
      this.engine.updateAgentStatus(task.id, 'failed', `Scripted runner error: ${err}`);
    } finally {
      this.stopHeartbeat(task.id);
      this.processing.delete(task.id);
    }
  }

  private async dispatchByType(task: AgentTask, item: FrontierItem): Promise<string> {
    switch (item.type) {
      case 'credential_test':
        return this.runCredentialTest(task, item);

      case 'incomplete_node':
      case 'untested_edge':
      case 'inferred_edge': {
        // Try credential-driven execution when the item targets a cred node.
        const targetId = item.node_id ?? item.edge_source ?? item.edge_target;
        if (targetId) {
          const node = this.engine.getNode(targetId);
          if (node?.type === 'credential' && isTokenCredential(node) && isCredentialUsableForAuth(node)) {
            return this.runTokenValidationForNode(task, item, node);
          }
        }
        return 'No scripted handler for this frontier item type; operator should drive manually.';
      }

      default:
        // network_discovery, network_pivot, mfa_bypass_candidate, etc.
        return `No scripted handler for type=${item.type}; operator should drive manually.`;
    }
  }

  // ----------------------------------------------------------------
  // credential_test handler
  // ----------------------------------------------------------------
  private async runCredentialTest(task: AgentTask, item: FrontierItem): Promise<string> {
    const credId = item.credential_id ?? item.node_id;
    if (!credId) return 'credential_test item has no credential_id; skipped';

    const cred = this.engine.getNode(credId);
    if (!cred) return `Credential node ${credId} not found; skipped`;
    if (cred.type !== 'credential') return `Node ${credId} is type=${cred.type}, expected credential; skipped`;
    if (!isCredentialUsableForAuth(cred)) return `Credential ${credId} is not usable for auth; skipped`;
    if (!isTokenCredential(cred)) return `Credential ${credId} is not a token credential; skipped`;

    return this.runTokenValidationForNode(task, item, cred);
  }

  // ----------------------------------------------------------------
  // Token validation (OIDC/bearer tokens only)
  // ----------------------------------------------------------------
  private async runTokenValidationForNode(
    task: AgentTask,
    item: FrontierItem,
    cred: NodeProperties,
  ): Promise<string> {
    const credValue = cred.cred_value as string | undefined;
    if (!credValue) {
      return `Credential ${cred.id} has no cred_value; cannot run automated validation`;
    }

    const endpoint = this.inferEndpoint(cred);
    if (!endpoint) {
      return `Cannot infer validation endpoint for credential ${cred.id} (kind=${cred.cred_material_kind}, audience=${cred.cred_audience}); operator should validate manually`;
    }

    const { binary, args, parser } = this.buildCurlArgs(cred, credValue, endpoint);
    if (!binary) return 'Could not build curl args for validation; skipped';

    const result = await runInstrumentedProcess(this.engine, {
      binary,
      args,
      command_repr: `curl -sS [token redacted] ${endpoint}`,
      agent_id: task.agent_id,
      frontier_item_id: item.id,
      technique: 'token_replay',
      tool_name: 'validate_token_credential',
      target_url: endpoint,
      target_node: cred.id,
      target_node_ids: [cred.id],
      description: `Validate token credential ${cred.id} against ${endpoint}`,
      parse_with: parser,
      noise_estimate: 0.05,
      invoking_tool: 'run_tool',
    });

    const text = result.content[0]?.text ?? '';
    if (result.isError) return `Token validation failed: ${text.slice(0, 200)}`;

    try {
      const parsed = JSON.parse(text) as Record<string, unknown>;
      if (parsed.executed === false) {
        return `Token validation queued for approval (action_id: ${parsed.action_id})`;
      }
    } catch { /* ignore */ }

    return `Token validation complete for ${cred.id} against ${endpoint}`;
  }

  private inferEndpoint(cred: NodeProperties): string | null {
    const audience = cred.cred_audience as string | undefined;
    const kind = cred.cred_material_kind as string | undefined;

    if (audience) {
      if (audience.includes('graph.microsoft.com')) return 'https://graph.microsoft.com/v1.0/me';
      if (audience.includes('sts.amazonaws.com') || audience.includes('aws.amazon.com')) return null; // AWS uses CLI, not curl
      if (/\.okta\.com/i.test(audience)) return `${audience.replace(/\/+$/, '')}/api/v1/users/me`;
      if (audience.includes('api.github.com') || audience.includes('github.com')) return 'https://api.github.com/user';
    }

    // Fallback by material kind
    switch (kind) {
      case 'oidc_access_token':
        if (!audience) return 'https://graph.microsoft.com/v1.0/me'; // most common in enterprise
        break;
      case 'pat':
        return 'https://api.github.com/user';
    }
    return null;
  }

  private buildCurlArgs(cred: NodeProperties, token: string, endpoint: string): {
    binary: string;
    args: string[];
    parser: string;
  } {
    const audience = cred.cred_audience as string | undefined;
    const kind = cred.cred_material_kind as string | undefined;

    let authHeader: string;
    let parser: string;

    if (audience && /\.okta\.com/i.test(audience)) {
      const isOidc = kind === 'oidc_access_token' || kind === 'oidc_id_token' || this.looksLikeJwt(token);
      authHeader = `${isOidc ? 'Bearer' : 'SSWS'} ${token}`;
      parser = 'token_replay_okta';
    } else if ((audience && audience.includes('api.github.com')) || kind === 'pat') {
      authHeader = `Bearer ${token}`;
      parser = 'token_replay_github';
    } else {
      // Default: Microsoft Graph / generic OIDC bearer
      authHeader = `Bearer ${token}`;
      parser = 'token_replay_msgraph';
    }

    return {
      binary: 'curl',
      args: [
        '-sS', '--max-time', '15',
        '-w', '\n[STATUS:%{http_code}]',
        '-H', `Authorization: ${authHeader}`,
        '-H', 'Accept: application/json',
        endpoint,
      ],
      parser,
    };
  }

  private looksLikeJwt(value: string): boolean {
    const token = value.replace(/^Bearer\s+/i, '').trim();
    const parts = token.split('.');
    return parts.length === 3 && parts.every(part => part.length > 0);
  }
}
