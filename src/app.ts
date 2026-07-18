// ============================================================
// Overwatch — App Bootstrap
// Core app construction separated from transport startup.
// ============================================================

import { chmodSync, readFileSync, readdirSync, existsSync, writeFileSync } from 'fs';
import { basename, dirname, join, resolve } from 'path';
import { randomUUID, createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ToolCallback, RegisteredTool } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ZodRawShapeCompat, AnySchema } from '@modelcontextprotocol/sdk/server/zod-compat.js';
import type { ToolAnnotations } from '@modelcontextprotocol/sdk/types.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import type { Express, Request, Response } from 'express';
import type { Server } from 'http';
import { z } from 'zod';
import { GraphEngine } from './services/graph-engine.js';
import { SkillIndex } from './services/skill-index.js';
import { ProcessTracker } from './services/process-tracker.js';
import { DashboardServer } from './services/dashboard-server.js';
import { SessionManager } from './services/session-manager.js';
import { LocalPtyAdapter, SshAdapter, SocketAdapter } from './services/session-adapters.js';
import {
  createMcpAuthMiddleware,
  getAuthenticatedMcpActorTaskId,
  McpTaskCredentialAuthority,
} from './services/mcp-auth.js';
import { TaskExecutionService, type TaskExecutionServiceOptions } from './services/task-execution-service.js';
import type { EngagementConfig } from './types.js';
import { engagementConfigSchema } from './types.js';
import { formatConfigError, parseEngagementConfig } from './config.js';
import { registerStateTools } from './tools/state.js';
import { registerOpsecTools } from './tools/opsec.js';
import { registerFindingReadinessTools } from './tools/finding-readiness.js';
import { registerFindingTools } from './tools/findings.js';
import { registerScoringTools } from './tools/scoring.js';
import { registerExplorationTools } from './tools/exploration.js';
import { registerResearchCveTools } from './tools/research-cve.js';
import { registerProposePlanTools } from './tools/propose-plan.js';
import { registerAgentTools } from './tools/agents.js';
import { registerSkillTools } from './tools/skills.js';
import { registerBloodHoundTools } from './tools/bloodhound.js';
import { registerAzureHoundTools } from './tools/azurehound.js';
import { registerToolCheckTools } from './tools/toolcheck.js';
import { registerProcessTools } from './tools/processes.js';
import { registerInferenceTools } from './tools/inference.js';
import { registerParseOutputTools } from './tools/parse-output.js';
import { registerLoggingTools } from './tools/logging.js';
import { registerRetrospectiveTools } from './tools/retrospective.js';
import { registerReportingTools } from './tools/reporting.js';
import { registerRemediationTools } from './tools/remediation.js';
import { registerSessionTools } from './tools/sessions.js';
import { registerScopeTools } from './tools/scope.js';
import { registerEngagementTools } from './tools/engagement.js';
import { EngagementManager } from './services/engagement-manager.js';
import { registerRunBashTool } from './tools/run-bash.js';
import { registerRunToolTool } from './tools/run-tool.js';
import { registerTokenReplayTool } from './tools/token-replay.js';
import { registerTestWebappCredentialTool } from './tools/test-webapp-credential.js';
import { registerIngestScreenshotsTool } from './tools/ingest-screenshots.js';
import { registerAwsPlaybookTool } from './tools/aws-playbook.js';
import { registerGithubPlaybookTool } from './tools/github-playbook.js';
import { registerCicdOidcPlaybookTool } from './tools/cicd-oidc-playbook.js';
import { registerEntraPlaybookTools } from './tools/entra-playbook.js';
import { registerPlaybookRunTools } from './tools/playbook-runs.js';
import { registerLogThoughtTool } from './tools/log-thought.js';
import { registerDecisionLogTools } from './tools/decision-log.js';
import { registerIntrospectionTools } from './tools/introspection.js';
import { registerTimelineTools } from './tools/timeline.js';
import { registerTranscriptTools } from './tools/transcripts.js';
import { registerTapeTools } from './tools/tapes.js';
import { registerOperatorInfraTools } from './tools/operator-infra.js';
import { registerPostgresTools } from './tools/postgres.js';
import { registerIngestJsonTools } from './tools/ingest-json.js';
import { registerBundleTools } from './tools/bundle.js';
import { registerInstructionTools } from './tools/instructions.js';
import { registerRecoveryTools } from './tools/recovery.js';
import {
  recoverInterruptedAtomicJsonWrite,
  withConfigMetadata,
  writeJsonAtomicDurable,
} from './services/engagement-config-service.js';
import { withStateMigrationWriteGuard } from './services/state-migration.js';
import type {
  ToolDescriptor,
} from './services/tool-descriptor-registry.js';
import {
  buildToolDescriptor,
  toolCanMutateDurableState,
  toolInvocationMutatesDurableState,
  toolRequiresWritablePersistence,
} from './services/tool-descriptor-registry.js';
import { ToolTelemetry } from './services/tool-telemetry.js';
import { setTelemetry, getTelemetry } from './tools/error-boundary.js';
import { InProcessTapeController, type TapeStartSource } from './services/in-process-tape.js';
import { reconcileRuntimeOwnershipOnStartup } from './services/runtime-ownership-recovery.js';
import {
  acquireDaemonInstanceLease,
  type DaemonLifecyclePhase,
  type DaemonInstanceLease,
} from './services/daemon-instance-lease.js';
import { readRuntimeBuildInfo } from './services/runtime-build-info.js';
import { publishManagedDaemonReady } from './services/managed-daemon-record.js';
import {
  ApplicationCommandService,
  withApplicationCommandInvocation,
} from './services/application-command-service.js';
import { PlaybookRunService } from './services/playbook-run-service.js';
import {
  ExternalMutationCommandService,
  buildExternalMutationFingerprint,
} from './services/external-mutation-command-service.js';

type DashboardStatusProvider = () => {
  enabled: boolean;
  running: boolean;
  address?: string;
};

export type OverwatchToolRegistrar = Pick<McpServer, 'registerTool'>;

type McpToolFailure = {
  error?: string;
  code?: string;
};

function failureFromError(error: unknown): McpToolFailure {
  return {
    error: error instanceof Error ? error.message : String(error),
    ...(typeof (error as { code?: unknown } | null)?.code === 'string'
      ? { code: (error as { code: string }).code }
      : {}),
  };
}

/** Extract the structured payload emitted by withErrorBoundary without
 * coupling the registrar to a specific tool implementation. */
function failureFromToolResult(result: unknown): McpToolFailure | undefined {
  if (!result || typeof result !== 'object' || (result as { isError?: unknown }).isError !== true) {
    return undefined;
  }
  const content = (result as { content?: unknown }).content;
  if (!Array.isArray(content)) return {};
  for (const block of content) {
    if (!block || typeof block !== 'object' || (block as { type?: unknown }).type !== 'text') continue;
    const text = (block as { text?: unknown }).text;
    if (typeof text !== 'string') continue;
    try {
      const parsed = JSON.parse(text) as unknown;
      if (parsed && typeof parsed === 'object') {
        const record = parsed as Record<string, unknown>;
        return {
          ...(typeof record.error === 'string' ? { error: record.error } : {}),
          ...(typeof record.code === 'string' ? { code: record.code } : {}),
        };
      }
    } catch {
      return { error: text };
    }
  }
  return {};
}

function isDurabilityFailure(
  failure: McpToolFailure,
  recovery: ReturnType<GraphEngine['getPersistenceRecoveryStatus']>,
  mapClosedGate: boolean,
): boolean {
  // Filesystem codes and persistence-sounding prose are not enough: several
  // public tools write reports, bundles, or inactive engagement files that are
  // deliberately outside the live engine's recovery gate. Only normalize a
  // late error when the combined engine/config recovery surface has actually
  // closed, or when StatePersistence recorded this exact error during one of
  // its retryable first/second failures (before the three-failure gate trips).
  if (
    failure.error !== undefined
    && recovery.last_persistence_error === failure.error
  ) return true;

  const combinedRecoveryIncomplete = recovery.writable === false
    || recovery.complete === false;
  if (!combinedRecoveryIncomplete) return false;

  // Ordinary durable tools were admitted only while the combined gate was
  // writable, so a closed/incomplete status here is necessarily late. Config
  // reconciliation is the sole exception: it starts behind a config-only gate
  // and must distinguish an ordinary stale-hash conflict from a newly retained
  // intent or a state/WAL failure.
  if (mapClosedGate) return true;

  const configRecovery = recovery.config_recovery;
  const stateRecovery = recovery.state_recovery;
  return configRecovery?.status === 'write_incomplete'
    || configRecovery?.intent_present === true
    || stateRecovery?.writable === false
    || stateRecovery?.complete === false;
}

function persistenceReadOnlyToolResult(
  recovery: ReturnType<GraphEngine['getPersistenceRecoveryStatus']>,
  failure: McpToolFailure = {},
  originalResult?: unknown,
) {
  const error = failure.error
    ?? 'Durable mutations are disabled while persistence recovery is incomplete.';
  const normalizedPayload = (original: Record<string, unknown> = {}): Record<string, unknown> => ({
    ...original,
    error: typeof original.error === 'string' ? original.error : error,
    ...(failure.code && failure.code !== 'PERSISTENCE_READ_ONLY'
      ? { persistence_error_code: failure.code }
      : {}),
    code: 'PERSISTENCE_READ_ONLY',
    recovery,
  });

  if (originalResult && typeof originalResult === 'object') {
    const original = originalResult as Record<string, unknown>;
    if (Array.isArray(original.content)) {
      let augmented = false;
      const content = original.content.map(block => {
        if (
          augmented
          || !block
          || typeof block !== 'object'
          || (block as { type?: unknown }).type !== 'text'
          || typeof (block as { text?: unknown }).text !== 'string'
        ) return block;
        try {
          const parsed = JSON.parse((block as { text: string }).text) as unknown;
          if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return block;
          augmented = true;
          return {
            ...block,
            text: JSON.stringify(normalizedPayload(parsed as Record<string, unknown>), null, 2),
          };
        } catch {
          return block;
        }
      });
      if (!augmented) {
        content.push({
          type: 'text' as const,
          text: JSON.stringify(normalizedPayload(), null, 2),
        });
      }
      return {
        ...original,
        content,
        isError: true,
      };
    }
  }

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify(normalizedPayload(), null, 2),
    }],
    isError: true,
  };
}

const APPLICATION_COMMAND_INPUT_SHAPE = {
  command_id: z.string().trim().min(1).max(256).optional()
    .describe('Stable client command identifier for correlation.'),
  idempotency_key: z.string().trim().min(1).max(512).optional()
    .describe('Stable client retry identity. Reuse it only for the same operation and input; provide it for retries across MCP reconnects or daemon restarts.'),
  retry_token: z.string().regex(/^idem_[a-f0-9]{64}$/).optional()
    .describe('Opaque retry token returned by a prior application-command response.'),
} satisfies ZodRawShapeCompat;

const APPLICATION_COMMAND_INPUT_KEYS = new Set([
  'command_id',
  'idempotency_key',
  'retry_token',
]);

function rawInputShape(
  inputSchema: ZodRawShapeCompat | AnySchema | undefined,
): Record<string, unknown> | undefined {
  if (!inputSchema || typeof inputSchema !== 'object') return undefined;
  const record = inputSchema as unknown as Record<string, unknown>;
  return record._def === undefined && record._zod === undefined ? record : undefined;
}

function semanticMutationInput(input: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(input).filter(([key]) => !APPLICATION_COMMAND_INPUT_KEYS.has(key)),
  );
}

function applicationCommandBoundaryResult(
  result: unknown,
  command: Awaited<ReturnType<ExternalMutationCommandService['execute']>>,
): unknown {
  const metadata = {
    boundary_command_id: command.command_id,
    retry_token: command.retry_token,
    status: command.status,
    replayed: command.replayed,
    ...(command.delivery_error ? { delivery_error: command.delivery_error } : {}),
  };
  if (result && typeof result === 'object' && !Array.isArray(result)) {
    const record = result as Record<string, unknown>;
    const priorMeta = record._meta && typeof record._meta === 'object' && !Array.isArray(record._meta)
      ? record._meta as Record<string, unknown>
      : {};
    return {
      ...record,
      _meta: {
        ...priorMeta,
        'overwatch/application-command': metadata,
      },
    };
  }
  return result;
}

function failedApplicationCommandBoundaryResult(
  command: Awaited<ReturnType<ExternalMutationCommandService['execute']>>,
) {
  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        error: command.error?.message
          ?? command.delivery_error?.message
          ?? `Application command is ${command.status}.`,
        code: command.error?.code
          ?? command.delivery_error?.code
          ?? 'APPLICATION_COMMAND_NOT_SUCCEEDED',
        command_id: command.command_id,
        retry_token: command.retry_token,
        status: command.status,
        replayed: command.replayed,
      }, null, 2),
    }],
    isError: true,
    _meta: {
      'overwatch/application-command': {
        boundary_command_id: command.command_id,
        retry_token: command.retry_token,
        status: command.status,
        replayed: command.replayed,
        ...(command.delivery_error ? { delivery_error: command.delivery_error } : {}),
      },
    },
  };
}

/**
 * Wrapper around McpServer that intercepts registerTool calls to collect
 * tool metadata (name + description) without monkey-patching the server.
 */
export class ToolRegistrar implements OverwatchToolRegistrar {
  private entries: ToolDescriptor[] = [];
  private readonly mutationBoundary?: ExternalMutationCommandService;
  /**
   * Stdio requests do not carry an MCP session id. Keep one opaque namespace
   * for this registrar lifetime so a retransmitted JSON-RPC request is
   * idempotent in-process without colliding with a later daemon lifetime.
   */
  private readonly invocationNamespace = `mcp-runtime-${randomUUID()}`;

  constructor(
    private server: McpServer,
    private persistenceGate?: Pick<
      GraphEngine,
      'isPersistenceWritable' | 'getPersistenceRecoveryStatus'
    > & Partial<Pick<GraphEngine, 'resolveAgentTaskReference'>>,
    private readonly authenticatedActorTaskId: string | null = null,
    private readonly runtimePhase?: () => DaemonLifecyclePhase,
  ) {
    if (persistenceGate instanceof GraphEngine) {
      this.mutationBoundary = new ExternalMutationCommandService(persistenceGate);
    }
  }
  registerTool<OutputArgs extends ZodRawShapeCompat | AnySchema, InputArgs extends undefined | ZodRawShapeCompat | AnySchema = undefined>(
    name: string,
    config: { title?: string; description?: string; inputSchema?: InputArgs; outputSchema?: OutputArgs; annotations?: ToolAnnotations; _meta?: Record<string, unknown> },
    cb: ToolCallback<InputArgs>,
  ): RegisteredTool {
    const preliminaryDescriptor = buildToolDescriptor(name, config);
    const canMutate = toolCanMutateDurableState(preliminaryDescriptor);
    const originalShape = config.inputSchema === undefined
      ? {}
      : rawInputShape(config.inputSchema);
    if (canMutate && !originalShape) {
      throw new Error(
        `Mutation-capable tool ${name} must register a raw object input shape so common command metadata can be added.`,
      );
    }
    const effectiveConfig = canMutate
      ? {
          ...config,
          inputSchema: {
            ...APPLICATION_COMMAND_INPUT_SHAPE,
            ...originalShape,
          },
        }
      : config;
    const descriptor = buildToolDescriptor(name, effectiveConfig);
    this.entries.push(descriptor);
    const wrapped = (async (...args: unknown[]) => {
      const phase = this.runtimePhase?.();
      if (phase && phase !== 'ready' && phase !== 'ready_read_only') {
        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({
              error: `Overwatch is ${phase}; MCP commands are not accepted until the runtime is ready.`,
              code: 'RUNTIME_NOT_READY',
              phase,
            }, null, 2),
          }],
          isError: true,
        };
      }
      const input = args[0];
      const inputRecord = input && typeof input === 'object'
        ? input as Record<string, unknown>
        : {};
      const requiresWritablePersistence = toolRequiresWritablePersistence(
        descriptor,
        inputRecord,
      );
      const mutatesDurableState = toolInvocationMutatesDurableState(
        descriptor,
        inputRecord,
      );
      if (
        requiresWritablePersistence
        && this.persistenceGate
        && !this.persistenceGate.isPersistenceWritable()
      ) {
        return persistenceReadOnlyToolResult(this.persistenceGate.getPersistenceRecoveryStatus());
      }
      const invoke = cb as unknown as (...callbackArgs: unknown[]) => unknown;
      try {
        const extra = args[1] && typeof args[1] === 'object'
          ? args[1] as {
              requestId?: string | number;
              sessionId?: string;
            }
          : undefined;
        const invocation = {
            transport: 'mcp',
            // HTTP workers are bound to a daemon-issued credential at session
            // initialization. The operator/stdio connection is deliberately
            // actorless. Caller-supplied task_id/agent_id fields are tool input,
            // never connection authority.
            actor_task_id: this.authenticatedActorTaskId,
            ...(extra?.requestId !== undefined
              ? { request_id: String(extra.requestId) }
              : {}),
            session_id: extra?.sessionId ?? this.invocationNamespace,
            ...(typeof inputRecord.command_id === 'string'
              ? { command_id: inputRecord.command_id }
              : {}),
            ...(typeof inputRecord.idempotency_key === 'string'
              ? { idempotency_key: inputRecord.idempotency_key }
              : {}),
            ...(typeof inputRecord.retry_token === 'string'
              ? { retry_token: inputRecord.retry_token }
              : {}),
            ...(typeof inputRecord.action_id === 'string'
              ? { action_id: inputRecord.action_id }
              : {}),
            ...(typeof inputRecord.frontier_item_id === 'string'
              ? { frontier_item_id: inputRecord.frontier_item_id }
              : {}),
          } as const;
        const callbackInput = { ...inputRecord };
        delete callbackInput.retry_token;
        if (!Object.prototype.hasOwnProperty.call(originalShape ?? {}, 'command_id')) {
          delete callbackInput.command_id;
        }
        if (!Object.prototype.hasOwnProperty.call(originalShape ?? {}, 'idempotency_key')) {
          delete callbackInput.idempotency_key;
        }
        const callbackArgs = [callbackInput, ...args.slice(1)];
        const wrapMutation = mutatesDurableState
          && this.mutationBoundary !== undefined
          && name !== 'resolve_config_divergence'
          && !(
            name === 'bundle_engagement'
            && this.persistenceGate
            && !this.persistenceGate.isPersistenceWritable()
          );
        const result = await withApplicationCommandInvocation(invocation, async () => {
          if (!wrapMutation) return invoke(...callbackArgs);
          const requestFingerprint = buildExternalMutationFingerprint(
            semanticMutationInput(inputRecord),
          );
          const publicIdentity = typeof inputRecord.command_id === 'string'
            ? inputRecord.command_id
            : typeof inputRecord.idempotency_key === 'string'
              ? inputRecord.idempotency_key
              : extra?.requestId !== undefined
                // JSON-RPC request ids are only unique within one client
                // session. Include that authority boundary so two terminal
                // MCP clients using the same counter and input never replay
                // one another. Cross-session/restart retries must use the
                // additive idempotency_key or opaque retry_token.
                ? `session:${invocation.session_id}:request:${String(extra.requestId)}:${requestFingerprint}`
                : randomUUID();
          const boundaryCommandId = `boundary_${createHash('sha256')
            .update(`mcp\0${name}\0${publicIdentity}`)
            .digest('hex')
            .slice(0, 48)}`;
          const boundary = await this.mutationBoundary!.execute({
            descriptor: {
              operation_id: `mcp.${name}`,
              request_fingerprint: requestFingerprint,
            },
            metadata: {
              command_id: boundaryCommandId,
              idempotency_key: `mcp-boundary:${name}:${
                typeof inputRecord.idempotency_key === 'string'
                  ? inputRecord.idempotency_key
                  : publicIdentity
              }`,
              ...(typeof inputRecord.retry_token === 'string'
                ? { retry_token: inputRecord.retry_token }
                : {}),
            },
            operation: () => withApplicationCommandInvocation(
              {
                ...invocation,
                // The outer retry token belongs to external.mcp.*. Nested
                // domain commands retain the public raw identity but must not
                // interpret the boundary receipt as their own token.
                retry_token: undefined,
              },
              () => invoke(...callbackArgs),
            ),
          });
          if (boundary.response === undefined) {
            return failedApplicationCommandBoundaryResult(boundary);
          }
          return applicationCommandBoundaryResult(boundary.response, boundary);
        });
        const failure = canMutate
          ? failureFromToolResult(result)
          : undefined;
        if (failure && this.persistenceGate) {
          const recovery = this.persistenceGate.getPersistenceRecoveryStatus();
          if (isDurabilityFailure(failure, recovery, requiresWritablePersistence)) {
            return persistenceReadOnlyToolResult(recovery, failure, result);
          }
        }
        return result;
      } catch (error) {
        if (canMutate && this.persistenceGate) {
          const recovery = this.persistenceGate.getPersistenceRecoveryStatus();
          const failure = failureFromError(error);
          if (isDurabilityFailure(failure, recovery, requiresWritablePersistence)) {
            return persistenceReadOnlyToolResult(recovery, failure);
          }
        }
        throw error;
      }
    }) as unknown as ToolCallback<InputArgs>;
    return this.server.registerTool(
      name,
      effectiveConfig as typeof config,
      wrapped,
    );
  }
  getEntries(): ToolDescriptor[] { return this.entries; }
}

export type OverwatchApp = {
  /** Live revisioned config. Retained as a property for compatibility, but
   * resolved from GraphEngine so embedded callers never observe startup-only
   * ownership state. */
  readonly config: EngagementConfig;
  engine: GraphEngine;
  skills: SkillIndex;
  processTracker: ProcessTracker;
  processTrackerUnsubscribe?: () => void;
  sessionManager: SessionManager;
  sessionDescriptorUnsubscribe?: () => void;
  engagementManager: EngagementManager;
  server: McpServer;
  dashboard: DashboardServer | null;
  taskExecution: TaskExecutionService;
  applicationCommands: ApplicationCommandService;
  telemetry: ToolTelemetry;
  tape: InProcessTapeController;
  /** Canonical browser-safe descriptors captured from the actual MCP registrations. */
  registeredTools: ToolDescriptor[];
  httpTransports?: Record<string, StreamableHTTPServerTransport>;
  httpServer?: Server;
  /** Removes terminal-worker credential/session observers and clears secrets. */
  mcpCredentialCleanup?: () => void;
  /** Process-lifetime ownership of the selected durable state family. */
  runtimeLease?: DaemonInstanceLease;
  /** Transport readiness exists even for embedded runtimes without a disk lease. */
  runtimeLifecycle: { phase: DaemonLifecyclePhase };
  runtimeBuild?: ReturnType<typeof readRuntimeBuildInfo>;
  /** Entrypoint-owned graceful stop hook used only by the authenticated managed lifecycle. */
  requestManagedShutdown?: () => void;
};

export type CreateOverwatchAppOptions = {
  config?: EngagementConfig;
  configPath?: string;
  skillDir?: string;
  dashboardPort?: number;
  stateFilePath?: string;
  /** Forwarded to TaskExecutionService — lets the eval harness set the headless
   *  claude binary / model (extraArgs) / max-turns / log dir for sub-agents. */
  taskExecution?: TaskExecutionServiceOptions;
  /** Enabled by the executable entrypoint. Embedded/test apps remain opt-in. */
  runtimeOwnership?: {
    transport: 'http' | 'stdio';
    dashboard_url?: string;
    mcp_url?: string;
  };
};

export function loadConfig(configPath: string = process.env.OVERWATCH_CONFIG || './engagement.json'): EngagementConfig {
  if (!existsSync(configPath)) {
    if (process.env.OVERWATCH_BOOTSTRAP === '1') {
      console.warn(`Config not found at ${configPath}. OVERWATCH_BOOTSTRAP=1 — creating default config.`);
      return engagementConfigSchema.parse({
        id: uuidv4(),
        name: 'default-engagement',
        created_at: new Date().toISOString(),
        scope: { cidrs: [], domains: [], exclusions: [] },
        objectives: [],
        opsec: { name: 'pentest', max_noise: 0.7 },
      });
    }
    throw new Error(
      `Engagement config not found at ${configPath}. ` +
      `Create a config file or set OVERWATCH_BOOTSTRAP=1 to start with an empty engagement.`
    );
  }

  return parseEngagementConfig(readFileSync(configPath, 'utf-8'));
}

function readConfigsFromDurableState(stateFilePath: string): EngagementConfig[] {
  const directory = dirname(stateFilePath);
  const base = basename(stateFilePath, '.json');
  const candidates: string[] = [];
  if (existsSync(stateFilePath)) candidates.push(stateFilePath);
  const snapshotDirectory = join(directory, '.snapshots');
  try {
    candidates.push(...readdirSync(snapshotDirectory)
      .filter(name => name.startsWith(`${base}.snap-`) && name.endsWith('.json'))
      .sort()
      .reverse()
      .map(name => join(snapshotDirectory, name)));
  } catch { /* no retained snapshot directory */ }
  try {
    candidates.push(...readdirSync(directory)
      .filter(name => name.startsWith(`${base}.snap-`) && name.endsWith('.json'))
      .sort()
      .reverse()
      .map(name => join(directory, name)));
  } catch { /* state directory is unavailable */ }

  const configs: EngagementConfig[] = [];
  const seen = new Set<string>();
  for (const candidate of candidates) {
    try {
      const value = JSON.parse(readFileSync(candidate, 'utf8')) as { config?: unknown };
      const config = engagementConfigSchema.parse(value.config);
      const identity = JSON.stringify(config);
      if (!seen.has(identity)) {
        seen.add(identity);
        configs.push(config);
      }
    } catch { /* try the next retained recovery base */ }
  }
  return configs;
}

function discoverRecoveryStateFile(
  configPath: string,
  preferredConfig?: EngagementConfig,
): { path: string; config: EngagementConfig } | undefined {
  const directory = dirname(configPath);
  let names: string[];
  try {
    const directoryNames = readdirSync(directory);
    const rootNames = directoryNames.filter(name =>
      /^state-.+\.json$/.test(name)
      && !name.includes('.snap-')
      && !name.endsWith('.runtime-owner.json'));
    const legacySnapshotBases = directoryNames.flatMap(name => {
      const match = /^(state-.+)\.snap-.+\.json$/.exec(name);
      return match ? [`${match[1]}.json`] : [];
    });
    let snapshotBases: string[] = [];
    try {
      snapshotBases = readdirSync(join(directory, '.snapshots'))
        .flatMap(name => {
          const match = /^(state-.+)\.snap-.+\.json$/.exec(name);
          return match ? [`${match[1]}.json`] : [];
        });
    } catch { /* no retained snapshots */ }
    names = [...new Set([...rootNames, ...legacySnapshotBases, ...snapshotBases])];
  } catch {
    return undefined;
  }
  const candidates = names.flatMap(name => {
    const path = join(directory, name);
    const configs = readConfigsFromDurableState(path);
    return configs.length > 0 ? [{ path, configs }] : [];
  });
  if (preferredConfig) {
    // StatePersistence validates and ranks every retained base. Discovery only
    // selects the family, so match the active config against every readable
    // base instead of incorrectly treating the primary file as authoritative.
    const idMatches = candidates.filter(candidate =>
      candidate.configs.some(config => config.id === preferredConfig.id));
    if (idMatches.length === 1) return { path: idMatches[0].path, config: preferredConfig };
    if (idMatches.length > 1) {
      throw new Error('Multiple durable state candidates match the active engagement id; set OVERWATCH_STATE_FILE explicitly.');
    }
    const identityMatches = candidates.filter(candidate =>
      candidate.configs.some(config =>
        config.created_at === preferredConfig.created_at
        && config.engagement_nonce === preferredConfig.engagement_nonce),
    );
    if (identityMatches.length === 1) return { path: identityMatches[0].path, config: preferredConfig };
    if (identityMatches.length > 1) {
      throw new Error('Active config identity matches multiple durable states; set OVERWATCH_STATE_FILE explicitly.');
    }
    return undefined;
  }
  if (candidates.length > 1) {
    throw new Error(
      `Active config cannot be loaded and ${candidates.length} durable engagement states exist beside it. ` +
      'Set OVERWATCH_STATE_FILE (or stateFilePath) to select the state to recover.',
    );
  }
  const selected = candidates[0];
  return selected ? { path: selected.path, config: selected.configs[0] } : undefined;
}

function hasStateArtifactsForPath(stateFilePath: string): boolean {
  const directory = dirname(stateFilePath);
  const base = basename(stateFilePath, '.json');
  const stateName = basename(stateFilePath);
  if (
    existsSync(stateFilePath)
    || existsSync(join(directory, `${base}.journal.jsonl`))
    || existsSync(`${stateFilePath}.rollback-intent.json`)
    || existsSync(`${stateFilePath}.migration-intent.json`)
    || existsSync(`${stateFilePath}.writer-lock`)
    || existsSync(`${stateFilePath}.migration-lock`)
  ) {
    return true;
  }
  if (readDirectoryIfPresent(directory).some(name =>
      (name.startsWith(`${base}.snap-`) && name.endsWith('.json'))
      || name.startsWith(`${base}.journal.jsonl.`)
      || name.startsWith(`${stateName}.rollback-intent.json`)
      || name.startsWith(`${stateName}.migration-intent.json`)
      || name.startsWith(`${stateName}.writer-lock`)
      || name.startsWith(`${stateName}.migration-lock`)
      || name.startsWith(`${stateName}.tmp`))) {
    return true;
  }
  if (readDirectoryIfPresent(join(directory, '.snapshots')).some(name =>
      name.startsWith(`${base}.snap-`) && name.endsWith('.json'))) {
    return true;
  }
  for (const name of ['.migration-backups', 'engagements', 'evidence', 'reports', 'tapes']) {
    if (readDirectoryIfPresent(join(directory, name)).length > 0) return true;
  }
  return false;
}

function readDirectoryIfPresent(path: string): string[] {
  try {
    return readdirSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
}

function hasAnyStateFamilyBeside(configPath: string): boolean {
  const directory = dirname(configPath);
  if (readDirectoryIfPresent(directory).some(name =>
    (/^state-.+\.json$/.test(name) && !name.endsWith('.runtime-owner.json'))
    || /^state-.+\.journal\.jsonl(?:\..+)?$/.test(name)
    || /^state-.+\.json\.(?:rollback-intent|migration-intent)\.json$/.test(name)
    || /^state-.+\.json\.(?:writer-lock|migration-lock)$/.test(name)
    || /^state-.+\.json\.tmp(?:-.+)?$/.test(name)
    || /^state-.+\.snap-.+\.json$/.test(name))) return true;
  return readDirectoryIfPresent(join(directory, '.snapshots'))
    .some(name => /^state-.+\.snap-.+\.json$/.test(name));
}

function hasAnyStateArtifactsBeside(configPath: string): boolean {
  const directory = dirname(configPath);
  const configName = basename(configPath);
  if (readDirectoryIfPresent(directory).some(name =>
      (/^state-.+\.json$/.test(name) && !name.endsWith('.runtime-owner.json'))
      || /^state-.+\.journal\.jsonl(?:\..+)?$/.test(name)
      || /^state-.+\.json\.(?:rollback-intent|migration-intent)\.json$/.test(name)
      || /^state-.+\.json\.(?:writer-lock|migration-lock)$/.test(name)
      || /^state-.+\.json\.tmp(?:-.+)?$/.test(name)
      || /^state-.+\.snap-.+\.json$/.test(name)
      || name === `${configName}.write-intent.json`
      || name.startsWith(`${configName}.write-intent.json.`)
      || name.startsWith(`${configName}.overwatch-`)
      || name.startsWith(`${configName}.tmp-`))) {
    return true;
  }
  if (readDirectoryIfPresent(join(directory, '.snapshots'))
    .some(name => /^state-.+\.snap-.+\.json$/.test(name))) return true;
  for (const name of ['.migration-backups', 'engagements', 'evidence', 'reports', 'tapes']) {
    if (readDirectoryIfPresent(join(directory, name)).length > 0) return true;
  }
  return false;
}

export function registerAllTools(
  server: OverwatchToolRegistrar,
  deps: {
    engine: GraphEngine;
    skills: SkillIndex;
    processTracker: ProcessTracker;
    sessionManager: SessionManager;
    engagementManager: EngagementManager;
    getDashboardStatus: DashboardStatusProvider;
    authenticatedActorTaskId?: string | null;
    runtimePhase?: () => DaemonLifecyclePhase;
  },
): ToolDescriptor[] {
  // Initialize shared telemetry (idempotent — first caller wins)
  if (!getTelemetry()) {
    setTelemetry(new ToolTelemetry());
  }

  const registrar = new ToolRegistrar(
    server as McpServer,
    deps.engine,
    deps.authenticatedActorTaskId ?? null,
    deps.runtimePhase,
  );
  const s = registrar as unknown as McpServer;

  registerStateTools(s, deps.engine, {
    getDashboardStatus: deps.getDashboardStatus,
  });
  registerFindingTools(s, deps.engine);
  registerFindingReadinessTools(s, deps.engine);
  registerScoringTools(s, deps.engine);
  registerOpsecTools(s, deps.engine);
  registerExplorationTools(s, deps.engine);
  registerResearchCveTools(s, deps.engine);
  registerProposePlanTools(s, deps.engine);
  registerAgentTools(s, deps.engine);
  registerSkillTools(s, deps.skills, deps.engine.getKB());
  registerBloodHoundTools(s, deps.engine);
  registerAzureHoundTools(s, deps.engine);
  registerToolCheckTools(s);
  registerProcessTools(s, deps.processTracker, deps.engine);
  registerInferenceTools(s, deps.engine);
  registerParseOutputTools(s, deps.engine);
  registerLoggingTools(s, deps.engine);
  registerRetrospectiveTools(s, deps.engine, deps.skills, () => registrar.getEntries().map(e => e.name));
  registerReportingTools(s, deps.engine, deps.skills);
  registerRemediationTools(s, deps.engine);
  registerSessionTools(s, deps.sessionManager, deps.engine);
  registerScopeTools(s, deps.engine);
  registerEngagementTools(s, deps.engine, deps.engagementManager);
  registerRunBashTool(s, deps.engine);
  registerRunToolTool(s, deps.engine);
  registerTokenReplayTool(s, deps.engine);
  registerTestWebappCredentialTool(s, deps.engine);
  registerIngestScreenshotsTool(s, deps.engine);
  registerAwsPlaybookTool(s, deps.engine);
  registerGithubPlaybookTool(s, deps.engine);
  registerCicdOidcPlaybookTool(s, deps.engine);
  registerEntraPlaybookTools(s, deps.engine);
  registerPlaybookRunTools(s, deps.engine);
  registerLogThoughtTool(s, deps.engine);
  registerDecisionLogTools(s, deps.engine);
  registerIntrospectionTools(s, deps.engine);
  registerTimelineTools(s, deps.engine);
  registerTranscriptTools(s, deps.engine);
  registerTapeTools(s, deps.engine);
  registerOperatorInfraTools(s, deps.engine);
  registerPostgresTools(s, deps.engine);
  registerIngestJsonTools(s, deps.engine);
  registerBundleTools(s, deps.engine);
  registerRecoveryTools(s, deps.engine);

  // Register instruction tools last (needs the collected tool list)
  registerInstructionTools(s, deps.engine, () => registrar.getEntries());

  return registrar.getEntries();
}

export function createOverwatchApp(options: CreateOverwatchAppOptions = {}): OverwatchApp {
  const configPath = options.configPath || process.env.OVERWATCH_CONFIG || './engagement.json';
  // Keep config and live state separate. By default, the mutable state file
  // lives beside the operator-authored config so launching from a different
  // cwd cannot silently create or load the wrong engagement state.
  const resolvedConfigPath = resolve(configPath);
  const explicitStateFilePath = options.stateFilePath || process.env.OVERWATCH_STATE_FILE;
  let config: EngagementConfig;
  let recoveredStateFilePath: string | undefined;
  let bootstrapConfigPending = false;
  if (options.config) {
    config = options.config;
  } else if (!existsSync(resolvedConfigPath)) {
    const explicitRecoveryConfig = explicitStateFilePath
      ? readConfigsFromDurableState(explicitStateFilePath)[0]
      : undefined;
    const discovered = explicitRecoveryConfig
      ? { path: explicitStateFilePath!, config: explicitRecoveryConfig }
      : discoverRecoveryStateFile(resolvedConfigPath);
    if (discovered) {
      recoveredStateFilePath = discovered.path;
      config = discovered.config;
      console.error(
        `[recovery] active config is missing; starting read-only from durable state ${discovered.path}`,
      );
    } else {
      const durableArtifactsExist = hasAnyStateArtifactsBeside(resolvedConfigPath)
        || (explicitStateFilePath ? hasStateArtifactsForPath(explicitStateFilePath) : false);
      if (durableArtifactsExist) {
        throw new Error(
          'Active config is missing, but durable state/WAL/snapshot artifacts could not be validated. ' +
          'Refusing bootstrap publication; select and repair the state explicitly.',
        );
      }
      config = loadConfig(resolvedConfigPath);
      bootstrapConfigPending = process.env.OVERWATCH_BOOTSTRAP === '1';
    }
  } else {
    try {
      config = loadConfig(resolvedConfigPath);
    } catch (configError) {
      const explicitRecoveryConfig = explicitStateFilePath
        ? readConfigsFromDurableState(explicitStateFilePath)[0]
        : undefined;
      if (explicitStateFilePath && !explicitRecoveryConfig) {
        throw new Error(
          `Active config cannot be loaded and the explicit durable state ${explicitStateFilePath} has no valid recovery base.`,
          { cause: configError },
        );
      }
      const discovered = explicitRecoveryConfig
        ? { path: explicitStateFilePath!, config: explicitRecoveryConfig }
        : discoverRecoveryStateFile(resolvedConfigPath);
      if (discovered) {
        recoveredStateFilePath = discovered.path;
        config = discovered.config;
        console.error(
          `[recovery] active config could not be loaded; starting read-only from durable state ${discovered.path}`,
        );
      } else {
        // Config CAS recovery can mutate pathnames. Only perform it after
        // proving there is no durable state that may still require a V0
        // migration backup; managed-state recovery owns that ordering.
        try {
          recoverInterruptedAtomicJsonWrite(resolvedConfigPath);
          config = loadConfig(resolvedConfigPath);
        } catch {
          throw configError;
        }
      }
    }
  }

  if (!explicitStateFilePath && !recoveredStateFilePath) {
    recoveredStateFilePath = discoverRecoveryStateFile(resolvedConfigPath, config)?.path;
    if (!recoveredStateFilePath && !options.config && hasAnyStateFamilyBeside(resolvedConfigPath)) {
      throw new Error(
        'The active config does not match the durable state families beside it. ' +
        'Refusing to select a fresh state path; restore the matching config or set OVERWATCH_STATE_FILE explicitly.',
      );
    }
  }

  const defaultStateFilePath = join(dirname(resolvedConfigPath), `state-${config.id}.json`);
  const stateFilePath = explicitStateFilePath || recoveredStateFilePath || defaultStateFilePath;
  const runtimeBuild = options.runtimeOwnership ? readRuntimeBuildInfo() : undefined;
  const runtimeLease = options.runtimeOwnership && runtimeBuild
    ? acquireDaemonInstanceLease({
        state_file: stateFilePath,
        config_file: resolvedConfigPath,
        engagement_id: config.id,
        transport: options.runtimeOwnership.transport,
        build_input_sha256: runtimeBuild.input_sha256,
        git_sha: runtimeBuild.git_sha,
        dashboard_url: options.runtimeOwnership.dashboard_url,
        mcp_url: options.runtimeOwnership.mcp_url,
      })
    : undefined;
  const runtimeLifecycle: { phase: DaemonLifecyclePhase } = { phase: 'recovering' };
  let partialEngine: GraphEngine | undefined;
  let partialProcessTracker: ProcessTracker | undefined;
  let partialProcessTrackerUnsubscribe: (() => void) | undefined;
  let partialSessionManager: SessionManager | undefined;

  try {
  // Bootstrap is an explicit request to create a new active engagement. Make
  // the file real before enabling managed write-through so a fresh bootstrap
  // cannot immediately classify its own absent file as divergence. This write
  // is deferred until durable-state discovery proves the path genuinely fresh
  // and the process-lifetime state owner is held.
  if (!options.config && bootstrapConfigPending && !existsSync(resolvedConfigPath)) {
    config = withConfigMetadata(config, config.config_revision ?? 1);
    withStateMigrationWriteGuard(
      stateFilePath,
      undefined,
      () => writeJsonAtomicDurable(resolvedConfigPath, config),
    );
  }
  // Tests and embedded callers often inject an in-memory config without
  // intending to create ./engagement.json. A loaded file (or an explicitly
  // supplied configPath) opts into revisioned write-through ownership.
  const managedConfigPath = options.config && !options.configPath ? undefined : resolvedConfigPath;
  const engine = new GraphEngine(config, stateFilePath, managedConfigPath);
  partialEngine = engine;
  const runtimeStatus = () => {
    const recovery = engine.getPersistenceRecoveryStatus();
    const persisted = runtimeLease?.getStatus();
    const publiclyWritable = runtimeLifecycle.phase === 'ready' && engine.isPersistenceWritable();
    return persisted
      ? {
          ...persisted,
          phase: runtimeLifecycle.phase,
          persistence_writable: publiclyWritable,
          ...(!publiclyWritable && (recovery.reason || recovery.last_persistence_error)
            ? { recovery_reason: recovery.reason ?? recovery.last_persistence_error }
            : {}),
        }
      : undefined;
  };
  const applicationCommands = new ApplicationCommandService(engine);
  applicationCommands.recoverInterruptedCommands();
  const authoritativeConfig = engine.getConfig();
  const skillDir = options.skillDir || process.env.OVERWATCH_SKILLS || './skills';
  const skills = new SkillIndex(skillDir);
  console.error(`Loaded ${skills.count} skills from ${skillDir}`);
  // Share the index with the engine so prompt generation + the headless runner
  // inline archetype methodology from the SAME loaded skills (not a per-call
  // `new SkillIndex()` that depends on cwd).
  engine.setSkillIndex(skills);

  // Managed process ownership must be reconciled before tools, transports, or
  // task execution can accept new target mutations. Only identity-verified
  // orphan groups are signaled; reused or unverifiable PIDs remain untouched
  // and surface through recovery status.
  const reconcileRuntimeOwnership = () => {
    // A config-divergent startup is intentionally read-only, so the first
    // recovery pass above cannot close accepted/running commands. This handler
    // is also invoked after explicit config reconciliation; retry command
    // recovery before process ownership and before writable service resumes.
    applicationCommands.recoverInterruptedCommands();
    reconcileRuntimeOwnershipOnStartup(engine);
    new PlaybookRunService(engine).recoverInterruptedRuns();
  };
  reconcileRuntimeOwnership();

  const savedProcesses = engine.getTrackedProcesses();
  const processTracker = savedProcesses.length > 0
    ? ProcessTracker.deserialize(savedProcesses)
    : new ProcessTracker();
  partialProcessTracker = processTracker;
  processTracker.setMutationGuard(() => engine.assertPersistenceWritable());

  // Reconcile tracked process liveness on startup — dead PIDs are marked completed
  const processStatusesChangedOnStartup = savedProcesses.length > 0
    && engine.isPersistenceWritable()
    ? processTracker.refreshStatuses()
    : false;
  const processTrackerUnsubscribe = processTracker.onChange(() => {
    if (!engine.isPersistenceWritable()) return;
    engine.setTrackedProcesses(processTracker.serialize());
  });
  partialProcessTrackerUnsubscribe = processTrackerUnsubscribe;
  if (processStatusesChangedOnStartup) {
    engine.reconcileTrackedProcessesOnStartup(processTracker.serialize());
  }

  const sessionManager = new SessionManager(engine);
  partialSessionManager = sessionManager;
  sessionManager.registerAdapter(new LocalPtyAdapter());
  sessionManager.registerAdapter(new SshAdapter());
  sessionManager.registerAdapter(new SocketAdapter());
  const sessionDescriptorUnsubscribe = sessionManager.onDurableEvent(event => {
    engine.recordSessionDescriptor(event.session);
  });
  sessionManager.restorePersistedDescriptors(engine.getSessionDescriptors());
  const server = new McpServer({
    name: 'overwatch-mcp-server',
    version: '0.1.0',
  });

  const dashboardPort = options.dashboardPort ?? parseInt(process.env.OVERWATCH_DASHBOARD_PORT || '8384', 10);
  const dashboard = dashboardPort > 0
    ? new DashboardServer(
        engine,
        dashboardPort,
        undefined,
        sessionManager,
        managedConfigPath,
        applicationCommands,
      )
    : null;

  // In-process tape controller. Always constructed; only opens a writer when
  // explicitly enabled via env, engagement config, or dashboard toggle.
  const tape = new InProcessTapeController(engine, {
    defaultDir: process.env.OVERWATCH_TAPE_DIR ?? authoritativeConfig.tape?.dir,
    file: process.env.OVERWATCH_TAPE_FILE ?? authoritativeConfig.tape?.file,
  });
  if (dashboard) {
    dashboard.attachTape(tape);
    dashboard.attachSkills(skills);
    dashboard.attachRuntimeLifecycle(() => runtimeLifecycle.phase);
    if (runtimeLease) dashboard.attachRuntimeStatus(() => runtimeStatus()!);
  }

  // File-backed engagement manager for the create_engagement / list_engagements
  // tools. Stateless over engagements/ (no in-memory cache), so this instance is
  // equivalent to the dashboard's own — no need to share a single object. An
  // embedded in-memory config has no authority to create storage beside the
  // caller's cwd; only an explicit/loaded config path enables these writes.
  const engagementManager = new EngagementManager(
    resolvedConfigPath,
    undefined,
    {
      readOnly: managedConfigPath === undefined || !engine.isPersistenceWritable(),
      isWritable: () => managedConfigPath !== undefined && engine.isPersistenceWritable(),
    },
  );
  engine.setRollbackCoordinator({
    beforeRollback: () => {
      const unresolvedSessions = sessionManager.listUnresolvedRuntimeOwnership();
      if (unresolvedSessions.length > 0) {
        throw new Error(
          `Close or resolve ${unresolvedSessions.length} runtime-owned session(s) before rolling back durable state.`,
        );
      }
      const liveProcesses = processTracker.listActive();
      if (liveProcesses.length > 0) {
        throw new Error(
          `Resolve ${liveProcesses.length} live tracked process(es) before rolling back durable state.`,
        );
      }
    },
    afterRollback: () => {
      sessionManager.reconcileAfterStateRollback();
      sessionManager.restorePersistedDescriptors(engine.getSessionDescriptors());
      processTracker.restore(engine.getTrackedProcesses(), { notify: false });
    },
  });

  const registeredTools = registerAllTools(server, {
    engine,
    skills,
    processTracker,
    sessionManager,
    engagementManager,
    getDashboardStatus: () => ({
      enabled: dashboard !== null,
      running: dashboard?.running ?? false,
      address: dashboard?.address,
    }),
    runtimePhase: () => runtimeLifecycle.phase,
  });
  if (dashboard) {
    dashboard.attachMcpTools(registeredTools);
  }

  // App-level agent-task execution (scripted + headless backends + watchdog).
  // Owned here, not by the dashboard, so agent execution runs whether or not the
  // dashboard is enabled. Started in startStdioApp/startHttpApp; the HTTP
  // endpoint for headless sub-agents is supplied later via setHttpEndpoint.
  const taskExecution = new TaskExecutionService(engine, processTracker, options.taskExecution);
  // A config-divergent daemon starts read-only, so the initial executor start is
  // intentionally deferred. Reconciliation must reopen the executor as part of
  // the same post-recovery lifecycle; otherwise the dashboard can reserve a
  // planner forever with no drain loop running.
  engine.setRuntimeOwnershipRecoveryHandler(() => {
    reconcileRuntimeOwnership();
    sessionManager.reconcileAfterStateRollback();
    sessionManager.restorePersistedDescriptors(engine.getSessionDescriptors());
    // The engine invokes this handler before it clears the deferred-startup
    // maintenance flag. Resume on the next microtask so no worker can observe
    // the temporary recovery write allowance as an open execution gate.
    queueMicrotask(() => {
      if (!engine.isPersistenceWritable()) return;
      // Config recovery opens the engine before executor preparation and the
      // durable READY publication complete. Close every public mutation gate
      // for that boundary; a transient retry must never expose a half-resumed
      // writable runtime under the prior ready_read_only phase.
      runtimeLifecycle.phase = 'binding';
      try {
        taskExecution.resumeAfterRecovery(() => {
          const leaseStatus = runtimeLease?.getStatus();
          if (leaseStatus && leaseStatus.phase !== 'ready') {
            runtimeLease?.update({
              phase: 'ready',
              persistence_writable: true,
              recovery_reason: null,
            });
          }
          publishManagedDaemonReady({
            runtimeLease,
            runtimeBuild,
            phase: 'ready',
            ...(dashboard?.address ? { dashboard_url: dashboard.address } : {}),
            ...(leaseStatus?.mcp_url
              ? { mcp_url: leaseStatus.mcp_url }
              : {}),
          });
          runtimeLifecycle.phase = 'ready';
        });
      } catch (error) {
        // TaskExecutionService owns an indefinite bounded retry (250ms → 30s).
        // This catch prevents an uncaught recovery microtask from crashing the
        // daemon while preserving a closed public binding phase
        // until executor preparation and READY publication both succeed.
        const message = error instanceof Error ? error.message : String(error);
        console.error(`[recovery] task execution resume failed; retry scheduled: ${message}`);
      }
    });
  });
  // Let the dashboard's cancel endpoint kill headless sub-agent processes.
  dashboard?.attachTaskExecution(taskExecution);
  if (runtimeLease) {
    const recovery = engine.getPersistenceRecoveryStatus();
    runtimeLease.update({
      phase: 'binding',
      persistence_writable: engine.isPersistenceWritable(),
      recovery_reason: engine.isPersistenceWritable()
        ? null
        : recovery.reason ?? recovery.last_persistence_error ?? recovery.outcome,
    });
  }
  runtimeLifecycle.phase = 'binding';

  return {
    get config() { return engine.getConfig(); },
    engine,
    skills,
    processTracker,
    processTrackerUnsubscribe,
    sessionManager,
    sessionDescriptorUnsubscribe,
    engagementManager,
    server,
    dashboard,
    taskExecution,
    applicationCommands,
    telemetry: getTelemetry()!,
    tape,
    registeredTools,
    runtimeLease,
    runtimeLifecycle,
    runtimeBuild,
  };
  } catch (error) {
    try { partialSessionManager?.beginShutdown(); } catch { /* continue unwinding */ }
    try { partialProcessTrackerUnsubscribe?.(); } catch { /* continue unwinding */ }
    try { partialProcessTracker?.setMutationGuard(undefined); } catch { /* continue unwinding */ }
    try { partialEngine?.setRollbackCoordinator(undefined); } catch { /* continue unwinding */ }
    try { partialEngine?.dispose(); } catch { /* continue unwinding */ }
    try { runtimeLease?.release(); } catch (releaseError) {
      console.error(
        `[runtime-owner] startup failed and lease cleanup also failed: ${
          releaseError instanceof Error ? releaseError.message : String(releaseError)
        }`,
      );
    }
    throw error;
  }
}

export async function startStdioApp(app: OverwatchApp): Promise<void> {
  try {
    if (app.dashboard) {
      const dashboard = await app.dashboard.start();
      if (!dashboard.started) {
        throw new Error(`Dashboard ownership could not be acquired: ${dashboard.error || 'unknown error'}`);
      }
    }
    const baseTransport = new StdioServerTransport();
    // Wrap unconditionally so the dashboard can flip recording on/off without
    // restarting the transport.
    const transport = app.tape.wrapTransport(baseTransport);
    await app.server.connect(transport);
    maybeAutoEnableTape(app);
    app.taskExecution.start({ deferInitialDrain: true });
    markRuntimeReady(app);
    app.taskExecution.activateAfterRuntimeReady();
    console.error('Overwatch MCP server running on stdio');
  } catch (error) {
    await shutdownOverwatchApp(app).catch(() => { /* preserve the startup cause */ });
    throw error;
  }
}

function markRuntimeReady(app: OverwatchApp): void {
  const writable = app.engine.isPersistenceWritable();
  const recovery = app.engine.getPersistenceRecoveryStatus();
  const phase = writable ? 'ready' : 'ready_read_only';
  app.runtimeLease?.update({
    phase,
    persistence_writable: writable,
    recovery_reason: writable
      ? null
      : recovery.reason ?? recovery.last_persistence_error ?? recovery.outcome,
    ...(app.dashboard?.address ? { dashboard_url: app.dashboard.address } : {}),
  });
  app.runtimeLifecycle.phase = phase;
  // Management publication is the final fallible startup commit. The launcher
  // requires both API readiness and this exact record, so a publication error
  // cannot become a false successful start.
  publishManagedDaemonReady({
    runtimeLease: app.runtimeLease,
    runtimeBuild: app.runtimeBuild,
    phase,
    ...(app.dashboard?.address ? { dashboard_url: app.dashboard.address } : {}),
    ...(app.runtimeLease?.getStatus().mcp_url
      ? { mcp_url: app.runtimeLease.getStatus().mcp_url }
      : {}),
  });
}

/**
 * Decide whether to auto-enable the in-process tape at startup. Env wins over
 * engagement config (operator override). `OVERWATCH_TAPE=0` forces off even
 * when the config says on, so a single shell prefix can disable it.
 */
export function getAutoTapeStartDecision(config: EngagementConfig): { enabled: boolean; startedBy?: TapeStartSource } {
  const env = process.env.OVERWATCH_TAPE;
  if (env === '0' || env === 'false' || env === 'off') return { enabled: false };
  if (env === '1' || env === 'true' || env === 'on') return { enabled: true, startedBy: 'env' };
  if (config.tape?.enabled === true) return { enabled: true, startedBy: 'config' };
  return { enabled: false };
}

export function maybeAutoEnableTape(app: OverwatchApp): void {
  const decision = getAutoTapeStartDecision(app.engine.getConfig());
  if (!decision.enabled || app.tape.isEnabled() || !app.engine.isPersistenceWritable()) return;
  app.engine.assertPersistenceWritable();
  const status = app.tape.enable({ startedBy: decision.startedBy });
  const suffix = status.started_by ? ` (started_by=${status.started_by})` : '';
  console.error(`Overwatch tape recording to ${status.path}${suffix}`);
}

export const MAX_HTTP_SESSIONS = 50;
export const DEFAULT_MCP_SESSION_IDLE_MS = 30 * 60_000;

// Default fallback when no engagement-specific approval timeout is configured.
// Mirrors DEFAULT_TIMEOUT_MS in pending-action-queue.ts.
export const DEFAULT_APPROVAL_TIMEOUT_MS = 300_000; // 5 minutes
// The HTTP socket must outlive the approval window by a margin, otherwise Node's
// default requestTimeout (~5 min) tears down the connection mid-approval and
// orphans the pending action. We add headroom on top of the approval timeout.
export const MCP_REQUEST_TIMEOUT_MARGIN_MS = 60_000; // 1 minute

export function connectableHttpHost(host: string): string {
  const normalized = host.trim().toLowerCase();
  if (normalized === '0.0.0.0') return '127.0.0.1';
  if (normalized === '::' || normalized === '[::]') return '[::1]';
  return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
}

export function resolveMcpTokenPath(): string {
  const configured = process.env.OVERWATCH_MCP_TOKEN_FILE;
  if (configured) return resolve(configured);
  const configPath = resolve(process.env.OVERWATCH_CONFIG || './engagement.json');
  return join(dirname(configPath), '.overwatch-mcp-token');
}

export type StartHttpAppOptions = {
  port?: number;
  host?: string;
  maxSessions?: number;
  sessionIdleMs?: number;
};

export async function startHttpApp(app: OverwatchApp, options: StartHttpAppOptions = {}): Promise<Express> {
  const port = options.port ?? parseInt(process.env.OVERWATCH_HTTP_PORT || '3000', 10);
  const host = options.host ?? process.env.OVERWATCH_HTTP_HOST ?? '127.0.0.1';
  try {

  const expressApp = createMcpExpressApp({ host });
  const taskCredentials = new McpTaskCredentialAuthority();

  // The listener may bind before the dashboard is ready so startup can reserve
  // both ports transactionally. Until the lifecycle reaches READY, no MCP
  // request may observe or mutate the half-started runtime.
  expressApp.use('/mcp', (_req, res, next) => {
    const phase = app.runtimeLifecycle.phase;
    if (phase !== 'ready' && phase !== 'ready_read_only') {
      res.status(503).json({
        error: `Overwatch is ${phase}; MCP is not ready yet.`,
        code: 'RUNTIME_NOT_READY',
      });
      return;
    }
    next();
  });

  // Guard /mcp with bearer-token auth before any route handlers run. The HTTP
  // daemon exposes the full Overwatch tool surface — including target-facing
  // run_bash/run_tool — to every connecting client (the primary + headless
  // sub-agents). Any local process could otherwise drive those tools, so we
  // FAIL CLOSED: a token is required by default, even on loopback. If none is
  // configured we generate one and log it (zero-config but secure). Explicit
  // opt-out (e.g. trusted single-user dev or test harnesses) via
  // OVERWATCH_MCP_REQUIRE_TOKEN=0.
  const requireDisabled = process.env.OVERWATCH_MCP_REQUIRE_TOKEN === '0'
    || process.env.OVERWATCH_MCP_REQUIRE_TOKEN === 'false';
  const requireMcpToken = !requireDisabled;
  if (requireMcpToken && !process.env.OVERWATCH_MCP_TOKEN) {
    const tokenPath = resolveMcpTokenPath();
    let generated: string;
    try {
      const existing = readFileSync(tokenPath, 'utf8').trim();
      generated = existing || randomUUID().replace(/-/g, '');
    } catch {
      generated = randomUUID().replace(/-/g, '');
    }
    process.env.OVERWATCH_MCP_TOKEN = generated;
    // Do NOT print the secret to stderr — it persists in logs / terminal
    // scrollback / log aggregation. Write it to a 0600 file beside the engagement
    // state and log only the path + a non-reversible fingerprint. Headless
    // sub-agents read the env var in-process; an operator wiring .mcp.http.json
    // reads the file.
    const fingerprint = createHash('sha256').update(generated).digest('hex').slice(0, 12);
    let tokenPersisted = false;
    try {
      writeFileSync(tokenPath, generated, { mode: 0o600 });
      chmodSync(tokenPath, 0o600);
      tokenPersisted = true;
    } catch {
      console.error('[overwatch] could not persist the MCP token file — set OVERWATCH_MCP_TOKEN explicitly before the next restart.');
    }
    console.error(tokenPersisted
      ? `[overwatch] /mcp auth required — using the stable token at ${tokenPath} (sha256:${fingerprint}…).`
      : `[overwatch] /mcp auth required — using an in-memory token for this run (sha256:${fingerprint}…).`);
  }
  const mcpAuth = createMcpAuthMiddleware({
    host,
    requireToken: requireMcpToken,
    resolveTaskToken: token => taskCredentials.resolve(token),
  });
  expressApp.use(['/mcp', '/api/runtime', '/api/runtime/shutdown'], mcpAuth);
  expressApp.get('/api/runtime', (_req, res) => {
    const persisted = app.runtimeLease?.getStatus();
    if (!persisted || !app.runtimeBuild) {
      res.status(503).json({ error: 'Runtime identity is not available', code: 'RUNTIME_IDENTITY_UNAVAILABLE' });
      return;
    }
    const recovery = app.engine.getPersistenceRecoveryStatus();
    const publiclyWritable = app.runtimeLifecycle.phase === 'ready'
      && app.engine.isPersistenceWritable();
    res.json({
      runtime_build: app.runtimeBuild,
      runtime_status: {
        ...persisted,
        phase: app.runtimeLifecycle.phase,
        persistence_writable: publiclyWritable,
        ...(!publiclyWritable && (recovery.reason || recovery.last_persistence_error)
          ? { recovery_reason: recovery.reason ?? recovery.last_persistence_error }
          : {}),
      },
    });
  });
  expressApp.post('/api/runtime/shutdown', (req, res) => {
    const expectedNonce = process.env.OVERWATCH_DAEMON_MANAGEMENT_NONCE;
    if (process.env.OVERWATCH_DAEMON_MANAGED !== '1' || !expectedNonce) {
      res.status(404).json({ error: 'Managed shutdown is not available', code: 'MANAGED_SHUTDOWN_UNAVAILABLE' });
      return;
    }
    const masterToken = process.env.OVERWATCH_MCP_TOKEN;
    if (!masterToken || req.header('authorization') !== `Bearer ${masterToken}`) {
      res.status(403).json({
        error: 'Managed shutdown requires the operator MCP credential',
        code: 'MANAGED_SHUTDOWN_OPERATOR_CREDENTIAL_REQUIRED',
      });
      return;
    }
    if (req.header('x-overwatch-management-nonce') !== expectedNonce) {
      res.status(403).json({ error: 'Managed shutdown identity mismatch', code: 'MANAGED_SHUTDOWN_IDENTITY_MISMATCH' });
      return;
    }
    if (!app.requestManagedShutdown) {
      res.status(503).json({ error: 'Managed shutdown is not ready', code: 'MANAGED_SHUTDOWN_NOT_READY' });
      return;
    }
    res.status(202).json({ accepted: true });
    setImmediate(() => app.requestManagedShutdown?.());
  });

  const transports: Record<string, StreamableHTTPServerTransport> = {};
  const transportActors: Record<string, string | null> = {};
  const transportActivity: Record<string, { last_activity_at: number; active_requests: number }> = {};
  app.httpTransports = transports;
  let pendingSessionInitializations = 0;
  let credentialCleanupTimer: ReturnType<typeof setTimeout> | null = null;
  let credentialCleanupClosed = false;
  const revokeTerminalWorkerCredentials = (): void => {
    credentialCleanupTimer = null;
    if (credentialCleanupClosed) return;
    const terminalTaskIds = new Set(taskCredentials.taskIds().filter(taskId => {
      const status = app.engine.getTask(taskId)?.status;
      return status === undefined
        || status === 'completed'
        || status === 'failed'
        || status === 'interrupted';
    }));
    if (terminalTaskIds.size === 0) return;
    for (const taskId of terminalTaskIds) taskCredentials.revoke(taskId);
    for (const [sessionId, actorTaskId] of Object.entries(transportActors)) {
      if (!actorTaskId || !terminalTaskIds.has(actorTaskId)) continue;
      const transport = transports[sessionId];
      delete transports[sessionId];
      delete transportActors[sessionId];
      delete transportActivity[sessionId];
      void transport?.close().catch(() => { /* terminal worker cleanup is best-effort */ });
    }
  };
  const credentialUpdateUnsubscribe = app.engine.onUpdate(() => {
    if (credentialCleanupClosed || credentialCleanupTimer) return;
    // Do not close the transport from inside the update_agent request that made
    // the task terminal. Let its response flush, then revoke the credential and
    // close any actor-owned sessions on the next event-loop turn.
    credentialCleanupTimer = setTimeout(revokeTerminalWorkerCredentials, 0);
    credentialCleanupTimer.unref?.();
  });
  const configuredSessionIdleMs = options.sessionIdleMs
    ?? Number(process.env.OVERWATCH_MCP_SESSION_IDLE_MS || DEFAULT_MCP_SESSION_IDLE_MS);
  const sessionIdleMs = Number.isFinite(configuredSessionIdleMs) && configuredSessionIdleMs > 0
    ? (options.sessionIdleMs === undefined
        ? Math.max(10_000, configuredSessionIdleMs)
        : configuredSessionIdleMs)
    : DEFAULT_MCP_SESSION_IDLE_MS;
  const closeSession = (sessionId: string): void => {
    const transport = transports[sessionId];
    delete transports[sessionId];
    delete transportActors[sessionId];
    delete transportActivity[sessionId];
    void transport?.close().catch(() => { /* idle/session cleanup is best-effort */ });
  };
  const reapIdleSessions = (): number => {
    const cutoff = Date.now() - sessionIdleMs;
    let reaped = 0;
    for (const [sessionId, activity] of Object.entries(transportActivity)) {
      if (activity.active_requests > 0 || activity.last_activity_at > cutoff) continue;
      closeSession(sessionId);
      reaped++;
    }
    return reaped;
  };
  const sessionReaper = setInterval(
    reapIdleSessions,
    Math.max(
      options.sessionIdleMs === undefined ? 5_000 : 10,
      Math.min(30_000, Math.floor(sessionIdleMs / 2)),
    ),
  );
  sessionReaper.unref?.();
  const trackResponse = (sessionId: string, res: Response): void => {
    const activity = transportActivity[sessionId];
    if (!activity) return;
    activity.last_activity_at = Date.now();
    activity.active_requests++;
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      const current = transportActivity[sessionId];
      if (!current) return;
      current.active_requests = Math.max(0, current.active_requests - 1);
      current.last_activity_at = Date.now();
    };
    res.once('finish', finish);
    res.once('close', finish);
  };
  app.mcpCredentialCleanup = () => {
    if (credentialCleanupClosed) return;
    credentialCleanupClosed = true;
    clearInterval(sessionReaper);
    credentialUpdateUnsubscribe();
    if (credentialCleanupTimer) clearTimeout(credentialCleanupTimer);
    credentialCleanupTimer = null;
    taskCredentials.clear();
  };

  // Each HTTP session needs its own McpServer (SDK limitation: one connect() per server).
  // All sessions share the same engine, skills, and services.
  function createSessionServer(authenticatedActorTaskId: string | null): McpServer {
    const server = new McpServer({
      name: 'overwatch-mcp-server',
      version: '0.1.0',
    });
    registerAllTools(server, {
      engine: app.engine,
      skills: app.skills,
      processTracker: app.processTracker,
      sessionManager: app.sessionManager,
      engagementManager: app.engagementManager,
      getDashboardStatus: () => ({
        enabled: app.dashboard !== null,
        running: app.dashboard?.running ?? false,
        address: app.dashboard?.address,
      }),
      authenticatedActorTaskId,
      runtimePhase: () => app.runtimeLifecycle.phase,
    });
    return server;
  }

  // MCP POST — initialize new session or route to existing
  expressApp.post('/mcp', async (req: Request, res: Response) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    const actorTaskId = getAuthenticatedMcpActorTaskId(req);

    if (sessionId && transports[sessionId]) {
      if (transportActors[sessionId] !== actorTaskId) {
        res.status(401).json({ error: 'MCP session credential does not match its authenticated owner' });
        return;
      }
      trackResponse(sessionId, res);
      await transports[sessionId].handleRequest(req, res, req.body);
      return;
    }

    if (!sessionId && isInitializeRequest(req.body)) {
      const maxSessions = options.maxSessions ?? MAX_HTTP_SESSIONS;
      reapIdleSessions();
      if (Object.keys(transports).length + pendingSessionInitializations >= maxSessions) {
        res.status(503).json({
          jsonrpc: '2.0',
          error: { code: -32000, message: `Too many active sessions (limit: ${maxSessions}). Close existing sessions before opening new ones.` },
          id: null,
        });
        return;
      }
      pendingSessionInitializations++;
      let pendingReservationHeld = true;
      const baseTransport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sid: string) => {
          // Convert the pending reservation into the active transport slot at
          // the exact initialization boundary. Keeping both until the request
          // finishes temporarily double-counts a valid session.
          if (pendingReservationHeld) {
            pendingSessionInitializations = Math.max(0, pendingSessionInitializations - 1);
            pendingReservationHeld = false;
          }
          // Store the *base* transport — handleRequest() is HTTP-specific
          // and lives on StreamableHTTPServerTransport, not on the generic
          // wrapper. The wrapper is only used for the MCP Server connect
          // path so its send/recv hooks can mirror frames into the tape.
          transports[sid] = baseTransport;
          transportActors[sid] = actorTaskId;
          transportActivity[sid] = { last_activity_at: Date.now(), active_requests: 0 };
          trackResponse(sid, res);
        },
      });
      baseTransport.onclose = () => {
        const sid = baseTransport.sessionId;
        if (sid) {
          delete transports[sid];
          delete transportActors[sid];
          delete transportActivity[sid];
        }
      };
      const wrappedTransport = app.tape.wrapTransport(baseTransport);
      const server = createSessionServer(actorTaskId);
      try {
        await server.connect(wrappedTransport);
        await baseTransport.handleRequest(req, res, req.body);
      } finally {
        if (pendingReservationHeld) {
          pendingSessionInitializations = Math.max(0, pendingSessionInitializations - 1);
          pendingReservationHeld = false;
        }
      }
      return;
    }

    res.status(400).json({
      jsonrpc: '2.0',
      error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
      id: null,
    });
  });

  // MCP GET — SSE stream for server-initiated messages
  expressApp.get('/mcp', async (req: Request, res: Response) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    if (!sessionId || !transports[sessionId]) {
      res.status(400).send('Invalid or missing session ID');
      return;
    }
    if (transportActors[sessionId] !== getAuthenticatedMcpActorTaskId(req)) {
      res.status(401).json({ error: 'MCP session credential does not match its authenticated owner' });
      return;
    }
    // A live SSE response is the session's server-to-client connection. Keep
    // it active until finish/close; an actually abandoned client closes the
    // response and then becomes eligible for idle reaping.
    trackResponse(sessionId, res);
    await transports[sessionId].handleRequest(req, res);
  });

  // MCP DELETE — session termination
  expressApp.delete('/mcp', async (req: Request, res: Response) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    if (!sessionId || !transports[sessionId]) {
      res.status(400).send('Invalid or missing session ID');
      return;
    }
    if (transportActors[sessionId] !== getAuthenticatedMcpActorTaskId(req)) {
      res.status(401).json({ error: 'MCP session credential does not match its authenticated owner' });
      return;
    }
    trackResponse(sessionId, res);
    await transports[sessionId].handleRequest(req, res);
  });

  // Start HTTP server — use http.createServer so server.address() is
  // reliable even with ephemeral port 0.
  const { createServer: createHttpServer } = await import('http');
  const server = createHttpServer(expressApp);

  // Approvals over HTTP block the tool-call request for up to approval_timeout_ms.
  // Node's default server.requestTimeout (~5 min) would close the socket mid-wait
  // and orphan the pending approval, so we set an explicit timeout that always
  // outlives the approval window by MCP_REQUEST_TIMEOUT_MARGIN_MS. We deliberately
  // do NOT set requestTimeout = 0 (unbounded): a finite ceiling keeps a hung
  // request from leaking a socket forever, while the queue's own approval-timeout
  // auto-resolve remains the functional pressure valve for un-answered approvals.
  const approvalTimeoutMs = app.engine.getConfig().opsec?.approval_timeout_ms ?? DEFAULT_APPROVAL_TIMEOUT_MS;
  const mcpRequestTimeoutMs = approvalTimeoutMs + MCP_REQUEST_TIMEOUT_MARGIN_MS;
  server.requestTimeout = mcpRequestTimeoutMs;
  // keepAliveTimeout/headersTimeout must exceed requestTimeout to avoid Node
  // racing the socket closed before the request timeout fires.
  server.keepAliveTimeout = mcpRequestTimeoutMs + 5_000;
  server.headersTimeout = mcpRequestTimeoutMs + 10_000;

  app.httpServer = server;

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.removeListener('error', reject);
      try {
        const addr = server.address();
        const boundPort = (addr && typeof addr === 'object') ? addr.port : port;
        // Tell the task-execution service where headless sub-agents should connect.
        // This enables the headless_mcp backend (only available in daemon mode).
        app.taskExecution.setHttpEndpoint({
          url: `http://${connectableHttpHost(host)}:${boundPort}/mcp`,
          tokenForTask: taskId => taskCredentials.issue(taskId),
        });
        app.runtimeLease?.update({
          mcp_url: `http://${connectableHttpHost(host)}:${boundPort}/mcp`,
        });
        resolve();
      } catch (error) {
        // Listener finalization is part of the startup transaction. Rejecting
        // here lets the outer startup catch close the now-bound socket and
        // release runtime ownership instead of surfacing an uncaught callback.
        reject(error);
      }
    });
  });

  // Bind every public listener before starting tape/workers or reporting READY.
  // A later failure is unwound by the entrypoint's centralized shutdown path.
  if (app.dashboard) {
    const dashboard = await app.dashboard.start();
    if (!dashboard.started) {
      throw new Error(`Dashboard ownership could not be acquired: ${dashboard.error || 'unknown error'}`);
    }
  }
  maybeAutoEnableTape(app);
  app.taskExecution.start({ deferInitialDrain: true });
  markRuntimeReady(app);
  app.taskExecution.activateAfterRuntimeReady();

  const addr = server.address();
  const boundPort = (addr && typeof addr === 'object') ? addr.port : port;
  console.error(`Overwatch MCP HTTP transport at http://${connectableHttpHost(host)}:${boundPort}/mcp`);
  if (app.dashboard?.running) console.error(`Dashboard at ${app.dashboard.address}`);
  return expressApp;
  } catch (error) {
    await shutdownOverwatchApp(app).catch(() => { /* preserve the startup cause */ });
    throw error;
  }
}

async function performShutdownOverwatchApp(app: OverwatchApp): Promise<void> {
  let firstError: unknown;
  const shutdownDeadline = Date.now() + 18_000;
  const capture = (error: unknown): void => {
    if (firstError === undefined) firstError = error;
  };
  const cleanup = async (operation: () => unknown | Promise<unknown>): Promise<void> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const remaining = Math.max(1, shutdownDeadline - Date.now());
      await Promise.race([
        Promise.resolve().then(operation),
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(
            () => reject(new Error('runtime cleanup exceeded the shared shutdown deadline')),
            remaining,
          );
          timer.unref?.();
        }),
      ]);
    } catch (error) {
      capture(error);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };

  try {
    if (app.runtimeLifecycle) app.runtimeLifecycle.phase = 'stopping';
    try {
      app.runtimeLease?.update({
        phase: 'stopping',
        persistence_writable: false,
      });
    } catch (error) {
      capture(error);
    }
    // Close task scheduling synchronously before awaiting any transport or
    // dashboard cleanup. Existing child termination remains awaited below.
    // Partial app fixtures and one-release embedders may not yet expose the
    // new synchronous quiesce hook. The built-in service always does.
    try { app.taskExecution.beginShutdown?.(); } catch (error) { capture(error); }
    await cleanup(() => app.dashboard?.beginRuntimeShutdown?.());

    // Stop accepting HTTP work immediately. The close callback is awaited only
    // after protocol transports have received cancellation, so keep-alive/SSE
    // sockets cannot admit work while worker shutdown is in progress.
    const httpClosePromise = app.httpServer
      ? new Promise<void>((resolveClose, rejectClose) => {
          app.httpServer!.close(error => {
            const code = (error as NodeJS.ErrnoException | undefined)?.code;
            if (!error || code === 'ERR_SERVER_NOT_RUNNING') resolveClose();
            else rejectClose(error);
          });
        })
      : undefined;
    await cleanup(() => app.mcpCredentialCleanup?.());

    // Close HTTP transport sessions. In-flight requests receive cancellation
    // through the SDK signal, which the process runner combines with its
    // persistence gate monitor.
    if (app.httpTransports) {
      for (const [sid, transport] of Object.entries(app.httpTransports)) {
        await cleanup(() => transport.close());
        delete app.httpTransports[sid];
      }
    }
    const forceClose = (app.httpServer as Server & { closeAllConnections?: () => void } | undefined)
      ?.closeAllConnections;
    await cleanup(() => forceClose?.call(app.httpServer));
    if (httpClosePromise) await cleanup(() => httpClosePromise);

    // Stop agent-task execution and AWAIT headless children exiting (SIGTERM→
    // SIGKILL) so none outlive the daemon. Every later cleanup still runs if a
    // component reports an error.
    await cleanup(() => app.taskExecution.shutdown());
    // Stop the idle reaper before the first shutdown descriptor read/write so
    // maintenance cannot race the final durable session projection.
    if (typeof app.sessionManager.beginShutdown === 'function') {
      await cleanup(() => app.sessionManager.beginShutdown());
    }
    if (app.engine.isPersistenceWritable()) {
      await cleanup(() => {
        for (const session of app.sessionManager.list(true)) {
          app.engine.recordSessionDescriptor(session);
        }
      });
    }
    // Preserve the pre-shutdown descriptors (including listener resume intent)
    // while SessionManager tears down runtime handles and closes graph edges.
    // Keep the mandatory descriptor owner installed until runtime teardown is
    // complete so any corrective lifecycle update cannot bypass durability.
    await cleanup(() => app.sessionManager.shutdown());
    await cleanup(() => app.sessionDescriptorUnsubscribe?.());
    if (app.dashboard) await cleanup(() => app.dashboard!.stop());
    await cleanup(() => app.tape.disable({ audit: app.engine.isPersistenceWritable() }));

    // A degraded engine intentionally rejects every durable mutation. Runtime
    // cleanup above remains mandatory, but attempting a final checkpoint would
    // only turn an orderly shutdown into a guard exception.
    if (app.engine.isPersistenceWritable()) {
      try {
        app.engine.setTrackedProcesses(app.processTracker.serialize());
        app.engine.persist();
        app.engine.flushNow();
      } catch (error) {
        capture(error);
      }
    }
  } finally {
    // dispose() cancels persistence retries, approval timers, and process-level
    // flush hooks. It must run even when another shutdown component failed or
    // the persistence gate is already closed.
    try { app.processTrackerUnsubscribe?.(); } catch (error) { capture(error); }
    try { app.processTracker.setMutationGuard(undefined); } catch (error) { capture(error); }
    try { app.engine.setRollbackCoordinator(undefined); } catch (error) { capture(error); }
    try { app.engine.dispose(); } catch (error) { capture(error); }
    if (firstError === undefined) {
      try { app.runtimeLease?.release(); } catch (error) { capture(error); }
    } else {
      // A cleanup operation may still own a process/socket callback even after
      // its deadline. Retain the process-lifetime owner until this PID exits;
      // the next startup can reclaim it only after proving the process dead.
      try {
        app.runtimeLease?.update({ phase: 'failed', persistence_writable: false });
      } catch { /* the original cleanup failure remains authoritative */ }
    }
  }

  if (firstError !== undefined) throw firstError;
}

const shutdownPromises = new WeakMap<OverwatchApp, Promise<void>>();

export function shutdownOverwatchApp(app: OverwatchApp): Promise<void> {
  const existing = shutdownPromises.get(app);
  if (existing) return existing;
  const pending = performShutdownOverwatchApp(app);
  shutdownPromises.set(app, pending);
  return pending;
}

export function createAppOrExit(options: CreateOverwatchAppOptions = {}): OverwatchApp {
  try {
    return createOverwatchApp(options);
  } catch (error) {
    console.error(formatConfigError(error, options.configPath || process.env.OVERWATCH_CONFIG || './engagement.json'));
    process.exit(1);
  }
}
