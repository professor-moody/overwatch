import { createHash } from 'node:crypto';
import type { ToolAnnotations } from '@modelcontextprotocol/sdk/types.js';
import type {
  AnySchema,
  ZodRawShapeCompat,
} from '@modelcontextprotocol/sdk/server/zod-compat.js';
import {
  normalizeObjectSchema,
  objectFromShape,
} from '@modelcontextprotocol/sdk/server/zod-compat.js';
import { toJsonSchemaCompat } from '@modelcontextprotocol/sdk/server/zod-json-schema-compat.js';
import {
  listArchetypes,
  type AgentArchetypeId,
} from './agent-archetypes.js';

export type JsonSchema = Record<string, unknown>;

export const TOOL_CATEGORY_DEFINITIONS = [
  { id: 'state-readiness', label: 'State & readiness', order: 10 },
  { id: 'execution-approval', label: 'Execution & approval', order: 20 },
  { id: 'graph-data', label: 'Graph & data', order: 30 },
  { id: 'agents-planning', label: 'Agents & planning', order: 40 },
  { id: 'credentials-playbooks', label: 'Credentials & playbooks', order: 50 },
  { id: 'sessions-runtime', label: 'Sessions & runtime', order: 60 },
  { id: 'config-scope', label: 'Configuration & scope', order: 70 },
  { id: 'audit-reporting', label: 'Audit & reporting', order: 80 },
] as const;

export type ToolCategoryId = typeof TOOL_CATEGORY_DEFINITIONS[number]['id'];

const CATEGORY_MEMBERS: Record<ToolCategoryId, readonly string[]> = {
  'state-readiness': [
    'get_state', 'get_recovery_status', 'run_lab_preflight', 'run_graph_health',
    'get_opsec_status', 'next_task', 'query_graph', 'find_paths', 'get_skill',
    'get_system_prompt',
  ],
  'execution-approval': [
    'validate_action', 'approve_action', 'deny_action', 'log_action_event',
    'log_thought', 'run_bash', 'run_tool', 'check_tools', 'track_process',
    'check_processes',
  ],
  'graph-data': [
    'report_finding', 'get_evidence', 'get_finding_readiness', 'parse_output',
    'ingest_json', 'export_graph', 'correct_graph', 'recompute_objectives',
    'suggest_inference_rule', 'ingest_bloodhound', 'ingest_azurehound',
    'ingest_screenshots',
  ],
  'agents-planning': [
    'register_agent', 'dispatch_agents', 'get_agent_context', 'update_agent',
    'submit_agent_transcript', 'propose_plan', 'ask_operator',
    'manage_agent_directive', 'acknowledge_agent_directive', 'research_cve',
    'agent_heartbeat', 'dispatch_subnet_agents', 'dispatch_campaign_agents',
    'manage_campaign', 'find_duplicate_agent_work', 'handoff_agent_work',
    'split_agent_work', 'merge_duplicate_agent_work',
  ],
  'credentials-playbooks': [
    'connect_postgres', 'list_postgres_tables', 'ingest_postgres_table',
    'validate_token_credential', 'test_webapp_credential',
    'expand_aws_credential', 'expand_github_credential',
    'expand_entra_credential', 'exchange_refresh_token', 'expand_oidc_capture',
    'list_playbook_runs', 'get_playbook_run', 'start_playbook_step',
    'resume_playbook_run', 'retry_playbook_step', 'skip_playbook_step',
    'interrupt_playbook_attempt', 'complete_playbook_attempt',
  ],
  'sessions-runtime': [
    'open_session', 'write_session', 'read_session', 'send_to_session',
    'list_sessions', 'resume_session', 'update_session', 'resize_session',
    'signal_session', 'close_session', 'register_mock_service',
  ],
  'config-scope': [
    'update_scope', 'resolve_config_divergence', 'create_engagement',
    'list_engagements', 'add_objective', 'set_opsec',
  ],
  'audit-reporting': [
    'verify_activity_chain', 'get_history', 'bundle_engagement',
    'get_decision_log', 'explain_action', 'get_timeline', 'ingest_transcript',
    'register_tape_session', 'run_retrospective', 'generate_report',
  ],
};

const CATEGORY_BY_TOOL = new Map<string, ToolCategoryId>();
for (const category of TOOL_CATEGORY_DEFINITIONS) {
  for (const name of CATEGORY_MEMBERS[category.id]) {
    if (CATEGORY_BY_TOOL.has(name)) {
      throw new Error(`Tool ${name} appears in more than one category`);
    }
    CATEGORY_BY_TOOL.set(name, category.id);
  }
}

const SHARED_DOC_PATHS: Record<string, string> = Object.fromEntries([
  ...['submit_agent_transcript', 'ingest_transcript'].map(name => [name, 'tools/transcripts.md']),
  ...['connect_postgres', 'list_postgres_tables', 'ingest_postgres_table'].map(name => [name, 'tools/postgres.md']),
  ...[
    'expand_aws_credential', 'expand_github_credential',
    'expand_entra_credential', 'exchange_refresh_token', 'expand_oidc_capture',
    'list_playbook_runs', 'get_playbook_run', 'start_playbook_step',
    'resume_playbook_run', 'retry_playbook_step', 'skip_playbook_step',
    'interrupt_playbook_attempt', 'complete_playbook_attempt',
  ].map(name => [name, 'tools/cloud-playbooks.md']),
  ...[
    'open_session', 'write_session', 'read_session', 'send_to_session',
    'list_sessions', 'resume_session', 'update_session', 'resize_session',
    'signal_session', 'close_session',
  ].map(name => [name, 'tools/sessions.md']),
  ...[
    'find_duplicate_agent_work', 'handoff_agent_work', 'split_agent_work',
    'merge_duplicate_agent_work',
  ].map(name => [name, 'tools/agent-work.md']),
  ['register_tape_session', 'tools/tape-sessions.md'],
  ['validate_token_credential', 'tools/token-credential.md'],
]);

export type ToolPersistenceMode = 'read' | 'write' | 'conditional';

export interface ToolDescriptor extends ToolEntry {
  category: ToolCategoryId;
  category_label: string;
  category_order: number;
  input_schema: JsonSchema;
  output_schema: JsonSchema | null;
  input_schema_sha256: string;
  output_schema_sha256: string | null;
  documentation: {
    path: string;
    purpose: string;
  };
  archetype_exposure: AgentArchetypeId[];
  persistence: {
    mode: ToolPersistenceMode;
    allowed_during_recovery: boolean;
  };
}

/** Compact prompt-facing projection retained for existing call sites/tests. */
export interface ToolEntry {
  name: string;
  title?: string;
  description: string;
  category?: string;
  read_only?: boolean;
  destructive?: boolean;
  idempotent?: boolean;
  open_world?: boolean;
}

export interface ToolRegistrationMetadata {
  title?: string;
  description?: string;
  inputSchema?: ZodRawShapeCompat | AnySchema;
  outputSchema?: ZodRawShapeCompat | AnySchema;
  annotations?: ToolAnnotations;
  _meta?: Record<string, unknown>;
}

function compareCodeUnits(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalize(value: unknown, parentKey?: string): unknown {
  if (Array.isArray(value)) {
    const normalized = value.map(item => canonicalize(item));
    return parentKey === 'required' && normalized.every(item => typeof item === 'string')
      ? normalized.slice().sort((left, right) => compareCodeUnits(left as string, right as string))
      : normalized;
  }
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => compareCodeUnits(left, right))
      .map(([key, nested]) => [key, canonicalize(nested, key)]),
  );
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function sha256Json(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function schemaToJsonSchema(
  schema: ZodRawShapeCompat | AnySchema | undefined,
  pipeStrategy: 'input' | 'output',
): JsonSchema | null {
  if (!schema) return pipeStrategy === 'input'
    ? { type: 'object', properties: {} }
    : null;
  // McpServer.registerTool materializes raw shapes (including `{}`) into a
  // Zod object before tools/list converts them. Mirror that registration step
  // so checked hashes describe exactly what an MCP client receives.
  const record = schema as unknown as Record<string, unknown>;
  const registeredSchema = typeof schema === 'object'
    && schema !== null
    && record._def === undefined
    && record._zod === undefined
    ? objectFromShape(schema as ZodRawShapeCompat)
    : schema;
  const normalized = normalizeObjectSchema(registeredSchema);
  if (!normalized) {
    if (pipeStrategy === 'input') return { type: 'object', properties: {} };
    throw new Error(`Tool ${pipeStrategy} schema is not an object schema`);
  }
  return canonicalize(toJsonSchemaCompat(normalized, {
    strictUnions: true,
    pipeStrategy,
  })) as JsonSchema;
}

function categoryFor(name: string): typeof TOOL_CATEGORY_DEFINITIONS[number] {
  const id = CATEGORY_BY_TOOL.get(name);
  if (!id) {
    throw new Error(`Tool ${name} has no canonical category; update CATEGORY_MEMBERS`);
  }
  return TOOL_CATEGORY_DEFINITIONS.find(category => category.id === id)!;
}

function documentationPathFor(name: string): string {
  return SHARED_DOC_PATHS[name]
    ?? `tools/${name.replaceAll('_', '-')}.md`;
}

function purposeFor(title: string | undefined, description: string): string {
  const firstParagraph = description.trim().split(/\n\s*\n/, 1)[0]
    ?.replace(/\s+/g, ' ')
    .replace(/[`*]/g, '')
    .trim();
  return firstParagraph || title || 'No public description supplied.';
}

function persistenceFor(name: string, readOnly: boolean): ToolDescriptor['persistence'] {
  if (name === 'resolve_config_divergence') {
    return { mode: 'write', allowed_during_recovery: true };
  }
  if (name === 'get_state' || name === 'get_system_prompt') {
    return { mode: 'conditional', allowed_during_recovery: false };
  }
  if (name === 'generate_report' || name === 'run_retrospective') {
    return { mode: 'conditional', allowed_during_recovery: false };
  }
  if (name === 'bundle_engagement') {
    return { mode: 'conditional', allowed_during_recovery: true };
  }
  if (name === 'check_processes') {
    return { mode: 'write', allowed_during_recovery: false };
  }
  return {
    mode: readOnly ? 'read' : 'write',
    allowed_during_recovery: readOnly,
  };
}

function archetypeExposure(name: string): AgentArchetypeId[] {
  return listArchetypes()
    .filter(archetype => archetype.tools.full || archetype.tools.overwatch.includes(name))
    .map(archetype => archetype.id);
}

export function buildToolDescriptor(
  name: string,
  config: ToolRegistrationMetadata,
): ToolDescriptor {
  const annotations = config.annotations;
  if (
    annotations?.readOnlyHint === undefined
    || annotations.destructiveHint === undefined
    || annotations.idempotentHint === undefined
    || annotations.openWorldHint === undefined
  ) {
    throw new Error(`Tool ${name} must declare all four MCP annotations`);
  }
  const category = categoryFor(name);
  const inputSchema = schemaToJsonSchema(config.inputSchema, 'input')!;
  const outputSchema = schemaToJsonSchema(config.outputSchema, 'output');
  const description = config.description ?? '';
  return {
    name,
    title: config.title,
    description,
    category: category.id,
    category_label: category.label,
    category_order: category.order,
    read_only: annotations.readOnlyHint,
    destructive: annotations.destructiveHint,
    idempotent: annotations.idempotentHint,
    open_world: annotations.openWorldHint,
    input_schema: inputSchema,
    output_schema: outputSchema,
    input_schema_sha256: sha256Json(inputSchema),
    output_schema_sha256: outputSchema ? sha256Json(outputSchema) : null,
    documentation: {
      path: documentationPathFor(name),
      purpose: purposeFor(config.title, description),
    },
    archetype_exposure: archetypeExposure(name),
    persistence: persistenceFor(name, annotations.readOnlyHint),
  };
}

export function toolRequiresWritablePersistence(
  descriptor: ToolDescriptor,
  input: Record<string, unknown>,
): boolean {
  if (descriptor.persistence.allowed_during_recovery) return false;
  if (descriptor.name === 'get_state') return input.snapshot === true;
  if (descriptor.name === 'get_system_prompt') return input.snapshot !== false;
  if (descriptor.name === 'generate_report') {
    return input.write_to_disk === true || input.persist_to_archive !== false;
  }
  if (descriptor.name === 'run_retrospective') return input.write_to_disk === true;
  if (descriptor.name === 'create_engagement') return input.dry_run !== true;
  if (descriptor.name === 'update_scope' || descriptor.name === 'set_opsec') {
    return input.confirm === true;
  }
  if (descriptor.name === 'manage_campaign') {
    return !['status', 'check_abort', 'children', 'parent_progress']
      .includes(String(input.action ?? ''));
  }
  return descriptor.persistence.mode !== 'read';
}

/** Whether this concrete invocation crosses an externally visible mutation
 * boundary. This is intentionally distinct from the recovery write gate:
 * previews and status actions may share a mutation-capable tool descriptor. */
export function toolInvocationMutatesDurableState(
  descriptor: ToolDescriptor,
  input: Record<string, unknown>,
): boolean {
  switch (descriptor.name) {
    case 'get_state':
      return input.snapshot === true;
    case 'get_system_prompt':
      return input.snapshot !== false;
    case 'generate_report':
      return input.write_to_disk === true || input.persist_to_archive !== false;
    case 'run_retrospective':
      return input.write_to_disk === true;
    case 'bundle_engagement':
      return true;
    case 'create_engagement':
      return input.dry_run !== true;
    case 'update_scope':
    case 'set_opsec':
      return input.confirm === true;
    case 'manage_campaign':
      return !['status', 'check_abort', 'children', 'parent_progress']
        .includes(String(input.action ?? ''));
    default:
      return descriptor.persistence.mode === 'write';
  }
}

export function toolCanMutateDurableState(descriptor: ToolDescriptor): boolean {
  return descriptor.persistence.mode !== 'read';
}

export function buildToolRegistryManifest(tools: readonly ToolDescriptor[]): {
  manifest_version: 1;
  tool_count: number;
  registry_sha256: string;
  categories: typeof TOOL_CATEGORY_DEFINITIONS;
  tools: ToolDescriptor[];
} {
  const names = tools.map(tool => tool.name);
  if (new Set(names).size !== names.length) throw new Error('Tool registry contains duplicate names');
  const sorted = [...tools].sort((left, right) => compareCodeUnits(left.name, right.name));
  const registrySha = sha256Json(sorted);
  return {
    manifest_version: 1,
    tool_count: sorted.length,
    registry_sha256: registrySha,
    categories: TOOL_CATEGORY_DEFINITIONS,
    tools: sorted,
  };
}
