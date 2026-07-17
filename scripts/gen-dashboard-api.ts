import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { z } from 'zod';
import {
  DASHBOARD_API_COMPATIBILITY_VERSION,
  DashboardHttpRegistry,
  getDashboardRouteManifest,
} from '../src/contracts/dashboard-api-v1.js';
import { DashboardWebSocketRegistry } from '../src/contracts/dashboard-v1.js';

const root = resolve(import.meta.dirname, '..');
const generatedClientPath = resolve(root, 'src/dashboard-next/src/lib/api.generated.ts');
const manifestPath = resolve(root, 'src/contracts/dashboard-api-v1.manifest.json');
const checkOnly = process.argv.includes('--check');

function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, child]) => `${JSON.stringify(key)}:${canonical(child)}`)
    .join(',')}}`;
}

function functionSource(value: unknown): string | undefined {
  if (typeof value !== 'function') return undefined;
  return String(value).replace(/\s+/g, ' ').trim();
}

function describeSchema(schema: z.ZodTypeAny, seen = new WeakSet<object>()): unknown {
  if (!schema || typeof schema !== 'object') return String(schema);
  if (seen.has(schema)) return { type: 'recursive' };
  seen.add(schema);
  const definition = (schema as unknown as { _def?: Record<string, unknown> })._def ?? {};
  const typeName = String(definition.typeName ?? schema.constructor?.name ?? 'unknown');
  const describe = (child: unknown) => describeSchema(child as z.ZodTypeAny, seen);
  const result: Record<string, unknown> = { type: typeName };

  switch (typeName) {
    case 'ZodObject': {
      const shapeFactory = definition.shape;
      const shape = typeof shapeFactory === 'function' ? shapeFactory() as Record<string, z.ZodTypeAny> : {};
      result.shape = Object.fromEntries(Object.entries(shape).sort(([left], [right]) => left.localeCompare(right)).map(([key, child]) => [key, describe(child)]));
      result.unknownKeys = definition.unknownKeys;
      result.catchall = describe(definition.catchall);
      break;
    }
    case 'ZodArray':
      result.element = describe(definition.type);
      result.min = definition.minLength;
      result.max = definition.maxLength;
      break;
    case 'ZodString':
    case 'ZodNumber':
    case 'ZodBigInt':
    case 'ZodDate':
      result.checks = definition.checks;
      result.coerce = definition.coerce;
      break;
    case 'ZodEnum':
      result.values = definition.values;
      break;
    case 'ZodNativeEnum':
      result.values = definition.values;
      break;
    case 'ZodLiteral':
      result.value = definition.value;
      break;
    case 'ZodUnion':
      result.options = (definition.options as z.ZodTypeAny[] | undefined)?.map(describe);
      break;
    case 'ZodDiscriminatedUnion':
      result.discriminator = definition.discriminator;
      result.options = [...((definition.optionsMap as Map<unknown, z.ZodTypeAny> | undefined)?.entries() ?? [])]
        .map(([key, child]) => [key, describe(child)]);
      break;
    case 'ZodRecord':
      result.key = describe(definition.keyType);
      result.value = describe(definition.valueType);
      break;
    case 'ZodOptional':
    case 'ZodNullable':
    case 'ZodDefault':
    case 'ZodCatch':
    case 'ZodReadonly':
    case 'ZodBranded':
      result.inner = describe(definition.innerType ?? definition.type);
      result.default = functionSource(definition.defaultValue);
      break;
    case 'ZodEffects': {
      result.inner = describe(definition.schema);
      const effect = definition.effect as { type?: unknown; transform?: unknown; refinement?: unknown } | undefined;
      result.effect = effect ? {
        type: effect.type,
        transform: functionSource(effect.transform),
        refinement: functionSource(effect.refinement),
      } : undefined;
      break;
    }
    case 'ZodPipeline':
      result.input = describe(definition.in);
      result.output = describe(definition.out);
      break;
    case 'ZodTuple':
      result.items = (definition.items as z.ZodTypeAny[] | undefined)?.map(describe);
      result.rest = describe(definition.rest);
      break;
    case 'ZodMap':
      result.key = describe(definition.keyType);
      result.value = describe(definition.valueType);
      break;
    case 'ZodSet':
      result.value = describe(definition.valueType);
      break;
    case 'ZodIntersection':
      result.left = describe(definition.left);
      result.right = describe(definition.right);
      break;
    case 'ZodLazy':
      result.getter = functionSource(definition.getter);
      break;
    default:
      break;
  }
  seen.delete(schema);
  return result;
}

const hashSchema = (schema: z.ZodTypeAny): string => createHash('sha256')
  .update(canonical(describeSchema(schema)))
  .digest('hex');

const schemaManifest = Object.fromEntries(Object.entries(DashboardHttpRegistry).map(([operationId, definition]) => [operationId, {
  path: hashSchema(definition.path_schema),
  query: hashSchema(definition.query_schema),
  body: hashSchema(definition.body_schema),
  responses: Object.fromEntries(Object.entries(definition.responses).map(([status, schema]) => [status, hashSchema(schema)])),
}]));

const wsManifest = Object.fromEntries(Object.entries(DashboardWebSocketRegistry).map(([channel, definition]) => [channel, {
  operation_id: definition.operation_id,
  path: definition.path,
  client_events: definition.client_events ? hashSchema(definition.client_events) : undefined,
  server_events: hashSchema(definition.server_events),
}]));

const hashInput = {
  compatibility_version: DASHBOARD_API_COMPATIBILITY_VERSION,
  routes: getDashboardRouteManifest(),
  schemas: schemaManifest,
  websockets: wsManifest,
};
const schemaHash = createHash('sha256').update(canonical(hashInput)).digest('hex');
const manifest = `${JSON.stringify({ ...hashInput, schema_hash: schemaHash }, null, 2)}\n`;

const operationIds = Object.keys(DashboardHttpRegistry).sort();
const operationUnion = operationIds.map(id => `  | ${JSON.stringify(id)}`).join('\n');
const wrappers = operationIds.map(operationId => {
  const functionName = `request${operationId[0].toUpperCase()}${operationId.slice(1)}`;
  return `export const ${functionName} = (input: GeneratedDashboardRequestFor<${JSON.stringify(operationId)}> = {}) => requestDashboardEndpoint(${JSON.stringify(operationId)}, input);`;
}).join('\n');

const generatedClient = `/* eslint-disable */
// AUTO-GENERATED by scripts/gen-dashboard-api.ts. DO NOT EDIT.
// Dashboard compatibility v${DASHBOARD_API_COMPATIBILITY_VERSION}; schema SHA-256 ${schemaHash}

import {
  DashboardHttpRegistry,
  buildDashboardPath,
  responseSchemaFor,
} from '@overwatch/dashboard-api-contracts';
import type {
  DashboardBodyInput,
  DashboardEndpoint,
  DashboardPathInput,
  DashboardQueryInput,
  DashboardSuccessOutput,
} from '@overwatch/dashboard-api-contracts';
import { dashboardFetch } from './dashboard-transport';

export const DASHBOARD_API_SCHEMA_HASH = ${JSON.stringify(schemaHash)} as const;
export type GeneratedDashboardOperationId =
${operationUnion};

export interface GeneratedDashboardRequest {
  path?: Record<string, unknown>;
  query?: Record<string, unknown>;
  body?: unknown;
  headers?: HeadersInit;
  signal?: AbortSignal;
  cache?: RequestCache;
}
export type GeneratedDashboardRequestFor<T extends GeneratedDashboardOperationId> =
  Omit<GeneratedDashboardRequest, 'path' | 'query' | 'body'> & {
    path?: DashboardPathInput<T>;
    query?: DashboardQueryInput<T>;
    body?: DashboardBodyInput<T>;
  };
export type GeneratedDashboardOutput<T extends GeneratedDashboardOperationId> =
  DashboardEndpoint<T>['response_kind'] extends 'binary'
    ? Response
    : DashboardSuccessOutput<T>;

export class DashboardApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = 'DashboardApiError';
  }
}

type DashboardApiErrorObserver = (error: DashboardApiError) => void;
let errorObserver: DashboardApiErrorObserver | undefined;
export function setDashboardApiErrorObserver(observer?: DashboardApiErrorObserver): void {
  errorObserver = observer;
}

function appendQuery(search: URLSearchParams, query: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || key === 'token') continue;
    if (Array.isArray(value)) {
      for (const item of value) search.append(key, String(item));
    } else {
      search.set(key, String(value));
    }
  }
}

export async function requestDashboardEndpoint<T extends GeneratedDashboardOperationId>(
  operationId: T,
  input: GeneratedDashboardRequestFor<T> = {},
): Promise<GeneratedDashboardOutput<T>> {
  const endpoint = DashboardHttpRegistry[operationId];
  if (!endpoint) throw new Error(\`Unknown dashboard operation: \${operationId}\`);
  const path = buildDashboardPath(operationId, input.path ?? {});
  const query = endpoint.query_schema.parse(input.query ?? {}) as Record<string, unknown>;
  const search = new URLSearchParams();
  appendQuery(search, query);
  const url = \`\${path}\${search.size > 0 ? \`?\${search.toString()}\` : ''}\`;
  const body = endpoint.body_schema.parse(input.body);
  const headers = new Headers(input.headers);
  if (body !== undefined && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const response = await dashboardFetch(url, {
    method: endpoint.method,
    headers,
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    ...(input.signal ? { signal: input.signal } : {}),
    ...(input.cache ? { cache: input.cache } : {}),
  });
  const registeredSchema = responseSchemaFor(endpoint, response.status);
  const explicitlyRegistered = Object.prototype.hasOwnProperty.call(endpoint.responses, response.status);
  if (endpoint.response_kind === 'binary' && explicitlyRegistered) {
    return response as GeneratedDashboardOutput<T>;
  }

  const raw = await response.text().catch(() => '');
  let payload: unknown;
  try {
    payload = raw ? JSON.parse(raw) : undefined;
  } catch {
    payload = raw;
  }

  if (registeredSchema) {
    const parsed = registeredSchema.safeParse(payload);
    if (!parsed.success) {
      const error = new DashboardApiError(
        \`Dashboard response contract failed for \${operationId} (\${response.status})\`,
        response.status,
        'DASHBOARD_RESPONSE_CONTRACT_FAILED',
        { issues: parsed.error.issues, payload },
      );
      errorObserver?.(error);
      throw error;
    }
    payload = parsed.data;
    if (explicitlyRegistered) return parsed.data as GeneratedDashboardOutput<T>;
  }

  const record = payload && typeof payload === 'object' ? payload as Record<string, unknown> : undefined;
  const detail = typeof record?.error === 'string' ? record.error : raw;
  const prefix = \`\${response.status}\${response.statusText ? \` \${response.statusText}\` : ''}\`;
  const error = new DashboardApiError(
    \`\${prefix}\${detail ? \`: \${detail}\` : ''}\`,
    response.status,
    typeof record?.code === 'string' ? record.code : undefined,
    payload,
  );
  errorObserver?.(error);
  throw error;
}

${wrappers}
`;

function verifyOrWrite(path: string, content: string): void {
  if (checkOnly) {
    let current = '';
    try { current = readFileSync(path, 'utf8'); } catch { /* missing is drift */ }
    if (current !== content) {
      console.error(`Dashboard API generated artifact is stale: ${path}`);
      process.exitCode = 1;
    }
    return;
  }
  writeFileSync(path, content);
}

verifyOrWrite(manifestPath, manifest);
verifyOrWrite(generatedClientPath, generatedClient);
if (!checkOnly) console.log(`Generated ${operationIds.length} dashboard operations (${schemaHash}).`);
