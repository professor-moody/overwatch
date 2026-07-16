// ============================================================
// Overwatch — register_mock_service tool
// Operator-controlled decoy / listener / relay infrastructure
// (fake LDAP, Responder, ntlmrelayx, redirector, reverse-shell catcher,
// HTTP/SMB capture endpoints) becomes a first-class graph node so
// captured credentials, attack chains, and retrospectives can
// attribute correctly.
// ============================================================

import { z } from 'zod';
import { createHash } from 'node:crypto';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import { withErrorBoundary } from './error-boundary.js';

const PURPOSE_VALUES = [
  'fake_ldap',
  'responder',
  'ntlmrelayx',
  'redirector',
  'reverse_shell_catcher',
  'http_capture',
  'smb_capture',
  'other',
] as const;

export type MockServicePurpose = typeof PURPOSE_VALUES[number];

/** Stable id derived from (purpose, bind_host, bind_port, owner). The
 * owner key falls back to a fixed sentinel when no agent is associated
 * so unattributed listeners still dedupe across calls. */
export function mockServiceId(
  purpose: MockServicePurpose,
  bindHost: string,
  bindPort: number,
  owner: string | undefined,
): string {
  const ownerKey = owner && owner.length > 0 ? owner : 'unattributed';
  const h = createHash('sha1')
    .update(`${purpose}|${bindHost}|${bindPort}|${ownerKey}`)
    .digest('hex')
    .slice(0, 12);
  return `mock-svc-${purpose}-${h}`;
}

export interface RegisterMockServiceOpts {
  purpose: MockServicePurpose;
  protocol: string;
  bind_host: string;
  bind_port: number;
  opsec_loud?: boolean;
  notes?: string;
  bound_session_id?: string;
  bound_process_id?: number;
  target_node?: string;
  agent_id?: string;
  action_id?: string;
  frontier_item_id?: string;
}

export interface RegisterMockServiceResult {
  mock_service_id: string;
  is_new: boolean;
  event_id: string;
  operator_edge: { added: boolean; edge_id?: string };
  runs_on_edge: { added: boolean; edge_id?: string };
}

/** Programmatic core that the MCP tool wraps; also called from
 * open_session listen-mode integration so the registration logic stays
 * in one place. */
export function registerMockServiceCore(
  engine: GraphEngine,
  opts: RegisterMockServiceOpts,
): RegisterMockServiceResult {
  return engine.runAtomicGraphCommand(
    'register or refresh mock service',
    opts.action_id,
    () => registerMockServiceMutation(engine, opts),
  );
}

function registerMockServiceMutation(
  engine: GraphEngine,
  opts: RegisterMockServiceOpts,
): RegisterMockServiceResult {
  const {
    purpose, protocol, bind_host, bind_port, opsec_loud, notes,
    bound_session_id, bound_process_id, target_node,
    agent_id, action_id, frontier_item_id,
  } = opts;

  const id = mockServiceId(purpose, bind_host, bind_port, agent_id);
  const nowIso = new Date().toISOString();
  const defaultLoud = opsec_loud ?? (
    purpose === 'responder' ||
    purpose === 'ntlmrelayx' ||
    purpose === 'fake_ldap' ||
    purpose === 'smb_capture'
  );

  const existing = engine.getNode(id);
  const isNew = existing === null;

  engine.addNode({
    id,
    type: 'mock_service' as const,
    label: `${purpose}://${bind_host}:${bind_port}`,
    confidence: 1,
    discovered_by: agent_id,
    discovered_at: existing?.discovered_at ?? nowIso,
    first_seen_at: existing?.first_seen_at ?? nowIso,
    last_seen_at: nowIso,
    mock_purpose: purpose,
    protocol,
    bind_host,
    bind_port,
    opsec_loud: defaultLoud,
    bound_session_id: bound_session_id ?? existing?.bound_session_id,
    bound_process_id: bound_process_id ?? existing?.bound_process_id,
    started_at: existing?.started_at ?? nowIso,
    notes: notes ?? existing?.notes,
  });

  // OPERATED_BY only when the agent corresponds to an existing user node
  // (we don't auto-create user nodes for sub-agent ids).
  const operator_edge: { added: boolean; edge_id?: string } = { added: false };
  if (agent_id) {
    const opNode = engine.getNode(agent_id);
    if (opNode && opNode.type === 'user') {
      const r = engine.addEdge(id, agent_id, {
        type: 'OPERATED_BY',
        confidence: 1,
        discovered_at: nowIso,
        discovered_by: agent_id,
      });
      operator_edge.added = r.isNew;
      operator_edge.edge_id = r.id;
    }
  }

  const runs_on_edge: { added: boolean; edge_id?: string } = { added: false };
  if (target_node) {
    const host = engine.getNode(target_node);
    if (host && host.type === 'host') {
      const r = engine.addEdge(id, target_node, {
        type: 'RUNS_ON',
        confidence: 1,
        discovered_at: nowIso,
        discovered_by: agent_id,
      });
      runs_on_edge.added = r.isNew;
      runs_on_edge.edge_id = r.id;
    }
  }

  const event = engine.logActionEvent({
    description: isNew
      ? `Mock service registered: ${purpose} on ${bind_host}:${bind_port}`
      : `Mock service refreshed: ${purpose} on ${bind_host}:${bind_port}`,
    event_type: isNew ? 'mock_service_registered' : 'mock_service_refreshed',
    category: 'system',
    provenance: 'operator',
    agent_id,
    action_id,
    frontier_item_id,
    details: {
      mock_service_id: id,
      purpose,
      protocol,
      bind_host,
      bind_port,
      opsec_loud: defaultLoud,
      bound_session_id,
      bound_process_id,
      target_node,
    },
  });

  return {
    mock_service_id: id,
    is_new: isNew,
    event_id: event.event_id,
    operator_edge,
    runs_on_edge,
  };
}

export function registerOperatorInfraTools(server: McpServer, engine: GraphEngine): void {
  server.registerTool(
    'register_mock_service',
    {
      title: 'Register Mock Service (Operator Infrastructure)',
      description: `Register an operator-controlled decoy / listener / relay as a first-class node in the engagement graph.

Use this whenever you spin up infrastructure that will RECEIVE incoming
connections from the target environment — fake LDAP, Responder,
ntlmrelayx, socat redirector, reverse-shell catcher, HTTP/SMB capture
endpoint, etc. Tying the listener to the graph lets the BAITED
inference rule attribute captured credentials back to the listener
that caught them, and lets retrospectives reconstruct which attacks
relied on operator infrastructure.

Idempotent on (purpose, bind_host, bind_port, owner). Calling again
with the same key updates timestamps + bound_session_id but does not
duplicate the node.

If \`bound_session_id\` is supplied, the session's
\`capabilities.serves_mock_service_id\` is updated so dashboards can
pivot session ↔ listener bidirectionally.`,
      inputSchema: {
        purpose: z.enum(PURPOSE_VALUES).describe('What this listener is for; drives BAITED inference defaults.'),
        protocol: z.string().min(1).describe('Wire protocol (ldap, smb, http, https, tcp, udp, raw, …).'),
        bind_host: z.string().min(1).describe("Address the listener is bound to. Usually '127.0.0.1' or the attacker box IP."),
        bind_port: z.number().int().min(1).max(65535),
        opsec_loud: z.boolean().optional().describe('True if this listener is loud (Responder broadcasts, etc.). Defaults true for responder/ntlmrelayx/fake_ldap/smb_capture; false otherwise.'),
        notes: z.string().optional(),
        bound_session_id: z.string().optional().describe('Session id of the long-lived process running the listener.'),
        bound_process_id: z.number().int().optional().describe('OS pid of the listener process.'),
        target_node: z.string().optional().describe('Optional host node id for RUNS_ON edge (defaults to leaving it unattached when host unknown).'),
        agent_id: z.string().optional().describe('Operator agent id; used for OPERATED_BY attribution and dedupe.'),
        action_id: z.string().optional(),
        frontier_item_id: z.string().optional(),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    withErrorBoundary('register_mock_service', async (args) => {
      const result = registerMockServiceCore(engine, args);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            registered: true,
            new: result.is_new,
            mock_service_id: result.mock_service_id,
            event_id: result.event_id,
            operator_edge: result.operator_edge,
            runs_on_edge: result.runs_on_edge,
          }, null, 2),
        }],
      };
    }),
  );
}
