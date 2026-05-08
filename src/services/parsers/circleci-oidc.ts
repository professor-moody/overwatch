// ============================================================
// CircleCI OIDC parser.
//
// CircleCI emits OIDC tokens via context-bound env vars
// (`CIRCLE_OIDC_TOKEN`, `CIRCLE_OIDC_TOKEN_V2`) and the canonical
// indication that a workflow uses OIDC is the presence of an
// `OIDC_TOKEN_FILE` env in `.circleci/config.yml`.
//
// Less structured than GitLab/GHA — Circle's OIDC subject claim is
// dynamic per-workflow (`org/<org-id>/project/<project-id>/...`), so
// we emit one idp_application per project/job pair we observe and
// leave audience to operator override via parser_context.
// ============================================================

import type { EdgeType, Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { idpApplicationId, idpId } from '../parser-utils.js';

interface CircleBundle {
  org_id?: string;
  project_id?: string;
  audience?: string;
  jobs: string[];
}

function tryParseJson(output: string, context?: ParseContext): CircleBundle | null {
  try {
    const obj = JSON.parse(output) as Record<string, unknown>;
    if (typeof obj !== 'object' || !obj) return null;
    const bundle: CircleBundle = {
      org_id: (obj.org_id as string | undefined) ?? (context as { circleci_org_id?: string } | undefined)?.circleci_org_id,
      project_id: (obj.project_id as string | undefined) ?? (context as { circleci_project_id?: string } | undefined)?.circleci_project_id,
      audience: obj.audience as string | undefined,
      jobs: [],
    };
    const ws = (obj.workflows ?? {}) as Record<string, unknown>;
    for (const [, wfval] of Object.entries(ws)) {
      const jobs = (wfval as { jobs?: Array<unknown> }).jobs ?? [];
      for (const j of jobs) {
        if (typeof j === 'string') bundle.jobs.push(j);
        else if (j && typeof j === 'object') {
          for (const name of Object.keys(j as Record<string, unknown>)) bundle.jobs.push(name);
        }
      }
    }
    return bundle.jobs.length > 0 || bundle.org_id || bundle.project_id ? bundle : null;
  } catch {
    return null;
  }
}

function tryParseYaml(output: string, context?: ParseContext): CircleBundle | null {
  if (!/OIDC_TOKEN_FILE|circleci\/oidc|CIRCLE_OIDC_TOKEN/i.test(output)) return null;
  const ctx = context as { circleci_org_id?: string; circleci_project_id?: string } | undefined;
  const bundle: CircleBundle = {
    org_id: ctx?.circleci_org_id,
    project_id: ctx?.circleci_project_id,
    jobs: [],
  };
  const lines = output.split('\n');
  let inWorkflows = false;
  let inJobsList = false;
  for (const line of lines) {
    if (/^workflows\s*:/.test(line)) { inWorkflows = true; continue; }
    if (inWorkflows && /^\S/.test(line) && !/^workflows\s*:/.test(line)) inWorkflows = false;
    if (inWorkflows && /^\s+jobs\s*:/.test(line)) { inJobsList = true; continue; }
    if (inJobsList) {
      // Either `- job_name` or `- job_name:`
      const m = line.match(/^\s+-\s+([A-Za-z0-9_-]+)\s*:?\s*$/);
      if (m) {
        bundle.jobs.push(m[1]);
        continue;
      }
      // De-indent to a non-list entry → close the list.
      if (/^\s*[A-Za-z0-9_-]+\s*:/.test(line) && !/^\s+-\s+/.test(line)) inJobsList = false;
    }
  }
  return bundle.jobs.length > 0 || bundle.org_id || bundle.project_id ? bundle : null;
}

export function parseCircleciOidc(output: string, agentId: string = 'circleci-oidc-parser', context?: ParseContext): Finding {
  const nodes: NodeProperties[] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  const bundle = tryParseJson(output, context) ?? tryParseYaml(output, context);
  if (!bundle) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  const orgId = bundle.org_id ?? 'unknown-org';
  const projectId = bundle.project_id ?? 'unknown-project';
  const tenantKey = `${orgId}/${projectId}`;
  const idpNodeId = idpId('ci_circleci', tenantKey);
  if (!seenNodes.has(idpNodeId)) {
    nodes.push({
      id: idpNodeId,
      type: 'idp',
      label: `circleci:${tenantKey}`,
      idp_kind: 'ci_circleci',
      tenant_id: tenantKey,
      issuer_url: `https://oidc.circleci.com/org/${orgId}`,
      discovered_via: agentId,
      discovered_at: now,
      confidence: 1.0,
    });
    seenNodes.add(idpNodeId);
  }

  // No jobs found but the file referenced OIDC — emit a single
  // placeholder idp_application so the org-level node has a child.
  const jobs = bundle.jobs.length > 0 ? bundle.jobs : ['<unspecified>'];
  for (const jobName of jobs) {
    const appKey = `${tenantKey}:${jobName}`;
    const appNodeId = idpApplicationId('ci_circleci', tenantKey, jobName);
    if (seenNodes.has(appNodeId)) continue;
    nodes.push({
      id: appNodeId,
      type: 'idp_application',
      label: `circleci:${jobName}`,
      client_id: appKey,
      app_name: jobName,
      audience: bundle.audience,
      idp_id: idpNodeId,
      discovered_at: now,
      confidence: 0.85,
    });
    seenNodes.add(appNodeId);
    edges.push({
      source: appNodeId,
      target: idpNodeId,
      properties: { type: 'TRUSTS' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId },
    });
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
