// ============================================================
// GitLab CI OIDC parser.
//
// Reads a `.gitlab-ci.yml` (raw YAML or pre-parsed JSON object) and
// extracts every job that declares `id_tokens:`. Each such job
// becomes an idp_application; the `aud:` field becomes the audience.
//
// Optional context: `parser_context.gitlab_project` provides the
// project path (acme/webapp). Without it we fall back to a synthetic
// "unknown" project id.
// ============================================================

import type { EdgeType, Finding, NodeProperties, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { idpApplicationId, idpId } from '../parser-utils.js';

const GITLAB_ISSUER = 'https://gitlab.com';

interface IdTokenSpec {
  aud?: string | string[];
}

interface GitlabJob {
  id_tokens?: Record<string, IdTokenSpec>;
  rules?: unknown[];
  script?: unknown;
  /** The job is keyed by name in the parent map; we pass it through here. */
  __name?: string;
}

interface GitlabCiBundle {
  project?: string;
  jobs: Record<string, GitlabJob>;
}

function tryParseJson(output: string, context?: ParseContext): GitlabCiBundle | null {
  try {
    const obj = JSON.parse(output) as Record<string, unknown>;
    if (typeof obj !== 'object' || !obj) return null;
    const bundle: GitlabCiBundle = {
      project: ((obj.project ?? (context as { gitlab_project?: string } | undefined)?.gitlab_project) as string | undefined),
      jobs: {},
    };
    for (const [k, v] of Object.entries(obj)) {
      if (k === 'project') continue;
      if (typeof v !== 'object' || v === null) continue;
      const job = v as GitlabJob;
      if (job.id_tokens && typeof job.id_tokens === 'object') {
        bundle.jobs[k] = job;
      }
    }
    return Object.keys(bundle.jobs).length > 0 || bundle.project ? bundle : null;
  } catch {
    return null;
  }
}

/** Tiny YAML-ish extractor — handles the subset GitLab CI uses for id_tokens.
 *  We deliberately don't pull in a full YAML dep; the jobs we care about
 *  follow a predictable shape: `^name:\n  id_tokens:\n    NAME:\n      aud: <value>`.
 */
function tryParseYaml(output: string, context?: ParseContext): GitlabCiBundle | null {
  if (!/id_tokens\s*:/.test(output)) return null;
  const lines = output.split('\n');
  const bundle: GitlabCiBundle = {
    project: (context as { gitlab_project?: string } | undefined)?.gitlab_project,
    jobs: {},
  };
  let currentJob: string | undefined;
  let inIdTokens = false;
  let currentTokenAud: string | undefined;
  let pendingTokenName: string | undefined;
  for (const raw of lines) {
    const line = raw.replace(/\r$/, '');
    if (/^[A-Za-z0-9_-]+:\s*(?:#.*)?$/.test(line)) {
      // Top-level job header (zero indentation).
      currentJob = line.replace(/:\s*(?:#.*)?$/, '');
      inIdTokens = false;
      pendingTokenName = undefined;
      continue;
    }
    if (currentJob && /^\s+id_tokens\s*:/.test(line)) {
      inIdTokens = true;
      bundle.jobs[currentJob] ??= {};
      bundle.jobs[currentJob].id_tokens ??= {};
      continue;
    }
    if (inIdTokens) {
      // Sibling key (2-space indent, same level as `id_tokens:`) ends the
      // block — `script:`, `rules:`, etc. are job siblings, not children
      // of id_tokens.
      if (/^\s{2}[A-Za-z0-9_-]+\s*:/.test(line)) {
        inIdTokens = false;
        pendingTokenName = undefined;
        continue;
      }
      // Token name lives at 4-space indent (children of id_tokens:).
      const tokenName = line.match(/^\s{4}([A-Za-z0-9_-]+)\s*:\s*$/);
      if (tokenName) {
        pendingTokenName = tokenName[1];
        bundle.jobs[currentJob!].id_tokens![pendingTokenName] = {};
        continue;
      }
      // aud: lives at 6-space indent (children of token name).
      const audMatch = line.match(/^\s{6,}aud\s*:\s*['"]?([^'"\n]+)['"]?/);
      if (audMatch && pendingTokenName) {
        currentTokenAud = audMatch[1].trim();
        bundle.jobs[currentJob!].id_tokens![pendingTokenName].aud = currentTokenAud;
        continue;
      }
    }
  }
  return Object.keys(bundle.jobs).length > 0 ? bundle : null;
}

function audOf(spec: IdTokenSpec): string | undefined {
  if (!spec.aud) return undefined;
  return Array.isArray(spec.aud) ? spec.aud[0] : spec.aud;
}

export function parseGitlabCiOidc(output: string, agentId: string = 'gitlab-ci-oidc-parser', context?: ParseContext): Finding {
  const nodes: NodeProperties[] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const now = new Date().toISOString();

  const bundle = tryParseJson(output, context) ?? tryParseYaml(output, context);
  if (!bundle) {
    return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
  }

  const project = bundle.project ?? 'unknown-project';
  const idpNodeId = idpId('ci_gitlab', project);
  if (!seenNodes.has(idpNodeId)) {
    nodes.push({
      id: idpNodeId,
      type: 'idp',
      label: `gitlab-ci:${project}`,
      idp_kind: 'ci_gitlab',
      tenant_id: project,
      issuer_url: GITLAB_ISSUER,
      discovered_via: agentId,
      discovered_at: now,
      confidence: 1.0,
    });
    seenNodes.add(idpNodeId);
  }

  for (const [jobName, job] of Object.entries(bundle.jobs)) {
    if (!job.id_tokens) continue;
    for (const [tokenName, spec] of Object.entries(job.id_tokens)) {
      const aud = audOf(spec);
      const appKey = `${project}:${jobName}:${tokenName}`;
      const appNodeId = idpApplicationId('ci_gitlab', project, appKey);
      if (seenNodes.has(appNodeId)) continue;
      nodes.push({
        id: appNodeId,
        type: 'idp_application',
        label: `gitlab-ci:${project}/${jobName}`,
        client_id: appKey,
        app_name: `${jobName} (${tokenName})`,
        audience: aud,
        idp_id: idpNodeId,
        discovered_at: now,
        confidence: 0.9,
      });
      seenNodes.add(appNodeId);
      edges.push({
        source: appNodeId,
        target: idpNodeId,
        properties: { type: 'TRUSTS' as EdgeType, confidence: 1.0, discovered_at: now, discovered_by: agentId },
      });
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
