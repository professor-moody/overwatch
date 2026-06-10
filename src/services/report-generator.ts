// ============================================================
// Overwatch — Pentest Report Generator
// Produces client-deliverable reports with per-finding sections,
// attack narrative, evidence chains, and auto-remediation.
// ============================================================

import type {
  EngagementConfig, NodeProperties,
  ExportedGraph, ExportedGraphEdge,
  AgentTask, InferenceRuleSuggestion, SkillGapReport,
  ContextImprovementReport, TraceQualityReport,
} from '../types.js';
import type { ActivityLogEntry } from './engine-context.js';
import { getCredentialDisplayKind, isCredentialUsableForAuth } from './credential-utils.js';
import { buildCredentialChains } from './retrospective.js';
import { classifyFinding, computeGapAnalysis } from './finding-classifier.js';
import type { FindingClassification } from './finding-classifier.js';
import { estimateCvssFromContext, vectorToString } from './cvss-calculator.js';
import {
  displayFindingCategory,
  displayFindingImpact,
  displayFindingRemediation,
  displayFindingSummary,
  displayFindingShortTitle,
  displayFindingTitle,
  presentFinding,
  type FindingPresentation,
} from './finding-presentation.js';
import {
  buildActionPlan,
  buildExecutiveSummary,
  type ReportActionPlanItem,
  type ReportExecutiveSummary,
} from './report-deliverable.js';
import type { TrustSignalDto } from './trust-signal-summary.js';
import { createHash } from 'crypto';

// ============================================================
// Types
// ============================================================

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ReportProfile = 'operator' | 'client';
export type EvidenceStyle = 'proof_cards' | 'appendix' | 'full_inline';

export interface ReportFinding {
  id: string;
  title: string;
  severity: FindingSeverity;
  category: 'compromised_host' | 'credential' | 'vulnerability' | 'access_path' | 'cloud_exposure' | 'webapp';
  /**
   * Phase 3 (enterprise): which engagement tier this finding lives in.
   *  - `network`     — on-prem hosts, services, AD attack paths.
   *  - `app`         — webapp / api_endpoint findings.
   *  - `cloud`       — cloud_resource / cloud_identity / cloud_policy.
   *  - `identity`    — idp / idp_application / idp_principal.
   *  - `cross_tier`  — finding spans ≥2 of the above (e.g. SSRF→IMDS).
   * Inferred from the affected node types when not set explicitly.
   */
  tier?: 'network' | 'app' | 'cloud' | 'identity' | 'cross_tier';
  description: string;
  affected_assets: string[];
  evidence: EvidenceChain[];
  proof_cards?: EvidenceProofCard[];
  presentation?: FindingPresentation;
  remediation: string;
  risk_score: number; // 0-10
  classification?: FindingClassification;
  cvss_vector?: string;
  cvss_score?: number;
  cvss_estimated?: boolean;
}

export interface EvidenceProofCard {
  id: string;
  appendix_ref: string;
  claim: string;
  proof: string;
  source_kind: 'direct_output' | 'parsed_result' | 'provenance' | 'activity';
  tool?: string;
  technique?: string;
  command?: string;
  timestamp?: string;
  action_id?: string;
  evidence_id?: string;
  content_hash?: string;
  evidence_bytes?: number;
  evidence_type?: string;
  filename?: string;
  parsed_summary?: string;
  raw_preview?: string;
  raw_preview_redacted?: boolean;
}

export interface EvidenceAppendixEntry {
  id: string;
  title: string;
  claim: string;
  source_kind: EvidenceProofCard['source_kind'];
  evidence_id?: string;
  content_hash?: string;
  action_id?: string;
  tool?: string;
  command?: string;
  timestamp?: string;
  evidence_type?: string;
  filename?: string;
  size_bytes?: number;
  redaction_mode: ReportProfile;
  finding_ids: string[];
  finding_titles: string[];
  raw_preview?: string;
  raw_preview_redacted?: boolean;
}

export interface EvidenceChain {
  claim: string;
  action_id?: string;
  tool?: string;
  technique?: string;
  command?: string;
  timestamp?: string;
  source_nodes: string[];
  target_nodes: string[];
  linked_findings?: string[];
  evidence_type?: string;
  evidence_content?: string;
  evidence_filename?: string;
  raw_output?: string;
  source_event_type?: string;
  result_classification?: string;
  /** Evidence-store IDs for full-fidelity stdout/stderr capture from
   * the terminal action that produced this finding. Reports cite these
   * IDs and inline a head/tail snippet of the content. */
  stdout_evidence_id?: string;
  stderr_evidence_id?: string;
  stdout_content_hash?: string;
  stderr_content_hash?: string;
  stdout_bytes?: number;
  stderr_bytes?: number;
  /** Truncation / capture diagnostics from the streamed evidence sink. */
  stdout_truncated?: boolean;
  stdout_dropped_bytes?: number;
  stdout_total_bytes?: number;
  evidence_capture_error?: string;
  /** Set when the parser had to fall back to bounded buffer output. */
  partial?: boolean;
  partial_reason?: string;
  /** Optional inline preview of stdout (head/tail with elision marker). */
  stdout_preview?: string;
}

export interface NarrativePhase {
  name: string;
  start_time?: string;
  end_time?: string;
  paragraphs: string[];
}

/**
 * One step in a reportable attack path. Carries the node we landed on
 * and the edge we traversed to reach the next step (omitted on the
 * terminal node). Consumed by `renderAttackPathsSection`.
 */
export interface AttackPathStep {
  node_id: string;
  label: string;
  type: string;
  edge_to_next?: {
    type: string;
    confidence: number;
    inferred: boolean;
    rule?: string;
  };
}

export interface AttackPath {
  /** When the path was found by walking from start nodes to a specific objective. */
  objective_id?: string;
  objective_label?: string;
  steps: AttackPathStep[];
  total_confidence: number;
  total_opsec_noise: number;
  /** Whether any hop is inferred-only (no confirmed evidence). High-value signal for the report. */
  contains_inferred: boolean;
}

export interface ReportOptions {
  include_evidence?: boolean;
  include_narrative?: boolean;
  include_retrospective?: boolean;
  include_compliance?: boolean;
  include_attack_navigator?: boolean;
  include_gap_analysis?: boolean;
  max_timeline_entries?: number;
  /** Lazy fetcher for full evidence-store content. When provided,
   * evidence chains will include a head/tail preview of stdout for
   * findings whose action recorded a `stdout_evidence_id`. */
  evidence_loader?: (evidenceId: string) => string | null;
  evidence_record_loader?: (evidenceId: string) => {
    evidence_id: string;
    content_hash?: string;
    evidence_type?: string;
    filename?: string;
    content_length?: number;
    raw_output_length?: number;
  } | undefined;
  /** Bytes of head + tail to show in the inline preview (default 8 KiB). */
  evidence_preview_bytes?: number;
  report_profile?: ReportProfile;
  evidence_style?: EvidenceStyle;
  trust_signals?: TrustSignalDto[];
}

export interface ReportInput {
  config: EngagementConfig;
  graph: ExportedGraph;
  history: ActivityLogEntry[];
  agents: AgentTask[];
  retrospective?: Partial<{
    inference_suggestions: InferenceRuleSuggestion[];
    skill_gaps: SkillGapReport;
    context_improvements: ContextImprovementReport;
    trace_quality: TraceQualityReport;
  }>;
  /** Pre-computed attack paths to render in the Attack Paths section.
   * Caller (typically the generate_report MCP tool) walks objectives via
   * `engine.findPathsToObjective` and decorates with edge metadata using
   * `buildAttackPaths`. Empty/undefined → section is omitted. */
  attack_paths?: AttackPath[];
}

// ============================================================
// Constants
// ============================================================

// ============================================================
// Per-Finding Sections
// ============================================================

type EvidenceBuildOptions = {
  evidenceLoader?: (id: string) => string | null;
  evidenceRecordLoader?: ReportOptions['evidence_record_loader'];
  previewBytes?: number;
};

export function buildFindings(graph: ExportedGraph, history: ActivityLogEntry[], config: EngagementConfig, opts?: EvidenceBuildOptions): ReportFinding[] {
  const findings: ReportFinding[] = [];
  const nodeMap = new Map<string, NodeProperties>();
  for (const n of graph.nodes) nodeMap.set(n.id, n.properties);

  const compromisedHostIds = new Set<string>();

  // 1. Compromised hosts
  for (const n of graph.nodes) {
    if (n.properties.type !== 'host') continue;
    const sessionEdges = graph.edges.filter(e =>
      e.target === n.id && e.properties.type === 'HAS_SESSION' && e.properties.confidence >= 0.9
      // P2.2: require explicit session_live === true for live-compromise
      // counting. Imported BloodHound sessions and historical edges without
      // an affirmative live flag no longer satisfy "compromised host" — they
      // remain in the graph (and other surfaces can render them) but the
      // compromise count refuses to over-claim. Aligns with
      // objective-manager.ts which already required === true.
      && e.properties.session_live === true
    );
    const exploitEdges = graph.edges.filter(e =>
      e.target === n.id && e.properties.type === 'EXPLOITS' && e.properties.confidence >= 0.9 &&
      (e.properties.tested === true || !e.properties.inferred_by_rule)
    );
    if (sessionEdges.length === 0 && exploitEdges.length === 0) continue;

    compromisedHostIds.add(n.id);
    const adminEdges = graph.edges.filter(e =>
      e.target === n.id && e.properties.type === 'ADMIN_TO' && e.properties.confidence >= 0.9
    );
    const accessEdges = [...sessionEdges, ...exploitEdges, ...adminEdges];

    const accessMethods = accessEdges.map(e => {
      const src = nodeMap.get(e.source);
      return describeAccessMethod(e, src);
    });
    const evidence = buildEvidenceChainsForNode(n.id, graph, history, opts);
    const hopsToObj = computeHopsToObjective(n.id, graph, config);

    findings.push({
      id: `finding-host-${n.id}`,
      title: `Compromised Host: ${n.properties.label || n.properties.ip || n.id}`,
      severity: adminEdges.length > 0 ? 'critical' : 'high',
      category: 'compromised_host',
      description: `Host ${n.properties.label || n.id} was confirmed accessible through ${accessMethods.join('; ')}. ` +
        `OS: ${n.properties.os || 'unknown'}. ` +
        (n.properties.domain_joined ? 'Domain-joined.' : ''),
      affected_assets: [n.properties.label || n.id],
      evidence,
      remediation: generateHostRemediation(n.properties, accessEdges, nodeMap),
      risk_score: computeHostRiskScore(accessEdges, hopsToObj),
    });
  }

  // 1b. Administrative access paths that are not confirmed compromise
  for (const e of graph.edges) {
    if (e.properties.type !== 'ADMIN_TO' || e.properties.confidence < 0.9) continue;
    const host = nodeMap.get(e.target);
    if (host?.type !== 'host' || compromisedHostIds.has(e.target)) continue;
    const src = nodeMap.get(e.source);
    const evidence = buildEvidenceChainsForNode(e.target, graph, history, opts);
    findings.push({
      id: `finding-access-${e.source}-${e.target}`,
      title: `Administrative Access Path: ${host.label || host.ip || e.target}`,
      severity: 'high',
      category: 'access_path',
      description: `${src?.label || e.source} has administrative rights to ${host.label || e.target}, but no confirmed session or code execution evidence is recorded for this host.`,
      affected_assets: [host.label || e.target, src?.label || e.source],
      evidence,
      remediation: generateAccessPathRemediation(host, src),
      risk_score: 7.0,
    });
  }

  // 2. Credentials obtained — bucketed by cred_material_kind so a real
  // engagement with hundreds of captured creds doesn't produce hundreds
  // of identical-looking findings. Each kind becomes one finding whose
  // severity is the max of its members' severities; individual creds
  // with confirmed reachability surface in the description.
  //
  // Per-cred severity is computed from edges in the graph:
  //   - VALID_ON, VALID_FOR_APP, ASSUMES_ROLE (confirmed) → high
  //     (or critical if `privileged: true`).
  //   - VALID_FOR_IDP_PRINCIPAL, OWNS_CRED (federated identity confirmed)
  //     → high.
  //   - POTENTIAL_AUTH only (untested candidate) → medium.
  //   - No auth-related outbound edges → medium (the floor — captured
  //     credentials are dangerous in principle even without a confirmed
  //     path; operators chose this floor over 'low' in plan B.5).
  const SEVERITY_RANK: Record<FindingSeverity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const maxSeverity = (a: FindingSeverity, b: FindingSeverity): FindingSeverity =>
    SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;

  function classifyCred(node: NodeProperties): { severity: FindingSeverity; reachable: boolean; risk_score: number } {
    const confirmedAuthEdges = graph.edges.filter(e =>
      e.source === node.id && (
        e.properties.type === 'VALID_ON' ||
        e.properties.type === 'VALID_FOR_APP' ||
        e.properties.type === 'VALID_FOR_IDP_PRINCIPAL' ||
        e.properties.type === 'ASSUMES_ROLE'
      ) && (e.properties.confidence ?? 0) >= 0.9
    );
    const candidateEdges = graph.edges.filter(e =>
      e.source === node.id && e.properties.type === 'POTENTIAL_AUTH'
    );
    if (node.privileged && confirmedAuthEdges.length > 0) {
      return { severity: 'critical', reachable: true, risk_score: 9.5 };
    }
    if (confirmedAuthEdges.length > 0) {
      return { severity: 'high', reachable: true, risk_score: 7.5 };
    }
    if (candidateEdges.length > 0) {
      return { severity: 'medium', reachable: false, risk_score: 5.0 };
    }
    return { severity: 'medium', reachable: false, risk_score: 4.0 };
  }

  // First pass: collect + classify each usable credential; group by kind.
  type CredEntry = {
    node: NodeProperties;
    severity: FindingSeverity;
    reachable: boolean;
    risk_score: number;
    confirmed_targets: string[];
    candidate_targets: string[];
  };
  const buckets = new Map<string, CredEntry[]>();
  for (const n of graph.nodes) {
    if (n.properties.type !== 'credential') continue;
    if (n.properties.confidence < 0.9 || !isCredentialUsableForAuth(n.properties)) continue;
    const cls = classifyCred(n.properties);
    const confirmedTargets = graph.edges
      .filter(e => e.source === n.id && (
        e.properties.type === 'VALID_ON' ||
        e.properties.type === 'VALID_FOR_APP' ||
        e.properties.type === 'ASSUMES_ROLE'
      ) && (e.properties.confidence ?? 0) >= 0.9)
      .map(e => nodeMap.get(e.target)?.label || e.target);
    const candidateTargets = graph.edges
      .filter(e => e.source === n.id && e.properties.type === 'POTENTIAL_AUTH')
      .map(e => nodeMap.get(e.target)?.label || e.target);
    const kind = (n.properties.cred_material_kind as string | undefined) ?? (n.properties.cred_type as string | undefined) ?? 'credential';
    const list = buckets.get(kind) ?? [];
    list.push({ node: n.properties, ...cls, confirmed_targets: confirmedTargets, candidate_targets: candidateTargets });
    buckets.set(kind, list);
  }

  // Second pass: emit one finding per kind bucket.
  for (const [kind, entries] of buckets.entries()) {
    if (entries.length === 0) continue;
    let bucketSeverity: FindingSeverity = 'medium';
    let maxRiskScore = 0;
    const reachableEntries: CredEntry[] = [];
    for (const e of entries) {
      bucketSeverity = maxSeverity(bucketSeverity, e.severity);
      if (e.risk_score > maxRiskScore) maxRiskScore = e.risk_score;
      if (e.reachable) reachableEntries.push(e);
    }
    const total = entries.length;
    const reachableCount = reachableEntries.length;
    const kindLabel = entries[0].node.cred_material_kind
      ? getCredentialDisplayKind(entries[0].node)
      : kind;

    // Title summarizes total + how many have a confirmed reachable target.
    const title = total === 1
      ? `Credential Obtained: ${entries[0].node.cred_user || entries[0].node.label || entries[0].node.id} (${kindLabel})`
      : `${total} ${kindLabel} credentials captured` +
        (reachableCount > 0 ? ` (${reachableCount} with confirmed reachability)` : '');

    // Description: first list the reachable creds (the dangerous ones),
    // then summarize the bucket as a whole.
    const lines: string[] = [];
    if (reachableEntries.length > 0) {
      lines.push(`**${reachableEntries.length} with confirmed authentication path:**`);
      for (const e of reachableEntries.slice(0, 10)) {
        const user = e.node.cred_user || e.node.label || e.node.id;
        const targets = e.confirmed_targets.slice(0, 3).join(', ');
        lines.push(`- ${user}${e.confirmed_targets.length > 0 ? ` → ${targets}${e.confirmed_targets.length > 3 ? `, +${e.confirmed_targets.length - 3} more` : ''}` : ''}`);
      }
      if (reachableEntries.length > 10) lines.push(`- +${reachableEntries.length - 10} more`);
    }
    const inventoryEntries = entries.filter(e => !e.reachable);
    if (inventoryEntries.length > 0) {
      lines.push(`**${inventoryEntries.length} captured without confirmed reachability:**`);
      for (const e of inventoryEntries.slice(0, 5)) {
        const user = e.node.cred_user || e.node.label || e.node.id;
        const candidates = e.candidate_targets.length > 0
          ? ` (${e.candidate_targets.length} candidate target${e.candidate_targets.length === 1 ? '' : 's'})`
          : '';
        lines.push(`- ${user}${candidates}`);
      }
      if (inventoryEntries.length > 5) lines.push(`- +${inventoryEntries.length - 5} more`);
    }

    // Affected assets: prefer the reachable creds first (operator wants
    // to see the dangerous ones at a glance), then fill with candidates.
    const reachableAssets = reachableEntries.map(e => e.node.cred_user || e.node.label || e.node.id);
    const inventoryAssets = inventoryEntries.map(e => e.node.cred_user || e.node.label || e.node.id);
    const affected_assets = [...reachableAssets, ...inventoryAssets].slice(0, 25);

    // Evidence: aggregate top-3 entries' chains so the report cites at
    // least the reachable proofs without exploding for huge buckets.
    const evidenceSampleEntries = [...reachableEntries.slice(0, 2), ...inventoryEntries.slice(0, 1)];
    const evidence = evidenceSampleEntries.flatMap(e =>
      buildEvidenceChainsForNode(e.node.id as string, graph, history, opts),
    );

    findings.push({
      id: `finding-creds-${kind.replace(/[^a-z0-9_]/gi, '-')}`,
      title,
      severity: bucketSeverity,
      category: 'credential',
      description: lines.length > 0 ? lines.join('\n') : `${total} ${kindLabel} credential(s) captured.`,
      affected_assets,
      evidence,
      remediation: generateCredentialRemediation(entries[0].node),
      risk_score: maxRiskScore,
    });
  }

  // 3. Vulnerabilities
  for (const n of graph.nodes) {
    if (n.properties.type !== 'vulnerability') continue;

    const affectedEdges = graph.edges.filter(e =>
      e.properties.type === 'VULNERABLE_TO' && e.target === n.id
    );
    const affectedAssets = affectedEdges.map(e => nodeMap.get(e.source)?.label || e.source);
    const exploitEdges = graph.edges.filter(e =>
      e.properties.type === 'EXPLOITS' && e.source === n.id
    );
    const evidence = buildEvidenceChainsForNode(n.id, graph, history, opts);

    findings.push({
      id: `finding-vuln-${n.id}`,
      title: `Vulnerability: ${n.properties.cve || n.properties.label || n.id}`,
      severity: cvssToSeverity(n.properties.cvss),
      category: 'vulnerability',
      description: `${n.properties.vuln_type || 'Vulnerability'}: ${n.properties.label || n.properties.cve || n.id}. ` +
        `CVSS: ${n.properties.cvss ?? 'N/A'}. ` +
        `Exploitable: ${n.properties.exploitable ? 'Yes' : 'Unknown'}. ` +
        `Exploit available: ${n.properties.exploit_available ? 'Yes' : 'No'}. ` +
        `Affects ${affectedAssets.length} asset(s): ${affectedAssets.slice(0, 5).join(', ')}.` +
        (exploitEdges.length > 0 ? ` Successfully exploited during engagement.` : ''),
      affected_assets: affectedAssets,
      evidence,
      remediation: generateVulnerabilityRemediation(n.properties, affectedAssets),
      risk_score: n.properties.cvss ?? (n.properties.exploitable ? 8.0 : 5.0),
    });
  }

  // 4. Cloud findings — IAM abuse, exposed resources, policy issues
  for (const n of graph.nodes) {
    if (n.properties.type !== 'cloud_identity' && n.properties.type !== 'cloud_resource') continue;

    const isIdentity = n.properties.type === 'cloud_identity';
    const isResource = n.properties.type === 'cloud_resource';

    if (isIdentity) {
      // IAM identities with dangerous policies or cross-account trust
      const policyEdges = graph.edges.filter(e =>
        e.source === n.id && e.properties.type === 'HAS_POLICY'
      );
      const assumedByEdges = graph.edges.filter(e =>
        e.target === n.id && e.properties.type === 'ASSUMES_ROLE'
      );
      if (policyEdges.length === 0 && assumedByEdges.length === 0) continue;

      const policyNames = policyEdges.map(e => nodeMap.get(e.target)?.label || e.target);
      const trustedBy = assumedByEdges.map(e => nodeMap.get(e.source)?.label || e.source);
      const evidence = buildEvidenceChainsForNode(n.id, graph, history, opts);

      const isAdmin = policyNames.some(p =>
        /administrator|admin|fullaccess|\*/i.test(p)
      );

      findings.push({
        id: `finding-cloud-${n.id}`,
        title: `Cloud Identity: ${n.properties.label || n.id}`,
        severity: isAdmin ? 'critical' : 'high',
        category: 'cloud_exposure',
        description: `${n.properties.principal_type || 'Identity'} ${n.properties.label || n.id}` +
          ` (${n.properties.provider || 'cloud'})` +
          (policyNames.length > 0 ? `. Policies: ${policyNames.slice(0, 5).join(', ')}` : '') +
          (trustedBy.length > 0 ? `. Trusted by: ${trustedBy.slice(0, 3).join(', ')}` : '') +
          '.',
        affected_assets: [n.properties.label || n.id, ...policyNames.slice(0, 5)],
        evidence,
        remediation: generateCloudIdentityRemediation(n.properties, policyNames),
        risk_score: isAdmin ? 9.0 : 6.5,
      });
    }

    if (isResource) {
      // Exposed or misconfigured cloud resources
      const isPublic = n.properties.public === true;
      const vulnEdges = graph.edges.filter(e =>
        e.source === n.id && e.properties.type === 'VULNERABLE_TO'
      );
      if (!isPublic && vulnEdges.length === 0) continue;

      const evidence = buildEvidenceChainsForNode(n.id, graph, history, opts);

      findings.push({
        id: `finding-cloud-${n.id}`,
        title: `Cloud Resource: ${n.properties.label || n.id}`,
        severity: isPublic && vulnEdges.length > 0 ? 'critical' : isPublic ? 'high' : 'medium',
        category: 'cloud_exposure',
        description: `${n.properties.resource_type || 'Resource'} ${n.properties.label || n.id}` +
          ` (${n.properties.provider || 'cloud'}, ${n.properties.region || 'unknown region'})` +
          (isPublic ? '. **Publicly accessible.**' : '') +
          (vulnEdges.length > 0 ? ` ${vulnEdges.length} misconfiguration(s) detected.` : '') +
          '.',
        affected_assets: [n.properties.label || n.id],
        evidence,
        remediation: generateCloudResourceRemediation(n.properties),
        risk_score: isPublic ? 7.5 : 5.0,
      });
    }
  }

  // 5. Webapp findings — compromised web applications with auth/technology context
  for (const n of graph.nodes) {
    if (n.properties.type !== 'webapp') continue;

    const vulnEdges = graph.edges.filter(e =>
      e.source === n.id && e.properties.type === 'VULNERABLE_TO'
    );
    const authEdges = graph.edges.filter(e =>
      e.properties.type === 'AUTHENTICATED_AS' && e.target === n.id
    );
    if (vulnEdges.length === 0 && authEdges.length === 0) continue;

    const vulnLabels = vulnEdges.map(e => nodeMap.get(e.target)?.label || e.target);
    const authSources = authEdges.map(e => nodeMap.get(e.source)?.label || e.source);
    const evidence = buildEvidenceChainsForNode(n.id, graph, history, opts);
    const url = n.properties.url || n.properties.label || n.id;

    findings.push({
      id: `finding-webapp-${n.id}`,
      title: `Web Application: ${n.properties.label || url}`,
      severity: vulnEdges.length > 0 ? 'high' : 'medium',
      category: 'webapp',
      description: `Web application at ${url}` +
        (n.properties.has_login_form ? ' (has login form)' : '') +
        (n.properties.technology ? `. Technology: ${n.properties.technology}` : '') +
        (vulnLabels.length > 0 ? `. Vulnerabilities: ${vulnLabels.slice(0, 5).join(', ')}` : '') +
        (authSources.length > 0 ? `. Authenticated via: ${authSources.join(', ')}` : '') +
        '.',
      affected_assets: [url, ...vulnLabels.slice(0, 5)],
      evidence,
      remediation: generateWebappRemediation(n.properties, vulnLabels),
      risk_score: vulnEdges.length > 0 ? 7.0 : 4.0,
    });
  }

  // Enrich findings with classification and CVSS estimation
  const nodeMap2 = new Map<string, NodeProperties>();
  for (const n of graph.nodes) nodeMap2.set(n.id, n.properties);

  for (const f of findings) {
    // Classification (CWE, OWASP, NIST, PCI, ATT&CK)
    f.classification = classifyFinding(f, nodeMap2, graph);

    // CVSS: use explicit vector from vuln node if available, otherwise estimate
    let hasExplicitCvss = false;
    for (const assetId of f.affected_assets) {
      const node = nodeMap2.get(assetId);
      if (node?.type === 'vulnerability' && node.cvss !== undefined) {
        hasExplicitCvss = true;
        f.cvss_score = node.cvss;
        break;
      }
    }
    // For vulnerability findings, also check the finding's own vuln node
    if (!hasExplicitCvss && f.category === 'vulnerability') {
      const vulnNodeId = f.id.replace(/^finding-vuln-/, '');
      const vulnNode = nodeMap2.get(vulnNodeId);
      if (vulnNode?.type === 'vulnerability' && vulnNode.cvss !== undefined) {
        hasExplicitCvss = true;
        f.cvss_score = vulnNode.cvss;
      }
    }
    if (!hasExplicitCvss) {
      const estimated = estimateCvssFromContext(f, graph, nodeMap2);
      f.cvss_vector = vectorToString(estimated.vector);
      f.cvss_score = estimated.score;
      f.cvss_estimated = true;
    }
    f.presentation = presentFinding(f, { graph });
  }

  // Sort by risk_score descending
  findings.sort((a, b) => b.risk_score - a.risk_score);
  return findings;
}

// ============================================================
// Evidence Chain Construction
// ============================================================

export function buildEvidenceChainsForNode(
  nodeId: string,
  graph: ExportedGraph,
  history: ActivityLogEntry[],
  opts?: EvidenceBuildOptions,
): EvidenceChain[] {
  const chains: EvidenceChain[] = [];
  const previewBytes = opts?.previewBytes ?? 8 * 1024;
  const loader = opts?.evidenceLoader;
  const recordLoader = opts?.evidenceRecordLoader;

  // 1. Find activity log entries that reference this node
  const relatedEntries = history.filter(entry => {
    if (entry.target_node_ids?.includes(nodeId)) return true;
    // Check ingested_node_ids stored in details (from finding ingestion)
    const d = entry.details as Record<string, unknown> | undefined;
    if (Array.isArray(d?.ingested_node_ids) && (d!.ingested_node_ids as string[]).includes(nodeId)) return true;
    return false;
  });

  // Group by action_id for structured chains
  const byAction = new Map<string, ActivityLogEntry[]>();
  for (const entry of relatedEntries) {
    if (entry.action_id) {
      const group = byAction.get(entry.action_id) || [];
      group.push(entry);
      byAction.set(entry.action_id, group);
    }
  }

  // For each related action_id, also pull every history entry sharing
  // that action_id (e.g. action_started / action_completed) so we can
  // attach stdout_evidence_id / stderr_evidence_id from the terminal
  // execution event even though those events do not carry node refs.
  const allByAction = new Map<string, ActivityLogEntry[]>();
  if (byAction.size > 0) {
    const wantedIds = new Set(byAction.keys());
    for (const entry of history) {
      if (entry.action_id && wantedIds.has(entry.action_id)) {
        const group = allByAction.get(entry.action_id) || [];
        group.push(entry);
        allByAction.set(entry.action_id, group);
      }
    }
  }

  for (const [actionId, entries] of byAction) {
    const first = entries[0];
    const allEntries = allByAction.get(actionId) || entries;

    // Merge evidence from all entries in the action cluster.
    // Later lifecycle events (finding_ingested, action_completed) are more
    // likely to carry the actual evidence than early ones (action_validated).
    const EVIDENCE_PRIORITY: Record<string, number> = {
      finding_ingested: 3,
      action_completed: 2,
      action_validated: 1,
    };
    let bestEvidence: Record<string, unknown> | undefined;
    let bestPriority = -1;
    for (const entry of allEntries) {
      const det = entry.details as Record<string, unknown> | undefined;
      if (!det) continue;
      if (det.evidence_type || det.evidence_content || det.evidence_filename || det.raw_output) {
        const prio = EVIDENCE_PRIORITY[entry.event_type ?? ''] ?? 0;
        if (prio > bestPriority) {
          bestEvidence = det;
          bestPriority = prio;
        }
      }
    }
    // Fall back to first entry's details if no entry carried evidence fields
    const d = bestEvidence ?? (first.details as Record<string, unknown> | undefined);

    // Pull terminal-execution diagnostics from the action lifecycle events.
    let stdoutEvidenceId: string | undefined;
    let stderrEvidenceId: string | undefined;
    let stdoutTruncated: boolean | undefined;
    let stdoutDropped: number | undefined;
    let stdoutTotal: number | undefined;
    let evidenceCaptureError: string | undefined;
    let partial: boolean | undefined;
    let partialReason: string | undefined;
    for (const entry of allEntries) {
      const det = entry.details as Record<string, unknown> | undefined;
      if (!det) continue;
      if (typeof det.stdout_evidence_id === 'string') stdoutEvidenceId = det.stdout_evidence_id;
      if (typeof det.stderr_evidence_id === 'string') stderrEvidenceId = det.stderr_evidence_id;
      if (typeof det.stdout_truncated === 'boolean') stdoutTruncated = det.stdout_truncated;
      if (typeof det.stdout_dropped_bytes === 'number') stdoutDropped = det.stdout_dropped_bytes;
      if (typeof det.stdout_total_bytes === 'number') stdoutTotal = det.stdout_total_bytes;
      if (typeof det.evidence_capture_error === 'string') evidenceCaptureError = det.evidence_capture_error;
      const ps = det.parse_summary as Record<string, unknown> | undefined;
      if (ps) {
        if (typeof ps.partial === 'boolean') partial = ps.partial;
        if (typeof ps.partial_reason === 'string') partialReason = ps.partial_reason;
      }
    }

    // Extract command_repr: prefer typed field (action_completed), fall back to details.command
    let commandRepr: string | undefined;
    for (const entry of allEntries) {
      if (entry.command_repr) { commandRepr = entry.command_repr; break; }
    }
    if (!commandRepr) {
      for (const entry of allEntries) {
        const det = entry.details as Record<string, unknown> | undefined;
        if (typeof det?.command === 'string') { commandRepr = det.command; break; }
      }
    }

    const chain: EvidenceChain = {
      claim: first.description,
      action_id: actionId,
      tool: first.tool_name,
      technique: first.technique,
      command: commandRepr,
      timestamp: first.timestamp,
      source_event_type: first.event_type,
      result_classification: first.result_classification || first.outcome,
      source_nodes: entries.flatMap(e => e.target_node_ids || []).filter(id => id !== nodeId),
      target_nodes: [nodeId],
      linked_findings: entries.flatMap(e => e.linked_finding_ids || []),
    };
    if (d?.evidence_type) chain.evidence_type = d.evidence_type as string;
    if (d?.evidence_content) chain.evidence_content = d.evidence_content as string;
    if (d?.evidence_filename) chain.evidence_filename = d.evidence_filename as string;
    if (d?.raw_output) chain.raw_output = d.raw_output as string;
    if (stdoutEvidenceId) chain.stdout_evidence_id = stdoutEvidenceId;
    if (stderrEvidenceId) chain.stderr_evidence_id = stderrEvidenceId;
    if (stdoutTruncated !== undefined) chain.stdout_truncated = stdoutTruncated;
    if (stdoutDropped !== undefined) chain.stdout_dropped_bytes = stdoutDropped;
    if (stdoutTotal !== undefined) chain.stdout_total_bytes = stdoutTotal;
    if (evidenceCaptureError) chain.evidence_capture_error = evidenceCaptureError;
    if (partial !== undefined) chain.partial = partial;
    if (partialReason) chain.partial_reason = partialReason;

    if (recordLoader && stdoutEvidenceId) {
      const record = recordLoader(stdoutEvidenceId);
      if (record?.content_hash) chain.stdout_content_hash = record.content_hash;
      if (record) chain.stdout_bytes = (record.raw_output_length ?? 0) + (record.content_length ?? 0);
    }
    if (recordLoader && stderrEvidenceId) {
      const record = recordLoader(stderrEvidenceId);
      if (record?.content_hash) chain.stderr_content_hash = record.content_hash;
      if (record) chain.stderr_bytes = (record.raw_output_length ?? 0) + (record.content_length ?? 0);
    }

    // Lazily resolve a head/tail preview of stdout from the evidence store
    // so reports show what the parser actually saw without bloating output.
    if (loader && stdoutEvidenceId) {
      try {
        const full = loader(stdoutEvidenceId);
        if (full !== null) {
          chain.stdout_preview = formatPreview(full, previewBytes);
        }
      } catch {
        // best-effort — never fail report generation on a missing blob
      }
    }
    chains.push(chain);
  }

  // 2. Entries without action_id — direct mentions
  const unlinkedEntries = relatedEntries.filter(e => !e.action_id);
  for (const entry of unlinkedEntries.slice(0, 5)) {
    chains.push({
      claim: entry.description,
      timestamp: entry.timestamp,
      tool: entry.tool_name,
      technique: entry.technique,
      source_event_type: entry.event_type,
      result_classification: entry.result_classification || entry.outcome,
      source_nodes: [],
      target_nodes: [nodeId],
    });
  }

  // 3. Edge provenance — DERIVED_FROM, DUMPED_FROM chains
  const derivationEdges = graph.edges.filter(e =>
    (e.properties.type === 'DERIVED_FROM' || e.properties.type === 'DUMPED_FROM') &&
    (e.source === nodeId || e.target === nodeId)
  );
  const nodeMap = new Map(graph.nodes.map(n => [n.id, n.properties]));
  for (const edge of derivationEdges) {
    const sourceLabel = nodeMap.get(edge.source)?.label || edge.source;
    const targetLabel = nodeMap.get(edge.target)?.label || edge.target;
    chains.push({
      claim: `${edge.properties.type}: ${sourceLabel} → ${targetLabel}` +
        (edge.properties.derivation_method ? ` (method: ${edge.properties.derivation_method})` : ''),
      timestamp: edge.properties.discovered_at,
      source_event_type: 'graph_provenance',
      source_nodes: [edge.source],
      target_nodes: [edge.target],
    });
  }

  return chains;
}

export function buildAllEvidenceChains(
  graph: ExportedGraph,
  history: ActivityLogEntry[],
  opts?: EvidenceBuildOptions,
): Map<string, EvidenceChain[]> {
  const result = new Map<string, EvidenceChain[]>();

  const interestingTypes = new Set([
    'host', 'credential', 'vulnerability',
    'cloud_identity', 'cloud_resource', 'webapp',
  ]);
  const interestingNodes = graph.nodes.filter(n => interestingTypes.has(n.properties.type));
  for (const n of interestingNodes) {
    const chains = buildEvidenceChainsForNode(n.id, graph, history, opts);
    if (chains.length > 0) {
      result.set(n.id, chains);
    }
  }

  return result;
}

/** Render a head/tail preview of large evidence content with an
 * elision marker citing the byte count. Always returns ≤ 2*budget. */
function formatPreview(text: string, budget: number): string {
  if (text.length <= budget * 2 + 64) return text;
  const head = text.slice(0, budget);
  const tail = text.slice(-budget);
  const elided = text.length - head.length - tail.length;
  return `${head}\n\n[… ${elided.toLocaleString()} bytes elided — fetch full content via evidence ID …]\n\n${tail}`;
}

function stableProofId(prefix: string, value: string): string {
  return `${prefix}-${createHash('sha256').update(value).digest('hex').slice(0, 12)}`;
}

function sourceKindForEvidence(ev: EvidenceChain): EvidenceProofCard['source_kind'] {
  if (ev.stdout_evidence_id || ev.stderr_evidence_id || ev.raw_output || ev.evidence_content || ev.command) {
    return 'direct_output';
  }
  if (ev.source_event_type === 'finding_ingested' || /ingest|parsed|parser/i.test(ev.claim)) {
    return 'parsed_result';
  }
  if (ev.source_event_type === 'graph_provenance' || /^(DERIVED_FROM|DUMPED_FROM):/.test(ev.claim)) {
    return 'provenance';
  }
  return 'activity';
}

function evidenceRank(kind: EvidenceProofCard['source_kind']): number {
  switch (kind) {
    case 'direct_output': return 0;
    case 'parsed_result': return 1;
    case 'provenance': return 2;
    case 'activity': return 3;
  }
}

function proofTextForEvidence(ev: EvidenceChain, kind: EvidenceProofCard['source_kind']): string {
  if (kind === 'direct_output') {
    if (ev.result_classification === 'failure') {
      return 'Captured command output records the attempted validation and its failed result.';
    }
    return 'Captured command output is linked to this finding and supports the claimed state change.';
  }
  if (kind === 'parsed_result') {
    return 'Parser or ingest output added graph artifacts that support this finding.';
  }
  if (kind === 'provenance') {
    return 'Graph provenance links this asset to the source artifact or derived credential chain.';
  }
  return 'The activity log references the affected asset during the engagement timeline.';
}

function parsedSummaryForEvidence(ev: EvidenceChain): string | undefined {
  const parts = [
    ev.source_event_type,
    ev.result_classification,
    ev.partial ? 'partial parser output' : undefined,
    ev.stdout_truncated ? 'stdout truncated' : undefined,
  ].filter(Boolean);
  return parts.length > 0 ? parts.join(' · ') : undefined;
}

function evidenceKey(ev: EvidenceChain): string {
  return ev.stdout_evidence_id
    || ev.stderr_evidence_id
    || ev.action_id
    || ev.evidence_filename
    || stableProofId('activity', `${ev.timestamp || ''}|${ev.claim}`);
}

function evidenceBytes(ev: EvidenceChain): number | undefined {
  const total = (ev.stdout_bytes ?? 0) + (ev.stderr_bytes ?? 0);
  if (total > 0) return total;
  if (ev.stdout_total_bytes && ev.stdout_total_bytes > 0) return ev.stdout_total_bytes;
  return undefined;
}

function rawPreviewForEvidence(ev: EvidenceChain, profile: ReportProfile): { preview?: string; redacted?: boolean } {
  if (profile === 'client') {
    if (ev.stdout_preview || ev.raw_output || ev.evidence_content) return { redacted: true };
    return {};
  }
  const preview = ev.stdout_preview || ev.raw_output || ev.evidence_content;
  return preview ? { preview } : {};
}

function proofCardForEvidence(ev: EvidenceChain, profile: ReportProfile): EvidenceProofCard {
  const key = evidenceKey(ev);
  const kind = sourceKindForEvidence(ev);
  const raw = rawPreviewForEvidence(ev, profile);
  return {
    id: stableProofId('proof', `${key}|${ev.claim}`),
    appendix_ref: stableProofId('ev', key),
    claim: ev.claim,
    proof: proofTextForEvidence(ev, kind),
    source_kind: kind,
    tool: ev.tool,
    technique: ev.technique,
    command: ev.command,
    timestamp: ev.timestamp,
    action_id: ev.action_id,
    evidence_id: ev.stdout_evidence_id || ev.stderr_evidence_id,
    content_hash: ev.stdout_content_hash || ev.stderr_content_hash,
    evidence_bytes: evidenceBytes(ev),
    evidence_type: ev.evidence_type,
    filename: ev.evidence_filename,
    parsed_summary: parsedSummaryForEvidence(ev),
    raw_preview: raw.preview,
    raw_preview_redacted: raw.redacted,
  };
}

export function buildProofCardsForFinding(finding: ReportFinding, profile: ReportProfile = 'operator'): EvidenceProofCard[] {
  const seen = new Set<string>();
  return finding.evidence
    .map(ev => proofCardForEvidence(ev, profile))
    .sort((a, b) => evidenceRank(a.source_kind) - evidenceRank(b.source_kind) || (a.timestamp || '').localeCompare(b.timestamp || ''))
    .filter(card => {
      const key = card.evidence_id || card.action_id || card.id;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

export function buildReportEvidenceModel(
  findings: ReportFinding[],
  opts: { profile?: ReportProfile; includeEvidence?: boolean } = {},
): { findings: ReportFinding[]; appendix: EvidenceAppendixEntry[]; evidenceCount: number } {
  const profile = opts.profile ?? 'operator';
  if (opts.includeEvidence === false) {
    return {
      findings: findings.map(f => ({ ...f, evidence: [], proof_cards: [] })),
      appendix: [],
      evidenceCount: 0,
    };
  }

  const appendix = new Map<string, EvidenceAppendixEntry>();
  const enriched = findings.map(finding => {
    const findingTitle = profile === 'client' ? displayFindingShortTitle(finding) : displayFindingTitle(finding);
    const proofCards = buildProofCardsForFinding(finding, profile);
    for (const card of proofCards) {
      const key = card.appendix_ref;
      const existing = appendix.get(key);
      if (existing) {
        if (!existing.finding_ids.includes(finding.id)) existing.finding_ids.push(finding.id);
        if (!existing.finding_titles.includes(findingTitle)) existing.finding_titles.push(findingTitle);
        continue;
      }
      appendix.set(key, {
        id: key,
        title: card.evidence_id ? `Evidence ${card.evidence_id.slice(0, 8)}` : card.action_id ? `Action ${card.action_id.slice(0, 8)}` : 'Activity evidence',
        claim: card.claim,
        source_kind: card.source_kind,
        evidence_id: card.evidence_id,
        content_hash: card.content_hash,
        action_id: card.action_id,
        tool: card.tool,
        command: card.command,
        timestamp: card.timestamp,
        evidence_type: card.evidence_type,
        filename: card.filename,
        size_bytes: card.evidence_bytes,
        redaction_mode: profile,
        finding_ids: [finding.id],
        finding_titles: [findingTitle],
        raw_preview: card.raw_preview,
        raw_preview_redacted: card.raw_preview_redacted,
      });
    }
    return { ...finding, proof_cards: proofCards };
  });

  return {
    findings: enriched,
    appendix: [...appendix.values()].sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || '')),
    evidenceCount: appendix.size,
  };
}

// ============================================================
// Attack Narrative
// ============================================================

export function buildAttackNarrative(
  graph: ExportedGraph,
  history: ActivityLogEntry[],
  config: EngagementConfig,
): NarrativePhase[] {
  const nodeMap = new Map<string, NodeProperties>();
  for (const n of graph.nodes) nodeMap.set(n.id, n.properties);

  // Group history by action_id clusters, preserve chronological order
  const phases: NarrativePhase[] = [];

  // Classify each cluster into engagement phases
  const reconEntries: ActivityLogEntry[] = [];
  const accessEntries: ActivityLogEntry[] = [];
  const lateralEntries: ActivityLogEntry[] = [];
  const privescEntries: ActivityLogEntry[] = [];
  const objectiveEntries: ActivityLogEntry[] = [];

  for (const entry of history) {
    const desc = (entry.description || '').toLowerCase();
    const eventType = entry.event_type || '';

    if (eventType === 'objective_achieved' || desc.includes('objective achieved')) {
      objectiveEntries.push(entry);
    } else if (desc.includes('admin_to') || desc.includes('domain admin') || desc.includes('dcsync') ||
               desc.includes('privilege escalat') || desc.includes('privesc') || desc.includes('suid') ||
               desc.includes('admin to')) {
      privescEntries.push(entry);
    } else if (desc.includes('lateral') || desc.includes('pivot') || desc.includes('session') && desc.includes('new') ||
               eventType === 'session_opened' || eventType === 'session_connected' ||
               desc.includes('has_session') || desc.includes('rdp') || desc.includes('psremote') ||
               desc.includes('winrm') || desc.includes('ssh')) {
      lateralEntries.push(entry);
    } else if (desc.includes('credential') || desc.includes('cred') || desc.includes('password') ||
               desc.includes('ntlm') || desc.includes('hash') || desc.includes('kerberos') ||
               desc.includes('initial access') || desc.includes('auth') || desc.includes('login') ||
               desc.includes('secretsdump') || desc.includes('owns_cred')) {
      accessEntries.push(entry);
    } else {
      reconEntries.push(entry);
    }
  }

  // Build narrative for each phase
  if (reconEntries.length > 0) {
    phases.push({
      name: 'Reconnaissance',
      start_time: reconEntries[0]?.timestamp,
      end_time: reconEntries[reconEntries.length - 1]?.timestamp,
      paragraphs: buildPhaseNarrative(reconEntries, nodeMap, config, 'reconnaissance'),
    });
  }

  if (accessEntries.length > 0) {
    phases.push({
      name: 'Initial Access & Credential Acquisition',
      start_time: accessEntries[0]?.timestamp,
      end_time: accessEntries[accessEntries.length - 1]?.timestamp,
      paragraphs: buildPhaseNarrative(accessEntries, nodeMap, config, 'access'),
    });
  }

  if (lateralEntries.length > 0) {
    phases.push({
      name: 'Lateral Movement',
      start_time: lateralEntries[0]?.timestamp,
      end_time: lateralEntries[lateralEntries.length - 1]?.timestamp,
      paragraphs: buildPhaseNarrative(lateralEntries, nodeMap, config, 'lateral'),
    });
  }

  if (privescEntries.length > 0) {
    phases.push({
      name: 'Privilege Escalation',
      start_time: privescEntries[0]?.timestamp,
      end_time: privescEntries[privescEntries.length - 1]?.timestamp,
      paragraphs: buildPhaseNarrative(privescEntries, nodeMap, config, 'privesc'),
    });
  }

  if (objectiveEntries.length > 0) {
    phases.push({
      name: 'Objective Achievement',
      start_time: objectiveEntries[0]?.timestamp,
      end_time: objectiveEntries[objectiveEntries.length - 1]?.timestamp,
      paragraphs: buildPhaseNarrative(objectiveEntries, nodeMap, config, 'objective'),
    });
  }

  // Fallback: if no phases were created, produce a single summary
  if (phases.length === 0 && history.length > 0) {
    phases.push({
      name: 'Engagement Summary',
      start_time: history[0]?.timestamp,
      end_time: history[history.length - 1]?.timestamp,
      paragraphs: ['The engagement produced activity but no significant attack phases were identified from the structured activity log.'],
    });
  }

  return phases;
}

function buildPhaseNarrative(
  entries: ActivityLogEntry[],
  nodeMap: Map<string, NodeProperties>,
  _config: EngagementConfig,
  phase: string,
): string[] {
  const grouped = groupByActionId(entries);
  const inventory = summarizeInventory(entries);
  const actionSummaries = [...grouped.values()]
    .map(cluster => summarizeActionCluster(cluster, nodeMap))
    .filter((value): value is string => !!value)
    .slice(0, 4);
  const accessChanges = summarizeAccessChanges(entries, nodeMap);
  const objectiveEvents = entries
    .filter(entry => entry.event_type === 'objective_achieved' || /objective achieved/i.test(entry.description || ''))
    .map(entry => humanizeActivityDescription(entry.description))
    .slice(0, 2);

  const paragraphs: string[] = [];
  const phaseIntent = phaseIntentLabel(phase);
  const inventorySentence = inventory ? ` ${inventory}` : '';
  if (actionSummaries.length > 0) {
    paragraphs.push(`${phaseIntent}${inventorySentence} ${actionSummaries.join(' ')}`.trim());
  } else if (inventory) {
    paragraphs.push(`${phaseIntent} ${inventory}`.trim());
  }

  const resultFacts = [...accessChanges, ...objectiveEvents];
  if (resultFacts.length > 0) {
    paragraphs.push(`Result: ${resultFacts.join(' ')}`);
  }

  if (paragraphs.length === 0) {
    paragraphs.push(`${capitalize(phase)} activity was recorded, but no reportable phase milestone was identified from the structured activity log.`);
  }

  return paragraphs;
}

function phaseIntentLabel(phase: string): string {
  switch (phase) {
    case 'reconnaissance': return 'Reconnaissance focused on mapping reachable assets and service exposure.';
    case 'access': return 'Initial access focused on validating credential material and authentication paths.';
    case 'lateral': return 'Lateral movement focused on turning confirmed access into host or application reach.';
    case 'privesc': return 'Privilege escalation focused on identifying administrative control paths.';
    case 'objective': return 'Objective work focused on validating engagement goals with the access already obtained.';
    default: return `${capitalize(phase)} focused on material engagement progress.`;
  }
}

function summarizeInventory(entries: ActivityLogEntry[]): string | null {
  const hosts = new Set<string>();
  const services = new Set<string>();
  for (const entry of entries) {
    const desc = entry.description || '';
    const host = desc.match(/New host discovered:\s*([^.;]+)/i)?.[1]?.trim();
    if (host) hosts.add(host);
    const service = desc.match(/New service discovered:\s*([^.;]+)/i)?.[1]?.trim();
    if (service) services.add(service);
  }
  const parts: string[] = [];
  if (hosts.size > 0) parts.push(`${hosts.size} host${hosts.size === 1 ? '' : 's'}`);
  if (services.size > 0) parts.push(`${services.size} service${services.size === 1 ? '' : 's'}`);
  return parts.length > 0 ? `Inventory expanded by ${parts.join(' and ')}.` : null;
}

function summarizeActionCluster(cluster: ActivityLogEntry[], nodeMap: Map<string, NodeProperties>): string | null {
  const first = cluster.find(entry => entry.tool_name || entry.command_repr) || cluster[0];
  const desc = first.description || '';
  if (isNarrativeNoise(desc)) return null;
  const tool = first.tool_name;
  const targets = [
    ...(first.target_node_ids?.map(id => nodeMap.get(id)?.label || id) || []),
    ...(first.target_ips || []),
  ];
  const allTargets = [...new Set(targets)].slice(0, 3);
  const result = cluster.find(e => e.event_type === 'action_completed' || e.event_type === 'action_failed');
  const outcome = result?.result_classification || result?.outcome;

  if (tool) {
    const action = [
      `Used ${tool}`,
      first.technique ? `for ${first.technique}` : undefined,
      allTargets.length > 0 ? `against ${allTargets.join(', ')}` : undefined,
    ].filter(Boolean).join(' ');
    const suffix = outcome === 'success' ? ' and confirmed useful results'
      : outcome === 'failure' ? ' but did not validate the attempted path'
        : '';
    return `${action}${suffix}.`;
  }

  return `${humanizeActivityDescription(desc)}.`;
}

function summarizeAccessChanges(entries: ActivityLogEntry[], nodeMap: Map<string, NodeProperties>): string[] {
  const facts: string[] = [];
  for (const entry of entries) {
    const desc = entry.description || '';
    if (isNarrativeNoise(desc)) continue;
    if (/session/i.test(desc) || /HAS_SESSION/.test(desc)) {
      const targets = entry.target_node_ids?.map(id => nodeMap.get(id)?.label || id).filter(Boolean) || [];
      facts.push(targets.length > 0
        ? `Session evidence changed access on ${targets.slice(0, 3).join(', ')}.`
        : `${humanizeActivityDescription(desc)}.`);
    } else if (/credential|cred|ntlm|hash|token/i.test(desc)) {
      facts.push(`${humanizeActivityDescription(desc)}.`);
    } else if (/admin_to|administrative|domain admin/i.test(desc)) {
      facts.push(`${humanizeActivityDescription(desc)}.`);
    }
    if (facts.length >= 3) break;
  }
  return [...new Set(facts)];
}

function isNarrativeNoise(desc: string): boolean {
  return /caveat|warning|malformed|skipped|indeterminate|truncated|exceeded inline buffer/i.test(desc)
    || /^New (host|service) discovered:/i.test(desc)
    || /Engagement initialized/i.test(desc);
}

function humanizeActivityDescription(desc: string): string {
  return desc
    .replace(/\bHAS_SESSION from ([\w@.:-]+)/g, 'an active session for `$1` confirmed access')
    .replace(/\bHAS_SESSION\b/g, 'active session')
    .replace(/\bADMIN_TO\b/g, 'administrative access')
    .replace(/\bOWNS_CRED\b/g, 'credential ownership')
    .replace(/\bVALID_FOR_IDP_PRINCIPAL\b/g, 'valid identity-provider access')
    .replace(/\s+/g, ' ')
    .replace(/[.]+$/, '');
}

// ============================================================
// Full Markdown Report
// ============================================================

/**
 * Decorate raw `PathResult`-shaped tuples (just node ID lists) with the
 * label/type of each step and the edge attributes traversed between
 * consecutive steps. The edge picker prefers a confirmed edge of any
 * type between (a→b); if none exists, falls back to the highest-
 * confidence edge available, which can be an inferred edge.
 *
 * Stamped fields per step:
 *   - `label` from the node's label property (or the node id as fallback)
 *   - `type` from the node's `type` property
 *   - `edge_to_next` (omitted on the terminal step) — type, confidence,
 *     inferred flag (true when the edge has `inferred_by_rule` and no
 *     `confirmed_at`), and the rule name when inferred.
 */
export function buildAttackPaths(
  rawPaths: Array<{ nodes: string[]; total_confidence: number; total_opsec_noise: number }>,
  graph: ExportedGraph,
  opts: { objective_id?: string; objective_label?: string } = {},
): AttackPath[] {
  const nodeById = new Map<string, NodeProperties>();
  for (const n of graph.nodes) nodeById.set(n.id, n.properties);

  // Group edges by (source, target) key for fast lookup. Keep all
  // candidates; the picker chooses confirmed first, then highest conf.
  const edgesBetween = new Map<string, ExportedGraphEdge[]>();
  for (const e of graph.edges) {
    const k = `${e.source}\u0000${e.target}`;
    const arr = edgesBetween.get(k);
    if (arr) arr.push(e);
    else edgesBetween.set(k, [e]);
  }

  const pickEdge = (src: string, tgt: string): ExportedGraphEdge | null => {
    const candidates = edgesBetween.get(`${src}\u0000${tgt}`) ?? edgesBetween.get(`${tgt}\u0000${src}`) ?? [];
    if (candidates.length === 0) return null;
    // Confirmed first — anything without `inferred_by_rule` OR with `confirmed_at`.
    const confirmed = candidates.find(e => !e.properties.inferred_by_rule || e.properties.confirmed_at);
    if (confirmed) return confirmed;
    // Otherwise highest-confidence inferred.
    return candidates.reduce((best, e) =>
      (e.properties.confidence ?? 0) > (best.properties.confidence ?? 0) ? e : best);
  };

  const out: AttackPath[] = [];
  // Dedup by node-set hash so the same chain reached via two objectives
  // doesn't print twice.
  const seen = new Set<string>();
  for (const raw of rawPaths) {
    const key = raw.nodes.join('|');
    if (seen.has(key)) continue;
    seen.add(key);

    const steps: AttackPathStep[] = [];
    let containsInferred = false;
    for (let i = 0; i < raw.nodes.length; i++) {
      const id = raw.nodes[i];
      const props = nodeById.get(id);
      const step: AttackPathStep = {
        node_id: id,
        label: (props?.label as string | undefined) ?? id,
        type: (props?.type as string | undefined) ?? 'unknown',
      };
      if (i < raw.nodes.length - 1) {
        const edge = pickEdge(id, raw.nodes[i + 1]);
        if (edge) {
          // Cross-tier-inference rules currently stamp `rule` on the edge
          // properties; the canonical schema field is `inferred_by_rule`.
          // Read both so a renamed-but-not-rewritten codebase still
          // classifies inferred edges correctly.
          const ruleName = (edge.properties.inferred_by_rule as string | undefined)
            ?? (edge.properties.rule as string | undefined);
          const inferred = !!ruleName && !edge.properties.confirmed_at;
          if (inferred) containsInferred = true;
          step.edge_to_next = {
            type: edge.properties.type as string,
            confidence: (edge.properties.confidence as number | undefined) ?? 0,
            inferred,
            rule: inferred ? ruleName : undefined,
          };
        }
      }
      steps.push(step);
    }
    out.push({
      objective_id: opts.objective_id,
      objective_label: opts.objective_label,
      steps,
      total_confidence: raw.total_confidence,
      total_opsec_noise: raw.total_opsec_noise,
      contains_inferred: containsInferred,
    });
  }
  return out;
}

/**
 * Render the Attack Paths section in markdown. Returns an empty string
 * when there are no paths so the caller can splice unconditionally.
 */
export function renderAttackPathsSection(paths: AttackPath[]): string {
  if (paths.length === 0) return '';
  const lines: string[] = [];
  lines.push('## Attack Paths');
  lines.push('');
  lines.push('Synthesized attack chains from current access to engagement objectives. ' +
    'Each path lists the node traversed, the edge type taken, and the per-edge confidence. ' +
    'Inferred edges (flagged below) have not been live-replayed; confirmed edges are evidence-backed.');
  lines.push('');

  // Group by objective so multi-objective reports stay readable.
  const byObjective = new Map<string, AttackPath[]>();
  for (const p of paths) {
    const key = p.objective_id ?? '__none__';
    const arr = byObjective.get(key);
    if (arr) arr.push(p);
    else byObjective.set(key, [p]);
  }

  for (const [objKey, group] of byObjective.entries()) {
    if (objKey !== '__none__') {
      const objLabel = group[0].objective_label ?? objKey;
      lines.push(`### Objective: ${objLabel}`);
      lines.push('');
    }

    let pathIdx = 1;
    for (const path of group) {
      lines.push(`**Path ${pathIdx}** — confidence ${path.total_confidence.toFixed(2)}, ` +
        `OPSEC noise ${path.total_opsec_noise.toFixed(2)}` +
        (path.contains_inferred ? ', **contains inferred hops**' : ''));
      lines.push('');
      for (let i = 0; i < path.steps.length; i++) {
        const step = path.steps[i];
        const indent = '  '.repeat(i);
        lines.push(`${indent}${i + 1}. ${step.label} \`(${step.type})\``);
        if (step.edge_to_next) {
          const edge = step.edge_to_next;
          const tag = edge.inferred
            ? `inferred by \`${edge.rule ?? 'rule'}\`, conf ${edge.confidence.toFixed(2)}`
            : `confirmed, conf ${edge.confidence.toFixed(2)}`;
          lines.push(`${indent}   → \`${edge.type}\` (${tag})`);
        }
      }
      lines.push('');
      pathIdx++;
    }
  }

  return lines.join('\n');
}

function renderProofCardsMarkdown(cards: EvidenceProofCard[], style: EvidenceStyle): string[] {
  const lines: string[] = [];
  if (cards.length === 0) return lines;
  if (style === 'appendix') {
    for (const card of cards.slice(0, 5)) {
      lines.push(`- ${card.claim} (see [${card.appendix_ref}](#${card.appendix_ref}))`);
    }
    return lines;
  }

  for (const card of cards.slice(0, 5)) {
    lines.push(`- **${sourceKindLabel(card.source_kind)}:** ${card.claim}`);
    lines.push(`  - Proof: ${card.proof}`);
    const meta = [
      card.tool ? `tool: ${card.tool}` : undefined,
      card.timestamp ? `time: ${formatTimestamp(card.timestamp)}` : undefined,
      card.action_id ? `action: ${card.action_id.slice(0, 8)}` : undefined,
      card.evidence_id ? `evidence: ${card.evidence_id}` : undefined,
      card.filename ? `file: ${card.filename}` : undefined,
      card.content_hash ? `sha256: ${card.content_hash.slice(0, 16)}...` : undefined,
    ].filter(Boolean);
    if (meta.length > 0) lines.push(`  - ${meta.join(' | ')}`);
    if (card.parsed_summary) lines.push(`  - Result: ${card.parsed_summary}`);
    if (card.command) {
      lines.push('  ```bash');
      lines.push(`  ${card.command}`);
      lines.push('  ```');
    }
    if (card.raw_preview_redacted) {
      lines.push('  - Raw preview redacted in client profile; full evidence is tracked in the appendix.');
    } else if (style === 'full_inline' && card.raw_preview) {
      lines.push('  ```');
      for (const pl of card.raw_preview.split('\n').slice(0, 80)) lines.push(`  ${pl}`);
      lines.push('  ```');
    } else if (card.raw_preview) {
      lines.push('  <details><summary>Raw preview</summary>');
      lines.push('');
      lines.push('  ```');
      for (const pl of card.raw_preview.split('\n').slice(0, 80)) lines.push(`  ${pl}`);
      lines.push('  ```');
      lines.push('  </details>');
    }
    lines.push(`  - Appendix: [${card.appendix_ref}](#${card.appendix_ref})`);
  }
  if (cards.length > 5) {
    lines.push(`- ... and ${cards.length - 5} more proof card(s) in the evidence appendix`);
  }
  return lines;
}

function renderEvidenceAppendixMarkdown(appendix: EvidenceAppendixEntry[]): string[] {
  const lines: string[] = [];
  if (appendix.length === 0) return lines;
  lines.push('## Evidence Appendix');
  lines.push('');
  lines.push('Each cited artifact is indexed once. Client reports preserve IDs and hashes for verification while redacting sensitive raw output.');
  lines.push('');
  for (const entry of appendix) {
    lines.push(`### ${entry.id}`);
    lines.push('');
    lines.push(`**${entry.title}**`);
    lines.push('');
    lines.push(`- Claim: ${entry.claim}`);
    lines.push(`- Source: ${sourceKindLabel(entry.source_kind)}`);
    if (entry.tool) lines.push(`- Tool: ${entry.tool}`);
    if (entry.timestamp) lines.push(`- Time: ${formatTimestamp(entry.timestamp)}`);
    if (entry.action_id) lines.push(`- Action ID: \`${entry.action_id}\``);
    if (entry.evidence_id) lines.push(`- Evidence ID: \`${entry.evidence_id}\``);
    if (entry.content_hash) lines.push(`- SHA-256: \`${entry.content_hash}\``);
    if (entry.size_bytes !== undefined) lines.push(`- Size: ${entry.size_bytes.toLocaleString()} bytes`);
    lines.push(`- Referenced by: ${entry.finding_titles.join('; ')}`);
    if (entry.command) {
      lines.push('');
      lines.push('```bash');
      lines.push(entry.command);
      lines.push('```');
    }
    if (entry.raw_preview_redacted) {
      lines.push('');
      lines.push('Raw output preview redacted in client profile.');
    } else if (entry.raw_preview) {
      lines.push('');
      lines.push('<details><summary>Raw preview</summary>');
      lines.push('');
      lines.push('```');
      lines.push(entry.raw_preview.split('\n').slice(0, 120).join('\n'));
      lines.push('```');
      lines.push('</details>');
    }
    lines.push('');
  }
  return lines;
}

function sourceKindLabel(kind: EvidenceProofCard['source_kind']): string {
  switch (kind) {
    case 'direct_output': return 'Command output';
    case 'parsed_result': return 'Parsed result';
    case 'provenance': return 'Graph provenance';
    case 'activity': return 'Activity record';
  }
}

function renderExecutiveSummaryMarkdown(summary: ReportExecutiveSummary, counts: Record<FindingSeverity, number>): string[] {
  const lines: string[] = [];
  lines.push(summary.headline);
  lines.push('');
  lines.push(`**Risk posture:** ${riskPostureLabel(summary.risk_posture)}`);
  lines.push('');
  lines.push(`- **Scope:** ${summary.scope_summary}`);
  lines.push(`- **Objectives:** ${summary.objective_summary}`);
  lines.push(`- **Findings:** ${summary.finding_summary}`);
  lines.push(`- **Evidence confidence:** ${summary.evidence_summary}`);
  lines.push(`- **Verification notes:** ${summary.verification_summary}`);
  lines.push('');
  if (summary.top_risk_themes.length > 0) {
    lines.push('### Top Risk Themes');
    lines.push('');
    for (const theme of summary.top_risk_themes) {
      lines.push(`- ${theme}`);
    }
    lines.push('');
  }
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  lines.push(`| Critical | ${counts.critical} |`);
  lines.push(`| High | ${counts.high} |`);
  lines.push(`| Medium | ${counts.medium} |`);
  lines.push(`| Low | ${counts.low} |`);
  lines.push(`| Info | ${counts.info} |`);
  lines.push('');
  return lines;
}

function renderActionPlanMarkdown(actionPlan: ReportActionPlanItem[]): string[] {
  const lines: string[] = [];
  lines.push('## Action Plan');
  lines.push('');
  if (actionPlan.length === 0) {
    lines.push('No consolidated remediation actions were generated from the current finding set.');
    lines.push('');
    return lines;
  }
  for (const item of actionPlan) {
    lines.push(`### ${item.title}`);
    lines.push('');
    lines.push(`**Priority:** ${actionPriorityLabel(item.priority)}`);
    lines.push('');
    lines.push(`**Action:** ${item.action}`);
    lines.push('');
    lines.push(`**Why it matters:** ${item.rationale}`);
    lines.push('');
    lines.push(`**Verification:** ${item.verification}`);
    if (item.related_findings.length > 0) {
      lines.push('');
      lines.push(`**Related findings:** ${item.related_findings.join('; ')}`);
    }
    lines.push('');
  }
  return lines;
}

function riskPostureLabel(posture: ReportExecutiveSummary['risk_posture']): string {
  switch (posture) {
    case 'critical': return 'Critical';
    case 'elevated': return 'Elevated';
    case 'moderate': return 'Moderate';
    case 'low': return 'Low';
  }
}

function actionPriorityLabel(priority: ReportActionPlanItem['priority']): string {
  switch (priority) {
    case 'immediate': return 'Immediate';
    case 'near_term': return 'Near term';
    case 'validation': return 'Validation';
  }
}

function describeAccessMethod(edge: ExportedGraphEdge, source?: NodeProperties): string {
  const actor = source?.label || source?.username || source?.id || edge.source;
  switch (edge.properties.type) {
    case 'HAS_SESSION':
      return `an active session for ${actor}`;
    case 'ADMIN_TO':
      return `administrative rights held by ${actor}`;
    case 'EXPLOITS':
      return `validated exploitation from ${actor}`;
    default:
      return `${String(edge.properties.type).toLowerCase().replace(/_/g, ' ')} from ${actor}`;
  }
}

export function generateFullReport(input: ReportInput, options: ReportOptions = {}): string {
  const {
    include_evidence = true,
    include_narrative = true,
    include_retrospective = true,
    include_compliance = true,
    include_gap_analysis = false,
    max_timeline_entries = 50,
    report_profile = 'operator',
    evidence_style = 'proof_cards',
  } = options;

  const config = input.config;
  const graph = input.graph;
  const history = input.history;

  const evidenceOpts: EvidenceBuildOptions | undefined = options.evidence_loader || options.evidence_record_loader
    ? {
      evidenceLoader: options.evidence_loader,
      evidenceRecordLoader: options.evidence_record_loader,
      previewBytes: options.evidence_preview_bytes,
    }
    : undefined;
  const baseFindings = buildFindings(graph, history, config, evidenceOpts);
  const proofModel = buildReportEvidenceModel(baseFindings, {
    profile: report_profile,
    includeEvidence: include_evidence,
  });
  const findings = proofModel.findings;
  const narrative = include_narrative ? buildAttackNarrative(graph, history, config) : [];
  const credChains = buildCredentialChains(graph);

  const nodesByType: Record<string, number> = {};
  for (const n of graph.nodes) {
    nodesByType[n.properties.type] = (nodesByType[n.properties.type] || 0) + 1;
  }

  const edgesByType: Record<string, number> = {};
  let confirmedEdges = 0;
  let inferredEdges = 0;
  for (const e of graph.edges) {
    edgesByType[e.properties.type] = (edgesByType[e.properties.type] || 0) + 1;
    // P3.3: provenance-based bucketing matching graph-engine.getState().
    // confidence >= 1.0 alone mislabels high-confidence inference rules
    // as "confirmed" and parser observations at 0.9 as "inferred".
    const isInferred = !!e.properties.inferred_by_rule && !e.properties.confirmed_at;
    if (isInferred) inferredEdges++;
    else confirmedEdges++;
  }

  const startTime = history.length > 0 ? history[0].timestamp : config.created_at;
  const endTime = history.length > 0 ? history[history.length - 1].timestamp : config.created_at;

  const criticalFindings = findings.filter(f => f.severity === 'critical');
  const highFindings = findings.filter(f => f.severity === 'high');
  const mediumFindings = findings.filter(f => f.severity === 'medium');
  const lowFindings = findings.filter(f => f.severity === 'low');
  const infoFindings = findings.filter(f => f.severity === 'info');
  const severityCounts: Record<FindingSeverity, number> = {
    critical: criticalFindings.length,
    high: highFindings.length,
    medium: mediumFindings.length,
    low: lowFindings.length,
    info: infoFindings.length,
  };
  const executiveSummary = buildExecutiveSummary({
    config,
    graph,
    findings,
    profile: report_profile,
    evidenceCount: proofModel.evidenceCount,
    trustSignals: options.trust_signals,
  });
  const actionPlan = buildActionPlan({
    config,
    graph,
    findings,
    profile: report_profile,
    evidenceCount: proofModel.evidenceCount,
    trustSignals: options.trust_signals,
  });

  const lines: string[] = [];

  // === Title ===
  lines.push(`# Penetration Test Report: ${config.name}`);
  lines.push('');
  lines.push(`**Engagement ID:** ${config.id}`);
  lines.push(`**Period:** ${formatTimestamp(startTime)} — ${formatTimestamp(endTime)}`);
  lines.push(`**OPSEC Profile:** ${config.opsec.name} (max noise: ${config.opsec.max_noise})`);
  lines.push(`**Report Generated:** ${formatTimestamp(new Date().toISOString())}`);
  lines.push('');

  // === Table of Contents ===
  lines.push('## Table of Contents');
  lines.push('');
  lines.push('1. [Executive Summary](#executive-summary)');
  lines.push('2. [Scope](#scope)');
  lines.push('3. [Findings Summary](#findings-summary)');
  lines.push('4. [Action Plan](#action-plan)');
  lines.push('5. [Detailed Findings](#detailed-findings)');
  if (include_narrative && narrative.length > 0) {
    lines.push('6. [Attack Narrative](#attack-narrative)');
  }
  lines.push(`${include_narrative && narrative.length > 0 ? '7' : '6'}. [Objectives](#objectives)`);
  lines.push('');

  // === Executive Summary ===
  lines.push('## Executive Summary');
  lines.push('');
  lines.push(...renderExecutiveSummaryMarkdown(executiveSummary, severityCounts));

  // === Scope ===
  lines.push('## Scope');
  lines.push('');
  lines.push('| Type | Values |');
  lines.push('|------|--------|');
  lines.push(`| CIDRs | ${config.scope.cidrs.join(', ') || 'none'} |`);
  lines.push(`| Domains | ${config.scope.domains.join(', ') || 'none'} |`);
  lines.push(`| Exclusions | ${config.scope.exclusions.join(', ') || 'none'} |`);
  if (config.scope.aws_accounts?.length) lines.push(`| AWS Accounts | ${config.scope.aws_accounts.join(', ')} |`);
  if (config.scope.azure_subscriptions?.length) lines.push(`| Azure Subscriptions | ${config.scope.azure_subscriptions.join(', ')} |`);
  if (config.scope.gcp_projects?.length) lines.push(`| GCP Projects | ${config.scope.gcp_projects.join(', ')} |`);
  if (config.scope.url_patterns?.length) lines.push(`| URL Patterns | ${config.scope.url_patterns.join(', ')} |`);
  lines.push('');

  // === Findings Summary ===
  lines.push('## Findings Summary');
  lines.push('');
  if (findings.length === 0) {
    lines.push('No significant findings were identified during this engagement.');
    lines.push('');
  } else {
    lines.push('| # | Severity | Title | Risk Score |');
    lines.push('|---|----------|-------|------------|');
    findings.forEach((f, i) => {
      lines.push(`| ${i + 1} | ${severityBadge(f.severity)} | ${escapeTableCell(displayFindingShortTitle(f))} | ${f.risk_score.toFixed(1)} |`);
    });
    lines.push('');
  }

  lines.push(...renderActionPlanMarkdown(actionPlan));

  // === Detailed Findings ===
  lines.push('## Detailed Findings');
  lines.push('');

  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    const findingHeading = report_profile === 'client' ? displayFindingShortTitle(f) : displayFindingTitle(f);
    lines.push(`### ${i + 1}. ${findingHeading}`);
    lines.push('');
    lines.push(`**Severity:** ${severityBadge(f.severity)} | **Risk Score:** ${f.risk_score.toFixed(1)} | **Category:** ${displayFindingCategory(f.category)}`);
    if (f.cvss_score !== undefined) {
      lines.push(`**CVSS:** ${f.cvss_score.toFixed(1)}${f.cvss_estimated ? ' (estimated)' : ''}${f.cvss_vector ? ` | \`${f.cvss_vector}\`` : ''}`);
      if (f.cvss_estimated) {
        lines.push('> Verification: CVSS was estimated from current graph evidence and should be corroborated before client reporting.');
      }
    }
    lines.push('');
    lines.push('#### Description');
    lines.push('');
    lines.push(displayFindingSummary(f));
    lines.push('');
    lines.push(`**Impact:** ${displayFindingImpact(f)}`);
    if (report_profile === 'operator' && f.presentation?.technical_context) {
      lines.push('');
      lines.push('**Technical context:**');
      lines.push('');
      lines.push(f.presentation.technical_context);
    }
    lines.push('');
    lines.push('#### Affected Assets');
    lines.push('');
    for (const asset of f.affected_assets.slice(0, 10)) {
      lines.push(`- ${asset}`);
    }
    if (f.affected_assets.length > 10) {
      lines.push(`- ... and ${f.affected_assets.length - 10} more`);
    }
    lines.push('');

    if (include_evidence && (f.proof_cards?.length || f.evidence.length > 0)) {
      lines.push('#### Evidence');
      lines.push('');
      lines.push(...renderProofCardsMarkdown(f.proof_cards ?? buildProofCardsForFinding(f, report_profile), evidence_style));
      lines.push('');
    }

    lines.push('#### Remediation');
    lines.push('');
    lines.push(displayFindingRemediation(f));
    lines.push('');
  }

  // === Attack Narrative ===
  if (include_narrative && narrative.length > 0) {
    lines.push('## Attack Narrative');
    lines.push('');
    for (const phase of narrative) {
      lines.push(`### ${phase.name}`);
      if (phase.start_time) {
        lines.push(`*${formatTimestamp(phase.start_time)}${phase.end_time && phase.end_time !== phase.start_time ? ` — ${formatTimestamp(phase.end_time)}` : ''}*`);
      }
      lines.push('');
      for (const para of phase.paragraphs) {
        lines.push(para);
        lines.push('');
      }
    }
  }

  // === Credential Chains ===
  if (credChains.length > 0) {
    lines.push('## Credential Chains');
    lines.push('');
    lines.push('The following credential derivation chains were identified:');
    lines.push('');
    for (const chain of credChains) {
      const parts: string[] = [];
      for (let i = 0; i < chain.labels.length; i++) {
        if (i > 0) parts.push(` → [${chain.methods[i - 1]}] → `);
        parts.push(chain.labels[i]);
      }
      lines.push(`- ${parts.join('')}`);
    }
    lines.push('');
  }

  if (include_evidence && proofModel.appendix.length > 0) {
    lines.push(...renderEvidenceAppendixMarkdown(proofModel.appendix));
  }

  // === Objectives ===
  lines.push('## Objectives');
  lines.push('');
  lines.push('| Objective | Status | Achieved At |');
  lines.push('|-----------|--------|-------------|');
  for (const obj of config.objectives) {
    const status = obj.achieved ? 'Achieved' : 'Pending';
    const at = obj.achieved_at ? formatTimestamp(obj.achieved_at) : '—';
    lines.push(`| ${escapeTableCell(obj.description)} | ${status} | ${at} |`);
  }
  lines.push('');

  // === Attack Paths === (requires caller to pass `attack_paths` in input)
  if (input.attack_paths && input.attack_paths.length > 0) {
    const section = renderAttackPathsSection(input.attack_paths);
    if (section) {
      lines.push(section);
      lines.push('');
    }
  }

  // === Discovery Summary ===
  lines.push('## Discovery Summary');
  lines.push('');
  lines.push('### Nodes');
  lines.push('');
  lines.push('| Type | Count |');
  lines.push('|------|-------|');
  for (const [type, count] of Object.entries(nodesByType).sort((a, b) => b[1] - a[1])) {
    lines.push(`| ${type} | ${count} |`);
  }
  lines.push(`| **Total** | **${graph.nodes.length}** |`);
  lines.push('');

  lines.push('### Edges');
  lines.push('');
  lines.push('| Type | Count |');
  lines.push('|------|-------|');
  for (const [type, count] of Object.entries(edgesByType).sort((a, b) => b[1] - a[1])) {
    lines.push(`| ${type} | ${count} |`);
  }
  lines.push(`| **Total** | **${graph.edges.length}** (${confirmedEdges} confirmed, ${inferredEdges} inferred) |`);
  lines.push('');

  // === Agent Activity ===
  if (input.agents.length > 0) {
    lines.push('## Agent Activity');
    lines.push('');
    const completedAgents = input.agents.filter(a => a.status === 'completed');
    const failedAgents = input.agents.filter(a => a.status === 'failed');
    lines.push(`- **Total agents dispatched:** ${input.agents.length}`);
    lines.push(`- **Completed:** ${completedAgents.length}`);
    lines.push(`- **Failed:** ${failedAgents.length}`);
    lines.push('');
  }

  // === Retrospective (optional) ===
  if (include_retrospective && input.retrospective) {
    const retro = input.retrospective;
    const hasContent = (retro.inference_suggestions?.length ?? 0) > 0 ||
      retro.skill_gaps || retro.context_improvements || retro.trace_quality;

    if (hasContent) {
      lines.push('## Retrospective Findings');
      lines.push('');

      if (retro.context_improvements) {
        lines.push('### Context Improvements');
        lines.push('');
        for (const obs of retro.context_improvements.frontier_observations.slice(0, 3)) {
          lines.push(`- **${obs.area}:** ${obs.observation} (${obs.confidence} confidence)`);
        }
        for (const gap of retro.context_improvements.context_gaps.slice(0, 3)) {
          lines.push(`- **${gap.area}:** ${gap.gap} Recommendation: ${gap.recommendation}`);
        }
        lines.push('');
      }

      if (retro.inference_suggestions && retro.inference_suggestions.length > 0) {
        lines.push('### Inference Opportunities');
        lines.push('');
        for (const s of retro.inference_suggestions.slice(0, 3)) {
          lines.push(`- ${s.rule.name}: ${s.evidence}`);
        }
        lines.push('');
      }

      if (retro.skill_gaps) {
        lines.push('### Skill Gaps');
        lines.push('');
        if (retro.skill_gaps.missing_skills.length > 0) {
          lines.push(`- Missing coverage: ${retro.skill_gaps.missing_skills.slice(0, 5).join(', ')}`);
        }
        if (retro.skill_gaps.failed_techniques.length > 0) {
          lines.push(`- Failed techniques: ${retro.skill_gaps.failed_techniques.slice(0, 5).join(', ')}`);
        }
        lines.push('');
      }
    }
  }

  // === Executive Heatmap — Severity × Category ===
  if (findings.length > 0) {
    lines.push('## Risk Heatmap');
    lines.push('');
    const categories = [...new Set(findings.map(f => f.category))];
    const severities: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
    lines.push(`| Category | ${severities.join(' | ')} | Total |`);
    lines.push(`|----------|${severities.map(() => '------').join('|')}|-------|`);
    for (const cat of categories) {
      const row = severities.map(s => findings.filter(f => f.category === cat && f.severity === s).length);
      const total = row.reduce((a, b) => a + b, 0);
      lines.push(`| ${displayFindingCategory(cat)} | ${row.join(' | ')} | ${total} |`);
    }
    lines.push('');
  }

  // === Remediation Priority Ranking ===
  if (findings.length > 0) {
    const ranked = buildRemediationRanking(findings, graph);
    if (ranked.length > 0) {
      lines.push('## Remediation Priority Ranking');
      lines.push('');
      lines.push('Findings ranked by combined CVSS score, blast radius, and credential exposure.');
      lines.push('');
      lines.push('| # | Finding | CVSS | Blast Radius | Credential Exposure | Priority Score |');
      lines.push('|---|---------|------|-------------|-------------------|----------------|');
      for (let i = 0; i < ranked.length; i++) {
        const r = ranked[i];
        lines.push(`| ${i + 1} | ${escapeTableCell(r.title)} | ${r.cvss.toFixed(1)}${r.cvss_estimated ? '†' : ''} | ${r.blast_radius} | ${r.cred_exposure} | ${r.priority_score.toFixed(1)} |`);
      }
      lines.push('');
      lines.push('*† CVSS score estimated from engagement context*');
      lines.push('');
    }
  }

  // === Compliance Mapping ===
  if (include_compliance && findings.some(f => f.classification)) {
    lines.push('## Compliance Mapping');
    lines.push('');

    // CWE Table
    const cweFindngs = findings.filter(f => f.classification?.cwe);
    if (cweFindngs.length > 0) {
      lines.push('### CWE Classification');
      lines.push('');
      lines.push('| Finding | CWE | Name |');
      lines.push('|---------|-----|------|');
      for (const f of cweFindngs) {
        const title = report_profile === 'client' ? displayFindingShortTitle(f) : displayFindingTitle(f);
        lines.push(`| ${escapeTableCell(title)} | ${f.classification!.cwe} | ${escapeTableCell(f.classification!.cwe_name || '')} |`);
      }
      lines.push('');
    }

    // OWASP Top 10
    const owaspFindings = findings.filter(f => f.classification?.owasp_category);
    if (owaspFindings.length > 0) {
      lines.push('### OWASP Top 10 (2021) Mapping');
      lines.push('');
      const owaspGroups = new Map<string, string[]>();
      for (const f of owaspFindings) {
        const cat = f.classification!.owasp_category!;
        const group = owaspGroups.get(cat) || [];
        group.push(report_profile === 'client' ? displayFindingShortTitle(f) : displayFindingTitle(f));
        owaspGroups.set(cat, group);
      }
      lines.push('| OWASP Category | Findings |');
      lines.push('|----------------|----------|');
      for (const [cat, titles] of owaspGroups) {
        lines.push(`| ${escapeTableCell(cat)} | ${titles.length} finding(s) |`);
      }
      lines.push('');
    }

    // NIST 800-53
    const nistFindings = findings.filter(f => f.classification && f.classification.nist_controls.length > 0);
    if (nistFindings.length > 0) {
      lines.push('### NIST 800-53 Controls');
      lines.push('');
      const nistGroups = new Map<string, number>();
      for (const f of nistFindings) {
        for (const ctrl of f.classification!.nist_controls) {
          nistGroups.set(ctrl, (nistGroups.get(ctrl) || 0) + 1);
        }
      }
      lines.push('| Control | Findings |');
      lines.push('|---------|----------|');
      for (const [ctrl, count] of [...nistGroups.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20)) {
        lines.push(`| ${ctrl} | ${count} |`);
      }
      lines.push('');
    }

    // PCI DSS
    const pciFindings = findings.filter(f => f.classification && f.classification.pci_requirements.length > 0);
    if (pciFindings.length > 0) {
      lines.push('### PCI DSS v4.0 Requirements');
      lines.push('');
      const pciGroups = new Map<string, number>();
      for (const f of pciFindings) {
        for (const req of f.classification!.pci_requirements) {
          pciGroups.set(req, (pciGroups.get(req) || 0) + 1);
        }
      }
      lines.push('| Requirement | Findings |');
      lines.push('|-------------|----------|');
      for (const [req, count] of [...pciGroups.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20)) {
        lines.push(`| ${req} | ${count} |`);
      }
      lines.push('');
    }
  }

  // === ATT&CK Technique Coverage ===
  if (include_compliance && findings.some(f => f.classification && f.classification.attack_techniques.length > 0)) {
    lines.push('## MITRE ATT&CK Techniques');
    lines.push('');
    const allTechniques = new Map<string, { name: string; count: number }>();
    for (const f of findings) {
      if (!f.classification) continue;
      for (const t of f.classification.attack_techniques) {
        const existing = allTechniques.get(t.id);
        if (existing) {
          existing.count++;
        } else {
          allTechniques.set(t.id, { name: t.name, count: 1 });
        }
      }
    }
    lines.push('| Technique | Name | Findings |');
    lines.push('|-----------|------|----------|');
    for (const [id, { name, count }] of [...allTechniques.entries()].sort((a, b) => b[1].count - a[1].count)) {
      lines.push(`| ${id} | ${escapeTableCell(name)} | ${count} |`);
    }
    lines.push('');
  }

  // === ATT&CK Coverage Gap Analysis ===
  if (include_gap_analysis) {
    const profile = config.profile || config.template || 'red-team';
    const gapResult = computeGapAnalysis(findings, graph, profile);
    lines.push('## ATT&CK Coverage Gap Analysis');
    lines.push('');
    lines.push(`**Profile:** ${profile} | **Coverage:** ${gapResult.coverage_pct}% (${gapResult.tested_count}/${gapResult.total_in_scope} techniques)`);
    lines.push('');

    if (gapResult.gaps.length > 0) {
      lines.push('### Untested Techniques');
      lines.push('');
      lines.push('| Technique | Name | Suggested Action |');
      lines.push('|-----------|------|------------------|');
      for (const gap of gapResult.gaps) {
        lines.push(`| ${gap.technique_id} | ${escapeTableCell(gap.name)} | ${escapeTableCell(gap.suggested_action || '-')} |`);
      }
      lines.push('');
    } else {
      lines.push('All in-scope techniques were tested.');
      lines.push('');
    }
  }

  // === Activity Timeline ===
  lines.push('## Activity Timeline');
  lines.push('');
  lines.push('| Time | Event |');
  lines.push('|------|-------|');
  const timelineEntries = history.slice(-max_timeline_entries);
  for (const entry of timelineEntries) {
    const time = formatTimestamp(entry.timestamp);
    const agent = entry.agent_id ? ` [${entry.agent_id}]` : '';
    lines.push(`| ${time} | ${escapeTableCell(entry.description)}${agent} |`);
  }
  lines.push('');

  lines.push('---');
  lines.push(`*Generated by Overwatch at ${new Date().toISOString()}*`);
  lines.push('');

  return lines.join('\n');
}

// ============================================================
// Remediation Ranking
// ============================================================

interface RemediationRanking {
  title: string;
  cvss: number;
  cvss_estimated: boolean;
  blast_radius: number;
  cred_exposure: number;
  priority_score: number;
}

export function buildRemediationRanking(findings: ReportFinding[], graph: ExportedGraph): RemediationRanking[] {
  // Build adjacency for blast radius computation
  const adjacency = new Map<string, Set<string>>();
  for (const e of graph.edges) {
    if (!adjacency.has(e.source)) adjacency.set(e.source, new Set());
    if (!adjacency.has(e.target)) adjacency.set(e.target, new Set());
    adjacency.get(e.source)!.add(e.target);
    adjacency.get(e.target)!.add(e.source);
  }

  const nodeMap = new Map(graph.nodes.map(n => [n.id, n.properties]));

  // Reverse lookup: label/ip/hostname/url → node ID for blast radius resolution
  const assetToNodeId = new Map<string, string>();
  for (const n of graph.nodes) {
    assetToNodeId.set(n.id, n.id);
    if (n.properties.label) assetToNodeId.set(n.properties.label, n.id);
    if (n.properties.ip) assetToNodeId.set(n.properties.ip, n.id);
    if (n.properties.hostname) assetToNodeId.set(n.properties.hostname as string, n.id);
    if (n.properties.cred_user) assetToNodeId.set(n.properties.cred_user as string, n.id);
    if (n.properties.url) assetToNodeId.set(n.properties.url as string, n.id);
  }

  const ranked = findings.map(f => {
    const cvss = f.cvss_score ?? f.risk_score;
    const cvssEstimated = f.cvss_estimated ?? false;

    // Blast radius: count unique nodes within 2 hops of affected assets
    const reachable = new Set<string>();
    for (const assetId of f.affected_assets) {
      const nodeId = assetToNodeId.get(assetId);
      if (!nodeId) continue;
      const hop1 = adjacency.get(nodeId);
      if (hop1) {
        for (const h of hop1) {
          reachable.add(h);
          const hop2 = adjacency.get(h);
          if (hop2) for (const h2 of hop2) reachable.add(h2);
        }
      }
    }
    const blastRadius = Math.min(reachable.size, 100);

    // Credential exposure: count credential nodes reachable from affected assets
    let credExposure = 0;
    for (const nodeId of reachable) {
      const node = nodeMap.get(nodeId);
      if (node?.type === 'credential') credExposure++;
    }

    // Priority score: weighted combination (CVSS × 4 + blast_radius × 0.3 + cred_exposure × 1.5), capped at 100
    const priorityScore = Math.min(100, cvss * 4 + blastRadius * 0.3 + credExposure * 1.5);

    return {
      title: displayFindingShortTitle(f),
      cvss,
      cvss_estimated: cvssEstimated,
      blast_radius: blastRadius,
      cred_exposure: credExposure,
      priority_score: priorityScore,
    };
  });

  ranked.sort((a, b) => b.priority_score - a.priority_score);
  return ranked.slice(0, 20);
}

// ============================================================
// Remediation Generators
// ============================================================

function generateHostRemediation(host: NodeProperties, accessEdges: ExportedGraphEdge[], nodeMap: Map<string, NodeProperties>): string {
  const lines: string[] = [];

  const hasAdmin = accessEdges.some(e => e.properties.type === 'ADMIN_TO');
  const confirmedSessions = accessEdges.filter(e =>
    e.properties.type === 'HAS_SESSION' && (e.properties.confidence ?? 0) >= 0.7
  );
  const hasSession = confirmedSessions.length > 0;
  // P2.2: live-session check requires explicit session_live === true.
  // Imported (BloodHound) and historical edges without an affirmative flag
  // do not count as live access for remediation framing.
  const hasLiveSession = confirmedSessions.some(e => e.properties.session_live === true);

  if (hasLiveSession) {
    lines.push(`1. **Revoke all active sessions** on ${host.label || host.ip || host.id} and force re-authentication.`);
  } else if (hasSession) {
    lines.push(`1. **Review historical sessions** on ${host.label || host.ip || host.id} — no sessions are currently active, but past access was confirmed.`);
  } else {
    lines.push(`1. **Force re-authentication** on ${host.label || host.ip || host.id}.`);
  }

  if (hasAdmin) {
    lines.push('2. **Reset local administrator credentials** and review local admin group membership.');
  }
  if (hasSession) {
    const sessionSources = confirmedSessions
      .map(e => nodeMap.get(e.source)?.label || e.source);
    lines.push(`${hasAdmin ? '3' : '2'}. **Reset credentials** for principals with sessions: ${sessionSources.join(', ')}.`);
  }

  lines.push(`${lines.length + 1}. **Review access logs** for this host for signs of data exfiltration or persistence.`);

  if (host.os?.toLowerCase().includes('windows')) {
    lines.push(`${lines.length + 1}. **Check for persistence mechanisms** (scheduled tasks, services, registry run keys).`);
  } else if (host.os?.toLowerCase().includes('linux')) {
    lines.push(`${lines.length + 1}. **Check for persistence mechanisms** (cron jobs, SSH authorized_keys, systemd services).`);
  }

  return lines.join('\n');
}

function generateAccessPathRemediation(host: NodeProperties, principal?: NodeProperties): string {
  const hostLabel = host.label || host.ip || host.id;
  const principalLabel = principal?.label || principal?.id || 'the privileged principal';
  return [
    `1. **Review and reduce administrative membership** granting ${principalLabel} access to ${hostLabel}.`,
    '2. **Validate whether the access path is required** for business operations and remove stale delegated rights.',
    '3. **Monitor for logon attempts** using this path until access has been remediated.',
  ].join('\n');
}

function generateCredentialRemediation(cred: NodeProperties): string {
  const lines: string[] = [];
  const kind = getCredentialDisplayKind(cred);
  const user = cred.cred_user || 'the affected user';

  lines.push(`1. **Immediately rotate** the ${kind} credential for ${user}.`);

  if (cred.cred_domain) {
    lines.push(`2. **Check for lateral movement** — this domain credential (${cred.cred_domain}) may have been used across multiple hosts.`);
  }

  if (cred.privileged) {
    lines.push(`${lines.length + 1}. **Review privileged access** — this is a privileged credential. Audit all actions taken with this account.`);
    lines.push(`${lines.length + 1}. **Implement tiered administration** to prevent privileged credential exposure on standard workstations.`);
  }

  if (kind === 'ntlm_hash' || kind === 'aes256_key') {
    lines.push(`${lines.length + 1}. **Enable pass-the-hash mitigations** — consider Credential Guard, Protected Users group, and restricted admin mode.`);
  }

  if (kind === 'plaintext_password') {
    lines.push(`${lines.length + 1}. **Enforce password complexity** and check if this password is reused across other accounts.`);
  }

  return lines.join('\n');
}

function generateVulnerabilityRemediation(vuln: NodeProperties, affectedAssets: string[]): string {
  const lines: string[] = [];

  if (vuln.cve) {
    lines.push(`1. **Patch ${vuln.cve}** on affected systems: ${affectedAssets.slice(0, 5).join(', ')}${affectedAssets.length > 5 ? ` (+${affectedAssets.length - 5} more)` : ''}.`);
  } else {
    lines.push(`1. **Remediate ${vuln.vuln_type || 'vulnerability'}** on affected systems: ${affectedAssets.slice(0, 5).join(', ')}.`);
  }

  if (vuln.affected_component) {
    lines.push(`2. **Update or disable** the affected component: ${vuln.affected_component}.`);
  }

  if (vuln.exploitable) {
    lines.push(`${lines.length + 1}. **Prioritize this fix** — the vulnerability was confirmed as exploitable during the assessment.`);
  }

  if (vuln.vuln_type === 'ssrf') {
    lines.push(`${lines.length + 1}. **Implement SSRF protections** — restrict outbound requests, enforce IMDSv2 on cloud instances, validate URLs server-side.`);
  } else if (vuln.vuln_type === 'sqli') {
    lines.push(`${lines.length + 1}. **Use parameterized queries** and input validation to prevent SQL injection.`);
  } else if (vuln.vuln_type === 'xss') {
    lines.push(`${lines.length + 1}. **Implement output encoding** and Content Security Policy headers.`);
  }

  lines.push(`${lines.length + 1}. **Verify the fix** by retesting with the same tools used during the assessment.`);

  return lines.join('\n');
}

function generateCloudIdentityRemediation(identity: NodeProperties, policyNames: string[]): string {
  const lines: string[] = [];
  const label = identity.label || identity.id;
  const isAdmin = policyNames.some(p => /administrator|admin|fullaccess|\*/i.test(p));

  lines.push(`1. **Review permissions** for ${label} and apply least-privilege.`);
  if (isAdmin) {
    lines.push('2. **Remove or scope down administrative policies** — broad admin access enables full account takeover.');
  }
  if (policyNames.length > 0) {
    lines.push(`${lines.length + 1}. **Audit attached policies:** ${policyNames.slice(0, 5).join(', ')}.`);
  }
  lines.push(`${lines.length + 1}. **Enable MFA** on this identity if not already enforced.`);
  lines.push(`${lines.length + 1}. **Rotate credentials** (access keys, passwords) for this identity.`);

  return lines.join('\n');
}

function generateCloudResourceRemediation(resource: NodeProperties): string {
  const lines: string[] = [];
  const label = resource.label || resource.id;
  const isPublic = resource.public === true;

  if (isPublic) {
    lines.push(`1. **Restrict public access** to ${label} — configure private access or VPC endpoints.`);
  }
  if (resource.resource_type === 's3_bucket') {
    lines.push(`${lines.length + 1}. **Enable S3 Block Public Access** at account and bucket level.`);
    lines.push(`${lines.length + 1}. **Review bucket policy and ACLs** for overly permissive grants.`);
  } else if (resource.resource_type === 'ec2') {
    lines.push(`${lines.length + 1}. **Review security groups** — restrict inbound access to required ports and sources.`);
    if (!resource.imdsv2_required) {
      lines.push(`${lines.length + 1}. **Enforce IMDSv2** to prevent SSRF-based credential theft.`);
    }
  }
  lines.push(`${lines.length + 1}. **Enable logging and monitoring** (CloudTrail, GuardDuty) for this resource.`);

  return lines.join('\n');
}

function generateWebappRemediation(webapp: NodeProperties, vulnLabels: string[]): string {
  const lines: string[] = [];
  const url = webapp.url || webapp.label || webapp.id;

  if (vulnLabels.length > 0) {
    lines.push(`1. **Fix identified vulnerabilities** in ${url}: ${vulnLabels.slice(0, 5).join(', ')}.`);
  }
  if (webapp.has_login_form) {
    lines.push(`${lines.length + 1}. **Harden authentication** — enforce MFA, rate limiting, and account lockout.`);
  }
  lines.push(`${lines.length + 1}. **Deploy a WAF** and ensure security headers (CSP, HSTS, X-Frame-Options).`);
  lines.push(`${lines.length + 1}. **Conduct code review** for the identified vulnerability classes.`);

  return lines.join('\n');
}

// ============================================================
// Helpers
// ============================================================

function cvssToSeverity(cvss?: number): FindingSeverity {
  if (cvss === undefined || cvss === null) return 'medium';
  if (cvss >= 9.0) return 'critical';
  if (cvss >= 7.0) return 'high';
  if (cvss >= 4.0) return 'medium';
  if (cvss >= 0.1) return 'low';
  return 'info';
}

function severityBadge(severity: FindingSeverity): string {
  switch (severity) {
    case 'critical': return 'Critical';
    case 'high': return 'High';
    case 'medium': return 'Medium';
    case 'low': return 'Low';
    case 'info': return 'Info';
  }
}

function computeHostRiskScore(accessEdges: ExportedGraphEdge[], hopsToObjective: number | null): number {
  let score = 5.0;
  if (accessEdges.some(e => e.properties.type === 'ADMIN_TO')) score += 3.0;
  // Only count confirmed sessions (confidence >= 0.7) for risk scoring
  if (accessEdges.some(e => e.properties.type === 'HAS_SESSION' && (e.properties.confidence ?? 0) >= 0.7)) score += 1.5;
  if (hopsToObjective !== null && hopsToObjective <= 2) score += 1.0;
  return Math.min(10, score);
}

function computeHopsToObjective(nodeId: string, graph: ExportedGraph, _config: EngagementConfig): number | null {
  // Simple BFS from node to any objective node
  const objectiveNodeIds = new Set<string>();
  for (const n of graph.nodes) {
    if (n.properties.type === 'objective') objectiveNodeIds.add(n.id);
  }
  if (objectiveNodeIds.size === 0) return null;

  const adjacency = new Map<string, string[]>();
  for (const e of graph.edges) {
    if (!adjacency.has(e.source)) adjacency.set(e.source, []);
    if (!adjacency.has(e.target)) adjacency.set(e.target, []);
    adjacency.get(e.source)!.push(e.target);
    adjacency.get(e.target)!.push(e.source);
  }

  const visited = new Set<string>();
  const queue: Array<{ id: string; depth: number }> = [{ id: nodeId, depth: 0 }];
  visited.add(nodeId);

  while (queue.length > 0) {
    const { id, depth } = queue.shift()!;
    if (objectiveNodeIds.has(id)) return depth;
    if (depth >= 10) continue; // cap search depth

    for (const neighbor of adjacency.get(id) || []) {
      if (!visited.has(neighbor)) {
        visited.add(neighbor);
        queue.push({ id: neighbor, depth: depth + 1 });
      }
    }
  }

  return null;
}

function groupByActionId(entries: ActivityLogEntry[]): Map<string, ActivityLogEntry[]> {
  const grouped = new Map<string, ActivityLogEntry[]>();
  for (const entry of entries) {
    if (!entry.action_id) continue;
    const existing = grouped.get(entry.action_id) || [];
    existing.push(entry);
    grouped.set(entry.action_id, existing);
  }
  return grouped;
}

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
  } catch {
    return ts;
  }
}

function escapeTableCell(text: string | undefined): string {
  if (!text) return '';
  return text.replace(/\|/g, '\\|').replace(/\n/g, ' ').replace(/`/g, '\\`');
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
