// ============================================================
// Overwatch — Pentest Report Generator
// Produces client-deliverable reports with per-finding sections,
// attack narrative, evidence chains, and auto-remediation.
// ============================================================

import type {
  EngagementConfig, NodeProperties, EdgeType,
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

// ============================================================
// Types
// ============================================================

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface ReportFinding {
  id: string;
  title: string;
  severity: FindingSeverity;
  category: 'compromised_host' | 'credential' | 'vulnerability' | 'access_path' | 'cloud_exposure' | 'webapp';
  description: string;
  affected_assets: string[];
  evidence: EvidenceChain[];
  remediation: string;
  risk_score: number; // 0-10
  classification?: FindingClassification;
  cvss_vector?: string;
  cvss_score?: number;
  cvss_estimated?: boolean;
}

export interface EvidenceChain {
  claim: string;
  action_id?: string;
  tool?: string;
  technique?: string;
  timestamp?: string;
  source_nodes: string[];
  target_nodes: string[];
  linked_findings?: string[];
  evidence_type?: string;
  evidence_content?: string;
  evidence_filename?: string;
  raw_output?: string;
}

export interface NarrativePhase {
  name: string;
  start_time?: string;
  end_time?: string;
  paragraphs: string[];
}

export interface ReportOptions {
  include_evidence?: boolean;
  include_narrative?: boolean;
  include_retrospective?: boolean;
  include_compliance?: boolean;
  include_attack_navigator?: boolean;
  include_gap_analysis?: boolean;
  max_timeline_entries?: number;
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
}

// ============================================================
// Constants
// ============================================================

const ACCESS_EDGES = new Set<EdgeType>(['HAS_SESSION', 'ADMIN_TO', 'OWNS_CRED']);

// ============================================================
// Per-Finding Sections
// ============================================================

export function buildFindings(graph: ExportedGraph, history: ActivityLogEntry[], config: EngagementConfig): ReportFinding[] {
  const findings: ReportFinding[] = [];
  const nodeMap = new Map<string, NodeProperties>();
  for (const n of graph.nodes) nodeMap.set(n.id, n.properties);

  // 1. Compromised hosts
  for (const n of graph.nodes) {
    if (n.properties.type !== 'host') continue;
    const accessEdges = graph.edges.filter(e =>
      e.target === n.id && ACCESS_EDGES.has(e.properties.type) && e.properties.confidence >= 0.9
      // HAS_SESSION edges with session_live:false are historical — exclude from
      // compromise determination.  Edges without session_live (pre-existing data)
      // still pass (backward compat: !== false, not === true).
      && !(e.properties.type === 'HAS_SESSION' && e.properties.session_live === false)
    );
    if (accessEdges.length === 0) continue;

    const accessMethods = accessEdges.map(e => {
      const src = nodeMap.get(e.source);
      return `${e.properties.type} from ${src?.label || e.source}`;
    });
    const evidence = buildEvidenceChainsForNode(n.id, graph, history);
    const hopsToObj = computeHopsToObjective(n.id, graph, config);

    findings.push({
      id: `finding-host-${n.id}`,
      title: `Compromised Host: ${n.properties.label || n.properties.ip || n.id}`,
      severity: accessEdges.some(e => e.properties.type === 'ADMIN_TO') ? 'critical' : 'high',
      category: 'compromised_host',
      description: `Host ${n.properties.label || n.id} was compromised via: ${accessMethods.join('; ')}. ` +
        `OS: ${n.properties.os || 'unknown'}. ` +
        (n.properties.domain_joined ? 'Domain-joined.' : ''),
      affected_assets: [n.properties.label || n.id],
      evidence,
      remediation: generateHostRemediation(n.properties, accessEdges, nodeMap),
      risk_score: computeHostRiskScore(accessEdges, hopsToObj),
    });
  }

  // 2. Credentials obtained
  for (const n of graph.nodes) {
    if (n.properties.type !== 'credential') continue;
    if (n.properties.confidence < 0.9 || !isCredentialUsableForAuth(n.properties)) continue;

    const evidence = buildEvidenceChainsForNode(n.id, graph, history);
    const validOnEdges = graph.edges.filter(e =>
      e.source === n.id && (e.properties.type === 'VALID_ON' || e.properties.type === 'POTENTIAL_AUTH')
    );
    const targetHosts = validOnEdges.map(e => nodeMap.get(e.target)?.label || e.target);

    findings.push({
      id: `finding-cred-${n.id}`,
      title: `Credential Obtained: ${n.properties.cred_user || n.properties.label || n.id}`,
      severity: n.properties.privileged ? 'critical' : 'high',
      category: 'credential',
      description: `${getCredentialDisplayKind(n.properties)} credential for ${n.properties.cred_user || 'unknown user'}` +
        (n.properties.cred_domain ? ` (domain: ${n.properties.cred_domain})` : '') +
        `. Valid on ${targetHosts.length} service(s): ${targetHosts.slice(0, 5).join(', ')}` +
        (targetHosts.length > 5 ? `, +${targetHosts.length - 5} more` : '') + '.',
      affected_assets: [n.properties.cred_user || n.properties.label || n.id, ...targetHosts.slice(0, 5)],
      evidence,
      remediation: generateCredentialRemediation(n.properties),
      risk_score: n.properties.privileged ? 9.5 : 7.0,
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
    const evidence = buildEvidenceChainsForNode(n.id, graph, history);

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
      const evidence = buildEvidenceChainsForNode(n.id, graph, history);

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

      const evidence = buildEvidenceChainsForNode(n.id, graph, history);

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
    const evidence = buildEvidenceChainsForNode(n.id, graph, history);
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
): EvidenceChain[] {
  const chains: EvidenceChain[] = [];

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

  for (const [actionId, entries] of byAction) {
    const first = entries[0];

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
    for (const entry of entries) {
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

    const chain: EvidenceChain = {
      claim: first.description,
      action_id: actionId,
      tool: first.tool_name,
      technique: first.technique,
      timestamp: first.timestamp,
      source_nodes: entries.flatMap(e => e.target_node_ids || []).filter(id => id !== nodeId),
      target_nodes: [nodeId],
      linked_findings: entries.flatMap(e => e.linked_finding_ids || []),
    };
    if (d?.evidence_type) chain.evidence_type = d.evidence_type as string;
    if (d?.evidence_content) chain.evidence_content = d.evidence_content as string;
    if (d?.evidence_filename) chain.evidence_filename = d.evidence_filename as string;
    if (d?.raw_output) chain.raw_output = d.raw_output as string;
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
      source_nodes: [edge.source],
      target_nodes: [edge.target],
    });
  }

  return chains;
}

export function buildAllEvidenceChains(
  graph: ExportedGraph,
  history: ActivityLogEntry[],
): Map<string, EvidenceChain[]> {
  const result = new Map<string, EvidenceChain[]>();

  const interestingTypes = new Set([
    'host', 'credential', 'vulnerability',
    'cloud_identity', 'cloud_resource', 'webapp',
  ]);
  const interestingNodes = graph.nodes.filter(n => interestingTypes.has(n.properties.type));
  for (const n of interestingNodes) {
    const chains = buildEvidenceChainsForNode(n.id, graph, history);
    if (chains.length > 0) {
      result.set(n.id, chains);
    }
  }

  return result;
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
  const paragraphs: string[] = [];

  // Group by action_id for structured narrative
  const grouped = groupByActionId(entries);
  const ungrouped = entries.filter(e => !e.action_id);

  // Build sentences from action clusters
  const sentences: string[] = [];
  for (const [_actionId, cluster] of grouped) {
    const first = cluster[0];
    const tool = first.tool_name;
    const targets = first.target_node_ids?.map(id => nodeMap.get(id)?.label || id) || [];
    const targetIps = first.target_ips || [];
    const allTargets = [...new Set([...targets, ...targetIps])];
    const result = cluster.find(e => e.event_type === 'action_completed' || e.event_type === 'action_failed');
    const outcome = result?.result_classification || result?.outcome;

    let sentence = '';
    if (tool) {
      sentence = `Used ${tool}`;
      if (first.technique) sentence += ` (${first.technique})`;
      if (allTargets.length > 0) sentence += ` against ${allTargets.slice(0, 3).join(', ')}`;
      if (outcome === 'success') sentence += ' — successful';
      else if (outcome === 'failure') sentence += ' — failed';
      sentence += '.';
    } else {
      sentence = first.description;
      if (!sentence.endsWith('.')) sentence += '.';
    }
    sentences.push(sentence);
  }

  // Add ungrouped entries as simple sentences
  for (const entry of ungrouped.slice(0, 10)) {
    let desc = entry.description;
    if (!desc.endsWith('.')) desc += '.';
    sentences.push(desc);
  }

  // Group sentences into paragraphs (max ~5 sentences each)
  for (let i = 0; i < sentences.length; i += 5) {
    paragraphs.push(sentences.slice(i, i + 5).join(' '));
  }

  if (paragraphs.length === 0) {
    paragraphs.push(`${capitalize(phase)} phase: ${entries.length} activities recorded.`);
  }

  return paragraphs;
}

// ============================================================
// Full Markdown Report
// ============================================================

export function generateFullReport(input: ReportInput, options: ReportOptions = {}): string {
  const {
    include_evidence = true,
    include_narrative = true,
    include_retrospective = true,
    include_compliance = true,
    include_gap_analysis = false,
    max_timeline_entries = 50,
  } = options;

  const config = input.config;
  const graph = input.graph;
  const history = input.history;

  const findings = buildFindings(graph, history, config);
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
    if (e.properties.confidence >= 1.0) confirmedEdges++;
    else inferredEdges++;
  }

  const objectivesAchieved = config.objectives.filter(o => o.achieved);
  const objectivesPending = config.objectives.filter(o => !o.achieved);
  const startTime = history.length > 0 ? history[0].timestamp : config.created_at;
  const endTime = history.length > 0 ? history[history.length - 1].timestamp : config.created_at;

  const criticalFindings = findings.filter(f => f.severity === 'critical');
  const highFindings = findings.filter(f => f.severity === 'high');
  const mediumFindings = findings.filter(f => f.severity === 'medium');
  const lowFindings = findings.filter(f => f.severity === 'low');
  const infoFindings = findings.filter(f => f.severity === 'info');

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
  lines.push('4. [Detailed Findings](#detailed-findings)');
  if (include_narrative && narrative.length > 0) {
    lines.push('5. [Attack Narrative](#attack-narrative)');
  }
  lines.push(`${include_narrative && narrative.length > 0 ? '6' : '5'}. [Objectives](#objectives)`);
  lines.push(`${include_narrative && narrative.length > 0 ? '7' : '6'}. [Recommendations](#recommendations)`);
  lines.push('');

  // === Executive Summary ===
  lines.push('## Executive Summary');
  lines.push('');
  lines.push(`This penetration test targeted ${config.scope.cidrs.length} CIDR range(s)` +
    (config.scope.domains.length > 0 ? ` and ${config.scope.domains.length} domain(s)` : '') + '. ' +
    `${objectivesAchieved.length} of ${config.objectives.length} objective(s) were achieved. ` +
    `The assessment identified **${findings.length} finding(s)**: ` +
    `${criticalFindings.length} Critical, ${highFindings.length} High, ${mediumFindings.length} Medium, ` +
    `${lowFindings.length} Low, ${infoFindings.length} Informational.`);
  lines.push('');
  lines.push(`The engagement discovered ${graph.nodes.length} nodes and ${graph.edges.length} relationships ` +
    `across the target environment (${confirmedEdges} confirmed, ${inferredEdges} inferred).`);
  lines.push('');

  // Severity distribution table
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  lines.push(`| Critical | ${criticalFindings.length} |`);
  lines.push(`| High | ${highFindings.length} |`);
  lines.push(`| Medium | ${mediumFindings.length} |`);
  lines.push(`| Low | ${lowFindings.length} |`);
  lines.push(`| Info | ${infoFindings.length} |`);
  lines.push('');

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
      lines.push(`| ${i + 1} | ${severityBadge(f.severity)} | ${escapeTableCell(f.title)} | ${f.risk_score.toFixed(1)} |`);
    });
    lines.push('');
  }

  // === Detailed Findings ===
  lines.push('## Detailed Findings');
  lines.push('');

  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    lines.push(`### ${i + 1}. ${f.title}`);
    lines.push('');
    lines.push(`**Severity:** ${severityBadge(f.severity)} | **Risk Score:** ${f.risk_score.toFixed(1)} | **Category:** ${f.category}`);
    lines.push('');
    lines.push('#### Description');
    lines.push('');
    lines.push(f.description);
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

    if (include_evidence && f.evidence.length > 0) {
      lines.push('#### Evidence');
      lines.push('');
      for (const ev of f.evidence.slice(0, 5)) {
        let evLine = `- ${ev.claim}`;
        if (ev.tool) evLine += ` (tool: ${ev.tool})`;
        if (ev.timestamp) evLine += ` — ${formatTimestamp(ev.timestamp)}`;
        if (ev.action_id) evLine += ` [action: ${ev.action_id.slice(0, 8)}]`;
        lines.push(evLine);
        if (ev.evidence_filename) {
          lines.push(`  - Attachment: ${ev.evidence_filename} (${ev.evidence_type})`);
        }
        if (ev.evidence_content) {
          lines.push('  ```');
          for (const cl of ev.evidence_content.slice(0, 2048).split('\n').slice(0, 30)) {
            lines.push(`  ${cl}`);
          }
          lines.push('  ```');
        }
        if (ev.raw_output) {
          lines.push('  <details><summary>Raw output (truncated)</summary>');
          lines.push('');
          lines.push('  ```');
          for (const rl of ev.raw_output.slice(0, 2048).split('\n').slice(0, 30)) {
            lines.push(`  ${rl}`);
          }
          lines.push('  ```');
          lines.push('  </details>');
        }
      }
      if (f.evidence.length > 5) {
        lines.push(`- ... and ${f.evidence.length - 5} more evidence entries`);
      }
      lines.push('');
    }

    lines.push('#### Remediation');
    lines.push('');
    lines.push(f.remediation);
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
      lines.push(`| ${cat} | ${row.join(' | ')} | ${total} |`);
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
        lines.push(`| ${escapeTableCell(f.title)} | ${f.classification!.cwe} | ${escapeTableCell(f.classification!.cwe_name || '')} |`);
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
        group.push(f.title);
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

  // === Recommendations ===
  lines.push('## Recommendations');
  lines.push('');

  // Auto-generate from findings
  const remediationsByPriority = findings
    .filter(f => f.severity === 'critical' || f.severity === 'high')
    .slice(0, 10);

  if (remediationsByPriority.length > 0) {
    lines.push('### Immediate Actions');
    lines.push('');
    for (const f of remediationsByPriority) {
      lines.push(`- **${f.title}:** ${f.remediation.split('\n')[0]}`);
    }
    lines.push('');
  }

  const untestedInferred = graph.edges.filter(e => e.properties.confidence < 1.0 && !e.properties.tested);
  if (untestedInferred.length > 0) {
    lines.push(`- **${untestedInferred.length} inferred edge(s) remain untested** — these represent potential attack paths not validated during the engagement.`);
  }
  if (objectivesPending.length > 0) {
    lines.push(`- **${objectivesPending.length} objective(s) not achieved** — ${objectivesPending.map(o => o.description).join(', ')}.`);
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

  const ranked = findings.map(f => {
    const cvss = f.cvss_score ?? f.risk_score;
    const cvssEstimated = f.cvss_estimated ?? false;

    // Blast radius: count unique nodes within 2 hops of affected assets
    const reachable = new Set<string>();
    for (const assetId of f.affected_assets) {
      // Find node ID matching the asset label
      const nodeId = graph.nodes.find(n =>
        n.properties.label === assetId || n.id === assetId
      )?.id;
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
      title: f.title,
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
  const hasLiveSession = confirmedSessions.some(e => e.properties.session_live !== false);

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
