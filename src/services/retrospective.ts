// ============================================================
// Overwatch — Retrospective Analyzer
// Post-engagement analysis producing structured outputs
// ============================================================

import type {
  EngagementConfig, NodeProperties, EdgeProperties, EdgeType, NodeType, ExportedGraph,
  InferenceRule, AgentTask, InferenceRuleSuggestion,
  SkillGapReport, ContextImprovementReport, RLVRTrace, RetrospectiveResult,
  LoggingQualityReport, TraceQualityReport, AnalysisConfidence,
} from '../types.js';
import type { ActivityLogEntry } from './engine-context.js';
import { getCredentialDisplayKind, isCredentialUsableForAuth } from './credential-utils.js';
import { validateEdgeEndpoints } from './graph-schema.js';
import { getNodeFirstSeenAt } from './provenance-utils.js';

export interface RetrospectiveInput {
  config: EngagementConfig;
  graph: ExportedGraph;
  history: ActivityLogEntry[];
  inferenceRules: InferenceRule[];
  agents: AgentTask[];
  skillNames: string[];
  skillTags?: string[];
}

// ============================================================
// Inference Gap Analysis
// ============================================================

export function analyzeInferenceGaps(input: RetrospectiveInput): InferenceRuleSuggestion[] {
  const suggestions: InferenceRuleSuggestion[] = [];

  // 1. Find manually-reported edge patterns that could be rules
  //    Group edges by (source_type, target_type, edge_type) and find patterns
  //    that appear 3+ times but aren't covered by existing rules.
  const edgePatterns = new Map<string, { count: number; sourceType: string; targetType: string; edgeType: EdgeType }>();
  const nodeMap = new Map<string, NodeProperties>();
  for (const n of input.graph.nodes) {
    nodeMap.set(n.id, n.properties);
  }

  for (const e of input.graph.edges) {
    const sourceNode = nodeMap.get(e.source);
    const targetNode = nodeMap.get(e.target);
    if (!sourceNode || !targetNode) continue;

    const key = `${sourceNode.type}→${e.properties.type}→${targetNode.type}`;
    const existing = edgePatterns.get(key);
    if (existing) {
      existing.count++;
    } else {
      edgePatterns.set(key, {
        count: 1,
        sourceType: sourceNode.type,
        targetType: targetNode.type,
        edgeType: e.properties.type,
      });
    }
  }

  // Check which patterns aren't covered by existing rules
  const coveredEdgeTypes = new Set(
    input.inferenceRules.flatMap(r => r.produces.map(p => p.edge_type))
  );

  // Map node types to inference engine selectors
  const typeToSourceSelector: Record<string, string> = {
    host: 'parent_host',
    domain: 'domain_nodes',
    user: 'domain_users',
    credential: 'domain_credentials',
  };

  for (const [key, pattern] of edgePatterns) {
    if (pattern.count >= 3 && !coveredEdgeTypes.has(pattern.edgeType)) {
      // Skip same-type patterns — they'd produce self-loops that the engine drops
      if (pattern.sourceType === pattern.targetType) continue;

      const schemaCheck = validateEdgeEndpoints(
        pattern.edgeType,
        pattern.sourceType as NodeType,
        pattern.targetType as NodeType,
        {
          source_id: `suggested-${pattern.sourceType}`,
          target_id: `suggested-${pattern.targetType}`,
        },
      );
      if (!schemaCheck.valid) continue;

      const sourceSelector = typeToSourceSelector[pattern.sourceType];
      // Skip if we can't map the source type to a valid selector
      if (!sourceSelector) continue;

      suggestions.push({
        rule: {
          id: `suggested-${pattern.edgeType.toLowerCase()}-${pattern.sourceType}-${pattern.targetType}`,
          name: `Auto-infer ${pattern.edgeType} from ${pattern.sourceType} to ${pattern.targetType}`,
          description: `Pattern observed ${pattern.count} times: ${pattern.sourceType} nodes frequently have ${pattern.edgeType} edges to ${pattern.targetType} nodes`,
          trigger: { node_type: pattern.targetType as NodeType },
          produces: [{
            edge_type: pattern.edgeType,
            source_selector: sourceSelector,
            target_selector: 'trigger_node',
            confidence: 0.6,
          }],
        },
        evidence: `${key} appeared ${pattern.count} times with no covering inference rule`,
        occurrences: pattern.count,
      });
    }
  }

  // 2. Check which inferred edges were confirmed (validates existing rules)
  //    Uses edge properties: inferred_by_rule (set when inference creates an edge)
  //    and confirmed_at (set when a confirmed finding merges into the inferred edge).
  const inferredEdges = input.graph.edges.filter(e => e.properties.inferred_by_rule);
  const confirmedEdges = inferredEdges.filter(e => e.properties.confirmed_at);

  // Per-rule confirmation rates
  const ruleStats = new Map<string, { total: number; confirmed: number }>();
  for (const e of inferredEdges) {
    const ruleId = e.properties.inferred_by_rule!;
    const stats = ruleStats.get(ruleId) || { total: 0, confirmed: 0 };
    stats.total++;
    if (e.properties.confirmed_at) stats.confirmed++;
    ruleStats.set(ruleId, stats);
  }

  // Flag individual low-performing rules
  for (const [ruleId, stats] of ruleStats) {
    if (stats.total >= 3) {
      const rate = stats.confirmed / stats.total;
      if (rate < 0.1) {
        suggestions.push({
          rule: {
            id: `suggested-review-${ruleId}`,
            name: `Review low-performing rule: ${ruleId}`,
            description: `Only ${(rate * 100).toFixed(0)}% of edges from rule '${ruleId}' were confirmed (${stats.confirmed}/${stats.total}). Consider raising its confidence threshold or removing it.`,
            trigger: {},
            produces: [],
          },
          evidence: `${stats.confirmed}/${stats.total} inferred edges confirmed for rule ${ruleId}`,
          occurrences: stats.total,
        });
      }
    }
  }

  // Global meta-suggestion if overall confirmation is low
  if (inferredEdges.length >= 5) {
    const globalRate = confirmedEdges.length / inferredEdges.length;
    if (globalRate < 0.1) {
      suggestions.push({
        rule: {
          id: 'suggested-review-low-confidence',
          name: 'Review low-performing inference rules',
          description: `Only ${(globalRate * 100).toFixed(0)}% of inferred edges were confirmed overall. Consider raising confidence thresholds or removing noisy rules.`,
          trigger: {},
          produces: [],
        },
        evidence: `${confirmedEdges.length}/${inferredEdges.length} inferred edges confirmed`,
        occurrences: inferredEdges.length,
      });
    }
  }

  return suggestions;
}

// ============================================================
// Skill Gap Analysis
// ============================================================

export function analyzeSkillGaps(input: RetrospectiveInput): SkillGapReport {
  const usageCounts: Record<string, number> = {};
  const mentionedTechniques = new Set<string>();
  const normalizeToken = (value: string): string => value.trim().toLowerCase().replace(/\s+/g, '-');

  // Tool-name keywords (not techniques — these are executables that won't appear in skill tags)
  const TOOL_KEYWORDS = [
    'nmap', 'nxc', 'netexec', 'certipy', 'impacket', 'secretsdump',
    'mimikatz', 'rubeus', 'seatbelt', 'snaffler', 'hashcat', 'john',
    'gobuster', 'feroxbuster', 'responder', 'bloodhound',
  ];

  // Build keyword set: skill tags (dynamic) + tool names (static fallback)
  const TECHNIQUE_KEYWORDS: string[] = [...TOOL_KEYWORDS];
  if (input.skillTags && input.skillTags.length > 0) {
    for (const tag of input.skillTags) {
      const t = tag.trim().toLowerCase();
      if (t.length > 2 && !TECHNIQUE_KEYWORDS.includes(t)) {
        TECHNIQUE_KEYWORDS.push(t);
      }
    }
  } else {
    // Fallback: hard-coded technique terms when no skill tags are provided
    TECHNIQUE_KEYWORDS.push(
      'kerberoast', 'asreproast', 'relay',
      'smb', 'ldap', 'rdp', 'winrm', 'psremote', 'dcsync',
      'sql injection', 'sqli', 'xss',
      'privesc', 'privilege escalation', 'lateral movement',
      'password spray', 'brute force', 'credential dump',
      'adcs', 'esc1', 'esc2', 'esc3', 'esc4', 'esc6', 'esc8',
      'delegation', 'unconstrained', 'constrained',
      'pivoting', 'port forward', 'tunnel', 'socks',
      'dns', 'snmp', 'exchange', 'sccm',
      'aws', 'azure', 'gcp', 'cloud',
      'persistence', 'exfiltration',
    );
  }

  // Parse history for skill/technique mentions
  for (const entry of input.history) {
    const desc = entry.description.toLowerCase();

    // Check for get_skill calls
    const skillMatch = desc.match(/skill.*?[:\s]+([a-z][a-z0-9\s-]+)/i);
    if (skillMatch) {
      const skill = skillMatch[1].trim();
      usageCounts[skill] = (usageCounts[skill] || 0) + 1;
    }

    // Check for technique keywords
    for (const kw of TECHNIQUE_KEYWORDS) {
      if (desc.includes(kw)) {
        mentionedTechniques.add(kw);
      }
    }
  }

  // Also check agent tasks for skill references
  for (const agent of input.agents) {
    if (agent.skill) {
      usageCounts[agent.skill] = (usageCounts[agent.skill] || 0) + 1;
    }
  }

  // Normalize skill names for comparison (strip extension, lowercase, replace spaces with hyphens)
  const normalizedSkillNames = new Set(
    input.skillNames.map(s => normalizeToken(s.replace(/\.md$/, '')))
  );
  const normalizedSkillTags = new Set((input.skillTags || []).map(normalizeToken));

  // Skills in library but never referenced
  const unusedSkills = input.skillNames
    .filter(s => {
      const normalized = normalizeToken(s.replace(/\.md$/, ''));
      return !usageCounts[normalized] && !usageCounts[s];
    });

  // Techniques mentioned in engagement but no matching skill
  const missingSkills: string[] = [];
  for (const technique of mentionedTechniques) {
    const normalizedTechnique = normalizeToken(technique);
    const matchesSkill = [...normalizedSkillNames, ...normalizedSkillTags].some(s =>
      s.includes(normalizedTechnique) || normalizedTechnique.includes(s)
    );
    if (!matchesSkill) {
      missingSkills.push(technique);
    }
  }

  // Failed techniques — look for "failed", "error", "denied" in history
  const failedTechniques: string[] = [];
  for (const entry of input.history) {
    const desc = entry.description.toLowerCase();
    if (desc.includes('fail') || desc.includes('error') || desc.includes('denied')) {
      for (const kw of TECHNIQUE_KEYWORDS) {
        if (desc.includes(kw) && !failedTechniques.includes(kw)) {
          failedTechniques.push(kw);
        }
      }
    }
  }

  return {
    unused_skills: unusedSkills,
    missing_skills: missingSkills,
    failed_techniques: failedTechniques,
    mentioned_techniques: [...mentionedTechniques],
    skill_usage_counts: usageCounts,
  };
}

// ============================================================
// Context Improvement Analysis
// ============================================================

type FrontierSuccessStats = Record<string, { total: number; successful: number }>;

function collectFrontierSuccessStats(input: RetrospectiveInput): FrontierSuccessStats {
  const successByType: Record<string, { total: number; successful: number }> = {
    incomplete_node: { total: 0, successful: 0 },
    untested_edge: { total: 0, successful: 0 },
    inferred_edge: { total: 0, successful: 0 },
    network_discovery: { total: 0, successful: 0 },
  };

  const groupedActions = groupHistoryByActionId(input.history);
  const actionIdsWithStructuredAttribution = new Set<string>();

  for (const [actionId, entries] of groupedActions) {
    const frontierType = entries.find(entry => !!entry.frontier_type)?.frontier_type;
    if (!frontierType || !successByType[frontierType]) continue;

    actionIdsWithStructuredAttribution.add(actionId);
    successByType[frontierType].total++;

    const hasSuccessfulLifecycle = entries.some(entry =>
      entry.event_type === 'action_completed' && (entry.result_classification === 'success' || entry.result_classification === 'partial'),
    );
    const hasLinkedFinding = entries.some(entry =>
      entry.event_type === 'finding_ingested' &&
      ((entry.linked_finding_ids && entry.linked_finding_ids.length > 0) || entry.result_classification === 'success'),
    );
    const hasObjective = entries.some(entry => entry.event_type === 'objective_achieved');
    if (hasSuccessfulLifecycle || hasLinkedFinding || hasObjective) {
      successByType[frontierType].successful++;
    }
  }

  // Walk history: actions followed by findings are "successful"
  // Prefer structured fields (category, frontier_type, outcome) when present;
  // fall back to text matching for legacy entries without structured fields.
  for (let i = 0; i < input.history.length; i++) {
    const entry = input.history[i];
    if (entry.action_id && actionIdsWithStructuredAttribution.has(entry.action_id)) continue;

    // Detect frontier item executions — structured path
    let frontierType: string | null = entry.frontier_type || null;

    // Fallback: text-based detection for legacy entries.
    // NOTE (M6): This heuristic is intentionally brittle — it only fires when
    // structured fields (frontier_type, category, outcome) are absent, which
    // limits it to pre-v0.3 activity log entries. False positives are possible
    // when description text contains matching keywords in a different context
    // (e.g. "test" matching 'untested_edge'). The logging quality report in
    // generateRetrospective() already flags entries lacking structured fields,
    // so the long-term fix is better structured logging, not a smarter regex.
    if (!frontierType) {
      const desc = entry.description.toLowerCase();
      if (desc.includes('discover hosts') || desc.includes('continue discovery') || desc.includes('host discovery') || desc.includes('network discovery') || desc.includes('network scan')) {
        frontierType = 'network_discovery';
      } else if (desc.includes('incomplete') || desc.includes('enumerat') || desc.includes('scan')) {
        frontierType = 'incomplete_node';
      } else if (desc.includes('untested') || desc.includes('test')) {
        frontierType = 'untested_edge';
      } else if (desc.includes('inferred') || desc.includes('hypothes')) {
        frontierType = 'inferred_edge';
      }
    }

    if (frontierType && successByType[frontierType]) {
      successByType[frontierType].total++;

      // Structured outcome takes priority
      if (entry.outcome === 'success') {
        successByType[frontierType].successful++;
        continue;
      } else if (entry.outcome === 'failure' || entry.outcome === 'neutral') {
        continue;
      }

      // Fallback: check if any of the next 5 entries contain a finding/ingestion
      for (let j = i + 1; j < Math.min(i + 6, input.history.length); j++) {
        const next = input.history[j];
        if (next.category === 'finding' || next.outcome === 'success') {
          successByType[frontierType].successful++;
          break;
        }
        const nextDesc = next.description.toLowerCase();
        if (nextDesc.includes('finding') || nextDesc.includes('ingest') || nextDesc.includes('discovered') || nextDesc.includes('new node')) {
          successByType[frontierType].successful++;
          break;
        }
      }
    }
  }

  return successByType;
}

function groupHistoryByActionId(history: ActivityLogEntry[]): Map<string, ActivityLogEntry[]> {
  const grouped = new Map<string, ActivityLogEntry[]>();
  for (const entry of history) {
    if (!entry.action_id) continue;
    const existing = grouped.get(entry.action_id) || [];
    existing.push(entry);
    grouped.set(entry.action_id, existing);
  }
  return grouped;
}

export function analyzeLoggingQuality(input: RetrospectiveInput): LoggingQualityReport {
  const total = input.history.length;
  if (total === 0) {
    return {
      status: 'weak',
      issues: ['No activity history is available, so retrospective attribution is almost entirely unavailable.'],
      recommendation: 'Record structured activity entries with action_id, event_type, category, frontier_type, and outcome during each run.',
    };
  }

  const withCategory = input.history.filter(entry => !!entry.category).length;
  const withFrontierType = input.history.filter(entry => !!entry.frontier_type).length;
  const withOutcome = input.history.filter(entry => !!entry.outcome).length;
  const actionEvents = input.history.filter(entry => !!entry.event_type && entry.event_type.startsWith('action_'));
  const actionIdRate = actionEvents.length > 0
    ? actionEvents.filter(entry => !!entry.action_id).length / actionEvents.length
    : 0;
  const validatedActions = input.history.filter(entry => entry.event_type === 'action_validated');
  const validatedLinkedRate = validatedActions.length > 0
    ? validatedActions.filter(entry =>
      !!entry.action_id &&
      input.history.some(candidate =>
        candidate.action_id === entry.action_id &&
        (candidate.event_type === 'finding_reported' || candidate.event_type === 'finding_ingested' || candidate.event_type === 'action_completed' || candidate.event_type === 'action_failed'),
      )
    ).length / validatedActions.length
    : 0;
  const findingEvents = input.history.filter(entry => entry.event_type === 'finding_reported' || entry.event_type === 'finding_ingested');
  const findingLinkedRate = findingEvents.length > 0
    ? findingEvents.filter(entry => !!entry.action_id || (entry.linked_finding_ids && entry.linked_finding_ids.length > 0)).length / findingEvents.length
    : 0;
  const terminalActions = input.history.filter(entry => entry.event_type === 'action_completed' || entry.event_type === 'action_failed');
  const terminalResultRate = terminalActions.length > 0
    ? terminalActions.filter(entry => !!entry.result_classification).length / terminalActions.length
    : 0;
  const instrumentationWarnings = input.history.filter(entry => entry.event_type === 'instrumentation_warning');

  let heuristicCount = 0;
  let ambiguousWindows = 0;
  for (let i = 0; i < input.history.length; i++) {
    const entry = input.history[i];
    if (!entry.category || !entry.frontier_type || !entry.outcome || !entry.event_type || !entry.action_id) {
      heuristicCount++;
    }

    const window = input.history.slice(Math.max(0, i - 2), Math.min(input.history.length, i + 3));
    const agents = new Set(window.map(candidate => candidate.agent_id).filter((value): value is string => !!value));
    const hasFinding = window.some(candidate => candidate.category === 'finding' || /finding|ingest|discovered/i.test(candidate.description));
    if (agents.size > 1 && hasFinding) {
      ambiguousWindows++;
    }
  }

  const categoryRate = withCategory / total;
  const frontierRate = withFrontierType / total;
  const outcomeRate = withOutcome / total;
  const heuristicRate = heuristicCount / total;
  const ambiguousRate = ambiguousWindows / total;

  const issues: string[] = [];
  if (categoryRate < 0.6) issues.push(`Only ${(categoryRate * 100).toFixed(0)}% of history entries include a category.`);
  if (frontierRate < 0.4) issues.push(`Only ${(frontierRate * 100).toFixed(0)}% of history entries include a frontier type.`);
  if (outcomeRate < 0.5) issues.push(`Only ${(outcomeRate * 100).toFixed(0)}% of history entries include an explicit outcome.`);
  if (actionEvents.length > 0 && actionIdRate < 0.8) issues.push(`Only ${(actionIdRate * 100).toFixed(0)}% of action events carry a stable action_id.`);
  if (validatedActions.length > 0 && validatedLinkedRate < 0.6) issues.push(`Only ${(validatedLinkedRate * 100).toFixed(0)}% of validated actions link cleanly to later findings or terminal action results.`);
  if (findingEvents.length > 0 && findingLinkedRate < 0.8) issues.push(`Only ${(findingLinkedRate * 100).toFixed(0)}% of finding events link back to an action or finding ID.`);
  if (terminalActions.length > 0 && terminalResultRate < 1.0) issues.push(`Only ${(terminalResultRate * 100).toFixed(0)}% of completed/failed actions include explicit result classification.`);
  if (instrumentationWarnings.length > 0) issues.push(`${instrumentationWarnings.length} explicit instrumentation warning(s) were recorded during the run.`);
  if (heuristicRate > 0.5) issues.push(`About ${(heuristicRate * 100).toFixed(0)}% of retrospective judgments depend on text heuristics.`);
  if (ambiguousRate > 0.2) issues.push('Nearby multi-agent findings make action/result attribution ambiguous in several windows.');

  const status = issues.length === 0
    ? 'good'
    : (categoryRate < 0.35 || frontierRate < 0.2 || outcomeRate < 0.25 || heuristicRate > 0.75 || (actionEvents.length > 0 && actionIdRate < 0.5))
      ? 'weak'
      : 'mixed';

  const recommendation = status === 'good'
    ? 'Continue recording structured activity entries; the current history quality supports iterative improvement.'
    : status === 'mixed'
      ? 'Increase structured logging on action validation, execution, and finding correlation so retrospective guidance relies less on text heuristics.'
      : 'Prioritize instrumentation: record action_id, event_type, frontier_type, and explicit result linkage for key actions before relying heavily on retrospective guidance.';

  return { status, issues, recommendation };
}

export function analyzeContextImprovements(input: RetrospectiveInput): ContextImprovementReport {
  const successByType = collectFrontierSuccessStats(input);
  const loggingQuality = analyzeLoggingQuality(input);
  const frontierObservations: ContextImprovementReport['frontier_observations'] = [];
  const contextGaps: ContextImprovementReport['context_gaps'] = [];
  const opsecObservations: ContextImprovementReport['opsec_observations'] = [];
  const recommendations = new Set<string>();

  for (const [frontierType, stats] of Object.entries(successByType)) {
    if (stats.total === 0) {
      frontierObservations.push({
        area: frontierType,
        observation: `${frontierType} was underrepresented in the engagement, so conclusions about its yield are weak.`,
        evidence_count: 0,
        confidence: loggingQuality.status === 'good' ? 'medium' : 'low',
      });
      continue;
    }

    const rate = stats.successful / stats.total;
    const confidence: AnalysisConfidence =
      loggingQuality.status === 'good' && stats.total >= 3 ? 'high'
        : loggingQuality.status === 'weak' ? 'low'
          : 'medium';

    let observation = `${frontierType} produced ${(rate * 100).toFixed(0)}% apparent yield across ${stats.total} observed follow-ups.`;
    if (frontierType === 'incomplete_node' && rate >= 0.6) {
      observation = `Incomplete-node exploration produced strong yield and likely benefited from richer host/service context.`;
    } else if (frontierType === 'inferred_edge' && rate < 0.3) {
      observation = `Inferred-edge follow-up had low apparent yield, which suggests the model needs better supporting context before acting on hypotheses.`;
    } else if (frontierType === 'untested_edge' && stats.total < 2) {
      observation = 'Untested-edge follow-up was sparse, so the retrospective has limited evidence about whether those leads are being explored effectively.';
    }

    frontierObservations.push({
      area: frontierType,
      observation,
      evidence_count: stats.total,
      confidence,
    });
  }

  const hostNodes = input.graph.nodes.filter(node => node.properties.type === 'host');
  const aliveHosts = hostNodes.filter(node => node.properties.alive !== false);
  const hostsMissingOs = aliveHosts.filter(node => !node.properties.os);
  if (hostsMissingOs.length >= 2) {
    contextGaps.push({
      area: 'parser improvement',
      gap: `${hostsMissingOs.length} live host nodes still lack operating-system enrichment.`,
      recommendation: 'Improve parser or manual enrichment coverage so hosts carry OS context before follow-on reasoning.',
      severity: 'warning',
      confidence: 'medium',
    });
    recommendations.add('Improve parser or manual enrichment coverage for host operating-system context.');
  }

  const servicesMissingDetail = input.graph.nodes.filter(node =>
    node.properties.type === 'service' &&
    !node.properties.version &&
    !node.properties.banner &&
    !node.properties.protocol,
  );
  if (servicesMissingDetail.length >= 2) {
    contextGaps.push({
      area: 'parser improvement',
      gap: `${servicesMissingDetail.length} service nodes lack banner, version, or protocol enrichment.`,
      recommendation: 'Improve service parsing so Claude gets richer service context instead of making decisions from bare open ports.',
      severity: 'warning',
      confidence: 'medium',
    });
    recommendations.add('Improve service parsing so frontier reasoning includes richer service details.');
  }

  if (input.skillNames.length > 0) {
    const skillGaps = analyzeSkillGaps(input);
    if (skillGaps.missing_skills.length > 0) {
      contextGaps.push({
        area: 'skill-library improvement',
        gap: `Techniques were attempted without matching skill coverage: ${skillGaps.missing_skills.slice(0, 3).join(', ')}${skillGaps.missing_skills.length > 3 ? ', ...' : ''}.`,
        recommendation: 'Add or improve skills for the techniques repeatedly attempted during the engagement.',
        severity: 'warning',
        confidence: 'medium',
      });
      recommendations.add('Add or update skills for techniques that appeared in the engagement without matching coverage.');
    }
  }

  const deniedOrFailed = input.history.filter(entry =>
    entry.result_classification === 'failure' ||
    entry.validation_result === 'invalid' ||
    /fail|denied|error/i.test(entry.description)
  );
  if (deniedOrFailed.length > 0) {
    contextGaps.push({
      area: 'validation-warning improvement',
      gap: `${deniedOrFailed.length} history entries indicate failures or access denial, which may mean validation warnings were too weak or too generic.`,
      recommendation: 'Strengthen validate_action guidance for recurring failure patterns so Claude gets clearer pre-execution context.',
      severity: loggingQuality.status === 'weak' ? 'warning' : 'critical',
      confidence: loggingQuality.status === 'good' ? 'medium' : 'low',
    });
    recommendations.add('Strengthen validation warnings for recurring failure patterns observed in the history.');
  }

  if (loggingQuality.status !== 'good') {
    contextGaps.push({
      area: 'logging/instrumentation improvement',
      gap: 'Structured activity logging is not strong enough to support high-confidence iterative improvements.',
      recommendation: loggingQuality.recommendation,
      severity: loggingQuality.status === 'weak' ? 'critical' : 'warning',
      confidence: 'high',
    });
    recommendations.add(loggingQuality.recommendation);
  }

  if (input.config.opsec.max_noise <= 0.3) {
    const noisyPatterns = input.history.filter(entry =>
      ['nmap', 'nxc', 'netexec', 'responder', 'impacket-secretsdump'].includes(entry.tool_name || '') ||
      /nmap|scan|secretsdump|responder|spray|brute/i.test(entry.description)
    );
    if (noisyPatterns.length > 0) {
      opsecObservations.push({
        observation: `${noisyPatterns.length} history entries look noisy for a restrictive OPSEC profile (${input.config.opsec.name}, max noise ${input.config.opsec.max_noise}).`,
        recommendation: 'Surface stronger OPSEC context and warnings before noisy actions instead of trying to numerically suppress them afterward.',
        confidence: loggingQuality.status === 'good' ? 'medium' : 'low',
      });
      recommendations.add('Improve OPSEC-facing validation and context for noisy actions in restrictive engagements.');
    }
  }

  const blacklistedHits = (input.config.opsec.blacklisted_techniques || []).filter(technique =>
    input.history.some(entry => entry.description.toLowerCase().includes(technique.toLowerCase()))
  );
  if (blacklistedHits.length > 0) {
    opsecObservations.push({
      observation: `Blacklisted technique references appeared in history: ${blacklistedHits.join(', ')}.`,
      recommendation: 'Review validation and prompt guidance to ensure blacklisted techniques are vetoed before execution.',
      confidence: 'high',
    });
    recommendations.add('Ensure validation and prompting clearly veto blacklisted techniques before execution.');
  }

  const inferredEdges = input.graph.edges.filter(edge => edge.properties.inferred_by_rule);
  const unconfirmedInferred = inferredEdges.filter(edge => !edge.properties.confirmed_at);
  if (inferredEdges.length >= 3 && unconfirmedInferred.length / inferredEdges.length > 0.6) {
    contextGaps.push({
      area: 'inference-rule improvement',
      gap: `${unconfirmedInferred.length}/${inferredEdges.length} inferred edges remained unconfirmed.`,
      recommendation: 'Improve inference rules or enrich supporting node context so hypotheses arrive with better evidence.',
      severity: 'warning',
      confidence: 'medium',
    });
    recommendations.add('Improve inference support context rather than trying to compensate with ranking formulas.');
  }

  if (recommendations.size === 0) {
    recommendations.add('No dominant context gap stood out; continue collecting richer structured activity and enrichment data.');
  }

  return {
    frontier_observations: frontierObservations,
    context_gaps: contextGaps,
    opsec_observations: opsecObservations,
    logging_quality: loggingQuality,
    recommendations: [...recommendations],
    success_by_frontier_type: successByType,
  };
}

// ============================================================
// Attack Path Report (Markdown)
// ============================================================

export function generateReport(
  input: RetrospectiveInput,
  retrospective?: Partial<Pick<RetrospectiveResult, 'inference_suggestions' | 'skill_gaps' | 'context_improvements' | 'trace_quality'>>
): string {
  const config = input.config;
  const graph = input.graph;
  const history = input.history;

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

  // Compute access summary
  const ACCESS_EDGES = new Set(['HAS_SESSION', 'ADMIN_TO', 'OWNS_CRED']);
  const compromisedHosts: string[] = [];
  const credentials: string[] = [];
  for (const n of graph.nodes) {
    if (n.properties.type === 'host') {
      const hasAccess = graph.edges.some(e =>
        e.target === n.id && ACCESS_EDGES.has(e.properties.type) && e.properties.confidence >= 0.9
      );
      if (hasAccess) compromisedHosts.push(n.properties.label || n.id);
    }
    if (n.properties.type === 'credential' && n.properties.confidence >= 0.9 && isCredentialUsableForAuth(n.properties)) {
      credentials.push(`${getCredentialDisplayKind(n.properties)}: ${n.properties.cred_user || n.properties.label}`);
    }
  }

  // Timeline
  const startTime = history.length > 0 ? history[0].timestamp : config.created_at;
  const endTime = history.length > 0 ? history[history.length - 1].timestamp : config.created_at;

  // Objectives
  const objectivesAchieved = config.objectives.filter(o => o.achieved);
  const objectivesPending = config.objectives.filter(o => !o.achieved);

  // Agent summary
  const completedAgents = input.agents.filter(a => a.status === 'completed');
  const failedAgents = input.agents.filter(a => a.status === 'failed');
  const inferenceSuggestions = retrospective?.inference_suggestions || [];
  const skillGaps = retrospective?.skill_gaps;
  const contextImprovements = retrospective?.context_improvements;
  const traceQuality = retrospective?.trace_quality;

  // Build markdown
  const lines: string[] = [];
  lines.push(`# Engagement Report: ${config.name}`);
  lines.push('');
  lines.push(`**Engagement ID:** ${config.id}`);
  lines.push(`**Period:** ${formatTimestamp(startTime)} — ${formatTimestamp(endTime)}`);
  lines.push(`**OPSEC Profile:** ${config.opsec.name} (max noise: ${config.opsec.max_noise})`);
  lines.push('');

  // Executive Summary
  lines.push('## Executive Summary');
  lines.push('');
  lines.push(`This engagement targeted ${config.scope.cidrs.length} CIDR range(s) and ${config.scope.domains.length} domain(s). ` +
    `${objectivesAchieved.length} of ${config.objectives.length} objective(s) were achieved. ` +
    `The engagement discovered ${graph.nodes.length} nodes and ${graph.edges.length} edges, ` +
    `compromising ${compromisedHosts.length} host(s) and obtaining ${credentials.length} reusable credential(s).`);
  lines.push('');

  // Scope
  lines.push('## Scope');
  lines.push('');
  lines.push('| Type | Values |');
  lines.push('|------|--------|');
  lines.push(`| CIDRs | ${config.scope.cidrs.join(', ') || 'none'} |`);
  lines.push(`| Domains | ${config.scope.domains.join(', ') || 'none'} |`);
  lines.push(`| Exclusions | ${config.scope.exclusions.join(', ') || 'none'} |`);
  lines.push('');

  // Objectives
  lines.push('## Objectives');
  lines.push('');
  lines.push('| Objective | Status | Achieved At |');
  lines.push('|-----------|--------|-------------|');
  for (const obj of config.objectives) {
    const status = obj.achieved ? 'Achieved' : 'Pending';
    const at = obj.achieved_at ? formatTimestamp(obj.achieved_at) : '—';
    lines.push(`| ${obj.description} | ${status} | ${at} |`);
  }
  lines.push('');

  // Graph Summary
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

  // Access
  lines.push('## Compromised Assets');
  lines.push('');
  if (compromisedHosts.length > 0) {
    lines.push('### Hosts');
    lines.push('');
    for (const h of compromisedHosts) {
      lines.push(`- ${h}`);
    }
    lines.push('');
  }
  if (credentials.length > 0) {
    lines.push('### Credentials');
    lines.push('');
    for (const c of credentials) {
      lines.push(`- ${c}`);
    }
    lines.push('');
  }
  if (compromisedHosts.length === 0 && credentials.length === 0) {
    lines.push('No assets were compromised during this engagement.');
    lines.push('');
  }

  // Credential Chains
  const credChains = buildCredentialChains(input.graph);
  if (credChains.length > 0) {
    lines.push('### Credential Chains');
    lines.push('');
    for (const chain of credChains) {
      const parts: string[] = [];
      for (let i = 0; i < chain.labels.length; i++) {
        if (i > 0) {
          parts.push(` → [${chain.methods[i - 1]}] → `);
        }
        parts.push(chain.labels[i]);
      }
      lines.push(`- ${parts.join('')}`);
    }
    lines.push('');
  }

  // Agent Summary
  if (input.agents.length > 0) {
    lines.push('## Agent Activity');
    lines.push('');
    lines.push(`- **Total agents dispatched:** ${input.agents.length}`);
    lines.push(`- **Completed:** ${completedAgents.length}`);
    lines.push(`- **Failed:** ${failedAgents.length}`);
    lines.push('');
  }

  if (contextImprovements || inferenceSuggestions.length > 0 || skillGaps || traceQuality) {
    lines.push('## Retrospective Findings');
    lines.push('');

    if (contextImprovements) {
      lines.push('### Context Improvements');
      lines.push('');
      for (const observation of contextImprovements.frontier_observations.slice(0, 3)) {
        lines.push(`- **${observation.area}:** ${observation.observation} (${observation.confidence} confidence)`);
      }
      for (const gap of contextImprovements.context_gaps.slice(0, 3)) {
        lines.push(`- **${gap.area}:** ${gap.gap} Recommendation: ${gap.recommendation} (${gap.confidence} confidence)`);
      }
      for (const opsec of contextImprovements.opsec_observations.slice(0, 2)) {
        lines.push(`- **OPSEC:** ${opsec.observation} Recommendation: ${opsec.recommendation} (${opsec.confidence} confidence)`);
      }
      lines.push(`- **Logging quality:** ${contextImprovements.logging_quality.status}. ${contextImprovements.logging_quality.recommendation}`);
      lines.push('');
    }

    if (inferenceSuggestions.length > 0) {
      lines.push('### Inference Opportunities');
      lines.push('');
      for (const suggestion of inferenceSuggestions.slice(0, 3)) {
        lines.push(`- ${suggestion.rule.name}: ${suggestion.evidence}`);
      }
      lines.push('');
    }

    if (skillGaps) {
      lines.push('### Skill Gaps');
      lines.push('');
      if (skillGaps.missing_skills.length > 0) {
        lines.push(`- Missing coverage: ${skillGaps.missing_skills.slice(0, 5).join(', ')}`);
      }
      if (skillGaps.failed_techniques.length > 0) {
        lines.push(`- Failed techniques observed: ${skillGaps.failed_techniques.slice(0, 5).join(', ')}`);
      }
      if (skillGaps.missing_skills.length === 0 && skillGaps.failed_techniques.length === 0) {
        lines.push('- No major skill gaps stood out in this run.');
      }
      lines.push('');
    }

    if (traceQuality) {
      lines.push('### Trace Quality');
      lines.push('');
      lines.push(`- Trace quality is **${traceQuality.status}**.`);
      for (const issue of traceQuality.issues.slice(0, 3)) {
        lines.push(`- ${issue}`);
      }
      lines.push('');
    }
  }

  // Timeline (last 50 events)
  lines.push('## Activity Timeline');
  lines.push('');
  lines.push('| Time | Event |');
  lines.push('|------|-------|');
  const timelineEntries = history.slice(-50);
  for (const entry of timelineEntries) {
    const time = formatTimestamp(entry.timestamp);
    const agent = entry.agent_id ? ` [${entry.agent_id}]` : '';
    lines.push(`| ${time} | ${entry.description}${agent} |`);
  }
  lines.push('');

  // Recommendations
  lines.push('## Recommendations');
  lines.push('');
  const untestedInferred = graph.edges.filter(e => e.properties.confidence < 1.0 && !e.properties.tested);
  if (untestedInferred.length > 0) {
    lines.push(`- **${untestedInferred.length} inferred edge(s) remain untested** — these represent potential attack paths that were not validated during the engagement.`);
  }
  if (objectivesPending.length > 0) {
    lines.push(`- **${objectivesPending.length} objective(s) not achieved** — ${objectivesPending.map(o => o.description).join(', ')}.`);
  }
  if (compromisedHosts.length > 0) {
    lines.push(`- **Remediate access on ${compromisedHosts.length} compromised host(s)** — reset credentials, revoke sessions, review logs.`);
  }
  if (credentials.length > 0) {
    lines.push(`- **Rotate ${credentials.length} discovered credential(s)** immediately.`);
  }
  lines.push('');

  lines.push('---');
  lines.push(`*Generated by Overwatch at ${new Date().toISOString()}*`);
  lines.push('');

  return lines.join('\n');
}

// ============================================================
// RLVR Training Traces
// ============================================================

export function exportTrainingTraces(input: RetrospectiveInput): { traces: RLVRTrace[]; trace_quality: TraceQualityReport } {
  const traces: RLVRTrace[] = [];
  const history = input.history;
  let structuredCount = 0;
  let mixedCount = 0;
  let heuristicCount = 0;

  // Track running state as we walk the history
  let nodeCount = 0;
  let edgeCount = 0;
  let accessLevel = 'none';
  let objectivesAchieved = 0;

  // Count initial graph (from seed)
  for (const n of input.graph.nodes) {
    if (getNodeFirstSeenAt(n.properties) === input.config.created_at) {
      nodeCount++;
    }
  }

  const groupedActions = groupHistoryByActionId(history);
  const processedActionIds = new Set<string>();
  let step = 0;
  for (let i = 0; i < history.length; i++) {
    const entry = history[i];
    if (entry.action_id && processedActionIds.has(entry.action_id)) {
      continue;
    }

    if (entry.action_id && groupedActions.has(entry.action_id)) {
      const entries = groupedActions.get(entry.action_id)!;
      processedActionIds.add(entry.action_id);

      const first = entries[0];
      const target = first.target_node_ids?.[0] || first.target_edge?.target;
      const tool = first.tool_name;
      const technique = first.technique;
      const terminal = [...entries].reverse().find(candidate =>
        candidate.event_type === 'action_completed' || candidate.event_type === 'action_failed'
      );
      const findingEvents = entries.filter(candidate => candidate.event_type === 'finding_ingested');
      const actionType = terminal?.event_type === 'action_failed'
        ? 'action_failed'
        : first.event_type || 'action';
      const newNodes = findingEvents.reduce((sum, candidate) => sum + asNumber(candidate.details?.new_nodes), 0);
      const newEdges = findingEvents.reduce((sum, candidate) => sum + asNumber(candidate.details?.new_edges), 0);
      const objAchieved = entries.some(candidate => candidate.event_type === 'objective_achieved');

      nodeCount += newNodes;
      edgeCount += newEdges;
      if (objAchieved) objectivesAchieved++;
      if (entries.some(candidate => /admin|session/i.test(candidate.description))) accessLevel = 'user';
      if (entries.some(candidate => /domain admin|da /i.test(candidate.description))) accessLevel = 'domain_admin';

      let reward = 0;
      reward += newNodes * 0.5;
      reward += newEdges * 0.3;
      if (objAchieved) reward += 5.0;
      if (entries.some(candidate => candidate.result_classification === 'success')) reward += 1.0;
      if (entries.some(candidate => candidate.result_classification === 'failure')) reward -= 0.1;

      const hasStructuredLifecycle = entries.some(candidate => candidate.event_type === 'action_validated')
        && !!terminal;
      const hasFindingLinkage = findingEvents.some(candidate => (candidate.linked_finding_ids?.length || 0) > 0);
      const derived_from: RLVRTrace['derived_from'] = hasStructuredLifecycle && hasFindingLinkage
        ? 'structured'
        : (hasStructuredLifecycle || hasFindingLinkage)
          ? 'mixed'
          : 'text_heuristic';
      const confidence: RLVRTrace['confidence'] = derived_from === 'structured'
        ? 'high'
        : derived_from === 'mixed'
          ? 'medium'
          : 'low';

      if (derived_from === 'structured') structuredCount++;
      else if (derived_from === 'mixed') mixedCount++;
      else heuristicCount++;

      traces.push({
        step,
        timestamp: first.timestamp,
        state_summary: {
          nodes: nodeCount,
          edges: edgeCount,
          access_level: accessLevel,
          objectives_achieved: objectivesAchieved,
        },
        action: { type: actionType, target, technique, tool },
        outcome: {
          new_nodes: newNodes,
          new_edges: newEdges,
          objective_achieved: objAchieved,
        },
        reward,
        confidence,
        derived_from,
      });
      step++;
      continue;
    }

    const desc = entry.description.toLowerCase();

    // Parse action type from log entry
    let actionType = 'unknown';
    let target: string | undefined;
    let technique: string | undefined;
    let tool: string | undefined;

    const structuredSessionTypes: Record<string, string> = {
      session_opened: 'session_opened',
      session_connected: 'session_connected',
      session_signaled: 'session_signaled',
      session_closed: 'session_closed',
      session_error: 'session_error',
    };

    if (entry.event_type && structuredSessionTypes[entry.event_type]) {
      actionType = structuredSessionTypes[entry.event_type];
      const sessionId = entry.details?.session_id;
      if (typeof sessionId === 'string') target = sessionId;
    } else if (desc.includes('finding') || desc.includes('ingest')) {
      actionType = 'report_finding';
    } else if (desc.includes('agent dispatch')) {
      actionType = 'dispatch_agent';
    } else if (desc.includes('objective achieved')) {
      actionType = 'objective_achieved';
    } else if (desc.includes('inference rule')) {
      actionType = 'inference_rule';
    } else if (desc.includes('scan') || desc.includes('nmap')) {
      actionType = 'scan';
      tool = 'nmap';
    } else if (desc.includes('initialized') || desc.includes('resumed')) {
      actionType = 'session_start';
    } else {
      actionType = 'action';
    }

    // Extract target from description
    const ipMatch = desc.match(/(\d+\.\d+\.\d+\.\d+)/);
    if (!target && ipMatch) target = ipMatch[1];

    // Look for findings following this action
    let newNodes = 0;
    let newEdges = 0;
    let objAchieved = false;
    let usedStructuredOutcome = false;
    let usedHeuristicOutcome = false;

    // Parse node/edge counts from the next few entries
    for (let j = i + 1; j < Math.min(i + 3, history.length); j++) {
      const nextEntry = history[j];
      const next = nextEntry.description.toLowerCase();
      const nodeMatch = next.match(/(\d+)\s*new\s*node/);
      const edgeMatch = next.match(/(\d+)\s*new\s*edge/);
      if (nodeMatch) newNodes += parseInt(nodeMatch[1]);
      if (edgeMatch) newEdges += parseInt(edgeMatch[1]);
      if (nextEntry.category === 'finding' || nextEntry.outcome === 'success') {
        usedStructuredOutcome = true;
      }
      if (nodeMatch || edgeMatch || next.includes('objective achieved')) {
        usedHeuristicOutcome = true;
      }
      if (next.includes('objective achieved')) objAchieved = true;
    }

    // Update running state
    nodeCount += newNodes;
    edgeCount += newEdges;
    if (objAchieved) objectivesAchieved++;
    if (desc.includes('admin') || desc.includes('has_session')) accessLevel = 'user';
    if (desc.includes('domain admin') || desc.includes('da ')) accessLevel = 'domain_admin';

    // Compute reward
    let reward = 0;
    reward += newNodes * 0.5;
    reward += newEdges * 0.3;
    if (objAchieved) reward += 5.0;
    if (desc.includes('admin_to') || desc.includes('has_session')) reward += 1.0;
    if (desc.includes('owns_cred')) reward += 1.0;
    if (desc.includes('fail') || desc.includes('denied')) reward -= 0.1;

    const hasStructuredAction = !!entry.category || !!entry.frontier_type || !!entry.outcome || !!entry.event_type;
    const derived_from: RLVRTrace['derived_from'] = hasStructuredAction && usedStructuredOutcome
      ? 'structured'
      : (hasStructuredAction || usedStructuredOutcome)
        ? 'mixed'
        : 'text_heuristic';
    const confidence: RLVRTrace['confidence'] = derived_from === 'structured'
      ? 'high'
      : derived_from === 'mixed'
        ? 'medium'
        : 'low';

    if (derived_from === 'structured') structuredCount++;
    else if (derived_from === 'mixed') mixedCount++;
    else heuristicCount++;

    traces.push({
      step,
      timestamp: entry.timestamp,
      state_summary: {
        nodes: nodeCount,
        edges: edgeCount,
        access_level: accessLevel,
        objectives_achieved: objectivesAchieved,
      },
      action: { type: actionType, target, technique, tool },
      outcome: {
        new_nodes: newNodes,
        new_edges: newEdges,
        objective_achieved: objAchieved,
      },
      reward,
      confidence,
      derived_from,
    });
    step++;
  }

  const issues: string[] = [];
  if (heuristicCount > 0) {
    issues.push(`${heuristicCount}/${traces.length || 1} traces rely mostly on text heuristics rather than structured action/result linkage.`);
  }
  if (mixedCount > structuredCount) {
    issues.push('Most traces depend on mixed structured + heuristic attribution instead of explicit causal linkage.');
  }
  const actionEvents = history.filter(entry => !!entry.action_id);
  if (actionEvents.length > 0 && structuredCount === 0) {
    issues.push('Action IDs are present, but explicit finding/result linkage is still too weak for high-confidence traces.');
  }
  if (input.history.length > 0 && input.history.filter(entry => !!entry.frontier_type).length === 0) {
    issues.push('History contains no explicit frontier_type fields, which weakens causal analysis.');
  }

  const trace_quality: TraceQualityReport = {
    status: heuristicCount === 0
      ? 'good'
      : heuristicCount > structuredCount
        ? 'weak'
        : 'mixed',
    issues,
  };

  return { traces, trace_quality };
}

// ============================================================
// Full Retrospective
// ============================================================

export function runRetrospective(input: RetrospectiveInput): RetrospectiveResult {
  const inferenceSuggestions = analyzeInferenceGaps(input);
  const skillGaps = analyzeSkillGaps(input);
  const contextImprovements = analyzeContextImprovements(input);
  const { traces: trainingTraces, trace_quality: traceQuality } = exportTrainingTraces(input);
  const reportMarkdown = generateReport(input, {
    inference_suggestions: inferenceSuggestions,
    skill_gaps: skillGaps,
    context_improvements: contextImprovements,
    trace_quality: traceQuality,
  });

  // Build summary
  const config = input.config;
  const objectivesAchieved = config.objectives.filter(o => o.achieved).length;
  const summaryLines = [
    `Engagement: ${config.name} (${config.id})`,
    `Graph: ${input.graph.nodes.length} nodes, ${input.graph.edges.length} edges`,
    `Objectives: ${objectivesAchieved}/${config.objectives.length} achieved`,
    `Agents: ${input.agents.length} dispatched (${input.agents.filter(a => a.status === 'completed').length} completed)`,
    `Activity: ${input.history.length} log entries`,
    `---`,
    `Inference suggestions: ${inferenceSuggestions.length}`,
    `Skill gaps: ${skillGaps.missing_skills.length} missing, ${skillGaps.unused_skills.length} unused`,
    `Context improvements: ${contextImprovements.recommendations.length} recommendations`,
    `Training traces: ${trainingTraces.length} steps (${traceQuality.status} quality)`,
  ];

  return {
    inference_suggestions: inferenceSuggestions,
    skill_gaps: skillGaps,
    context_improvements: contextImprovements,
    report_markdown: reportMarkdown,
    training_traces: trainingTraces,
    trace_quality: traceQuality,
    summary: summaryLines.join('\n'),
  };
}

// ============================================================
// Credential Chain Analysis
// ============================================================

export interface CredentialChain {
  chain: string[];       // node IDs in derivation order
  labels: string[];      // human-readable labels
  methods: string[];     // derivation_method for each link
}

export function buildCredentialChains(graph: ExportedGraph): CredentialChain[] {
  // Build adjacency from DERIVED_FROM edges (source derived from target)
  const derivedFrom = new Map<string, { target: string; method: string }[]>();
  const hasInbound = new Set<string>();

  for (const edge of graph.edges) {
    if (edge.properties.type !== 'DERIVED_FROM') continue;
    const entries = derivedFrom.get(edge.source) || [];
    entries.push({
      target: edge.target,
      method: (edge.properties.derivation_method as string) || 'unknown',
    });
    derivedFrom.set(edge.source, entries);
    hasInbound.add(edge.target);
  }

  if (derivedFrom.size === 0) return [];

  // Find chain roots: nodes that are targets of DERIVED_FROM but not sources
  // (i.e. the original credentials from which others were derived).
  // We walk forward from every source that has no parent to build chains.
  const nodeMap = new Map(graph.nodes.map(n => [n.id, n.properties]));
  const allSources = new Set(derivedFrom.keys());
  // Roots are nodes that appear as targets but not as sources (leaf origins)
  // OR sources that don't appear as any target (chain tips)
  const chainTips = [...allSources].filter(id => !hasInbound.has(id));

  // If no clear tips (cycles), just start from all sources
  const starts = chainTips.length > 0 ? chainTips : [...allSources];

  const chains: CredentialChain[] = [];
  const visited = new Set<string>();

  function walk(nodeId: string, chain: string[], labels: string[], methods: string[]): void {
    if (visited.has(nodeId)) return; // prevent cycles
    visited.add(nodeId);

    const nextEdges = derivedFrom.get(nodeId);
    if (!nextEdges || nextEdges.length === 0) {
      // End of chain — only emit if length > 1
      if (chain.length > 1) {
        chains.push({ chain: [...chain], labels: [...labels], methods: [...methods] });
      }
      return;
    }

    for (const { target, method } of nextEdges) {
      const targetNode = nodeMap.get(target);
      const targetLabel = targetNode
        ? `${getCredentialDisplayKind(targetNode)}: ${targetNode.cred_user || targetNode.label}`
        : target;
      walk(target, [...chain, target], [...labels, targetLabel], [...methods, method]);
    }
  }

  for (const startId of starts) {
    visited.clear();
    const startNode = nodeMap.get(startId);
    const startLabel = startNode
      ? `${getCredentialDisplayKind(startNode)}: ${startNode.cred_user || startNode.label}`
      : startId;
    walk(startId, [startId], [startLabel], []);
  }

  return chains;
}

// ============================================================
// Helpers
// ============================================================

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
  } catch {
    return ts;
  }
}

function asNumber(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}
