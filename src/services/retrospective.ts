// ============================================================
// Overwatch — Retrospective Analyzer
// Post-engagement analysis producing structured outputs
// ============================================================

import type {
  EngagementConfig, NodeProperties, EdgeProperties, EdgeType,
  InferenceRule, AgentTask, InferenceRuleSuggestion,
  SkillGapReport, ScoringRecommendation, RLVRTrace, RetrospectiveResult,
} from '../types.js';
import type { ActivityLogEntry } from './engine-context.js';
import { getCredentialDisplayKind, isCredentialUsableForAuth } from './credential-utils.js';

export interface RetrospectiveInput {
  config: EngagementConfig;
  graph: {
    nodes: Array<{ id: string; properties: NodeProperties }>;
    edges: Array<{ source: string; target: string; properties: EdgeProperties }>;
  };
  history: ActivityLogEntry[];
  inferenceRules: InferenceRule[];
  agents: AgentTask[];
  skillNames: string[];
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

      const sourceSelector = typeToSourceSelector[pattern.sourceType];
      // Skip if we can't map the source type to a valid selector
      if (!sourceSelector) continue;

      suggestions.push({
        rule: {
          id: `suggested-${pattern.edgeType.toLowerCase()}-${pattern.sourceType}-${pattern.targetType}`,
          name: `Auto-infer ${pattern.edgeType} from ${pattern.sourceType} to ${pattern.targetType}`,
          description: `Pattern observed ${pattern.count} times: ${pattern.sourceType} nodes frequently have ${pattern.edgeType} edges to ${pattern.targetType} nodes`,
          trigger: { node_type: pattern.targetType as any },
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

  // Common tool/technique keywords to look for in activity log
  const TECHNIQUE_KEYWORDS = [
    'nmap', 'nxc', 'netexec', 'certipy', 'impacket', 'secretsdump',
    'kerberoast', 'asreproast', 'bloodhound', 'responder', 'relay',
    'smb', 'ldap', 'rdp', 'winrm', 'psremote', 'dcsync',
    'mimikatz', 'rubeus', 'seatbelt', 'snaffler', 'hashcat', 'john',
    'gobuster', 'feroxbuster', 'sql injection', 'sqli', 'xss',
    'privesc', 'privilege escalation', 'lateral movement',
    'password spray', 'brute force', 'credential dump',
    'adcs', 'esc1', 'esc2', 'esc3', 'esc4', 'esc6', 'esc8',
    'delegation', 'unconstrained', 'constrained',
    'pivoting', 'port forward', 'tunnel', 'socks',
    'dns', 'snmp', 'exchange', 'sccm',
    'aws', 'azure', 'gcp', 'cloud',
    'persistence', 'exfiltration',
  ];

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
    input.skillNames.map(s => s.replace(/\.md$/, '').toLowerCase().replace(/\s+/g, '-'))
  );

  // Skills in library but never referenced
  const unusedSkills = input.skillNames
    .filter(s => {
      const normalized = s.replace(/\.md$/, '').toLowerCase().replace(/\s+/g, '-');
      return !usageCounts[normalized] && !usageCounts[s];
    });

  // Techniques mentioned in engagement but no matching skill
  const missingSkills: string[] = [];
  for (const technique of mentionedTechniques) {
    const matchesSkill = [...normalizedSkillNames].some(s =>
      s.includes(technique) || technique.includes(s)
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
    skill_usage_counts: usageCounts,
  };
}

// ============================================================
// Scoring Analysis
// ============================================================

export function analyzeScoring(input: RetrospectiveInput): ScoringRecommendation {
  // Default weights (what the system currently uses implicitly)
  const currentWeights: Record<string, number> = {
    hops_to_objective: 0.25,
    fan_out_estimate: 0.25,
    confidence: 0.25,
    opsec_noise_penalty: 0.25,
  };

  // Analyze which activity log entries correspond to findings vs dead ends
  const successByType: Record<string, { total: number; successful: number }> = {
    incomplete_node: { total: 0, successful: 0 },
    untested_edge: { total: 0, successful: 0 },
    inferred_edge: { total: 0, successful: 0 },
  };

  // Walk history: actions followed by findings are "successful"
  // Prefer structured fields (category, frontier_type, outcome) when present;
  // fall back to text matching for legacy entries without structured fields.
  for (let i = 0; i < input.history.length; i++) {
    const entry = input.history[i];

    // Detect frontier item executions — structured path
    let frontierType: string | null = entry.frontier_type || null;

    // Fallback: text-based detection for legacy entries
    if (!frontierType) {
      const desc = entry.description.toLowerCase();
      if (desc.includes('incomplete') || desc.includes('enumerat') || desc.includes('scan')) {
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

  // Compute suggested weights based on success rates
  const suggestedWeights = { ...currentWeights };
  const rationale: string[] = [];

  // If inferred edges have high confirmation rate, boost confidence weight
  const inferredStats = successByType['inferred_edge'];
  if (inferredStats.total > 0) {
    const rate = inferredStats.successful / inferredStats.total;
    if (rate > 0.5) {
      suggestedWeights.confidence = 0.35;
      suggestedWeights.fan_out_estimate = 0.20;
      rationale.push(`Inferred edges had ${(rate * 100).toFixed(0)}% success rate — boost confidence weight`);
    } else if (rate < 0.2) {
      suggestedWeights.confidence = 0.15;
      suggestedWeights.hops_to_objective = 0.30;
      rationale.push(`Inferred edges had only ${(rate * 100).toFixed(0)}% success rate — reduce confidence weight, prioritize objective proximity`);
    }
  }

  // If incomplete_node exploration was very productive, boost fan_out
  const incompleteStats = successByType['incomplete_node'];
  if (incompleteStats.total > 0) {
    const rate = incompleteStats.successful / incompleteStats.total;
    if (rate > 0.6) {
      suggestedWeights.fan_out_estimate = 0.30;
      rationale.push(`Node enumeration had ${(rate * 100).toFixed(0)}% yield — increase fan_out weight`);
    }
  }

  // Check objective achievement timing
  const objectivesAchieved = input.config.objectives.filter(o => o.achieved).length;
  const totalObjectives = input.config.objectives.length;
  if (totalObjectives > 0 && objectivesAchieved < totalObjectives) {
    suggestedWeights.hops_to_objective = Math.min(0.35, suggestedWeights.hops_to_objective + 0.05);
    rationale.push(`${totalObjectives - objectivesAchieved}/${totalObjectives} objectives unachieved — increase hops_to_objective weight`);
  }

  if (rationale.length === 0) {
    rationale.push('Insufficient data to recommend weight changes — using defaults');
  }

  return {
    current_weights: currentWeights,
    suggested_weights: suggestedWeights,
    rationale,
    success_by_frontier_type: successByType,
  };
}

// ============================================================
// Attack Path Report (Markdown)
// ============================================================

export function generateReport(input: RetrospectiveInput): string {
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
    const status = obj.achieved ? '✅ Achieved' : '❌ Pending';
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

  // Agent Summary
  if (input.agents.length > 0) {
    lines.push('## Agent Activity');
    lines.push('');
    lines.push(`- **Total agents dispatched:** ${input.agents.length}`);
    lines.push(`- **Completed:** ${completedAgents.length}`);
    lines.push(`- **Failed:** ${failedAgents.length}`);
    lines.push('');
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

export function exportTrainingTraces(input: RetrospectiveInput): RLVRTrace[] {
  const traces: RLVRTrace[] = [];
  const history = input.history;

  // Track running state as we walk the history
  let nodeCount = 0;
  let edgeCount = 0;
  let accessLevel = 'none';
  let objectivesAchieved = 0;

  // Count initial graph (from seed)
  for (const n of input.graph.nodes) {
    if (n.properties.discovered_at === input.config.created_at) {
      nodeCount++;
    }
  }

  let step = 0;
  for (let i = 0; i < history.length; i++) {
    const entry = history[i];
    const desc = entry.description.toLowerCase();

    // Parse action type from log entry
    let actionType = 'unknown';
    let target: string | undefined;
    let technique: string | undefined;
    let tool: string | undefined;

    if (desc.includes('finding') || desc.includes('ingest')) {
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
    if (ipMatch) target = ipMatch[1];

    // Look for findings following this action
    let newNodes = 0;
    let newEdges = 0;
    let objAchieved = false;

    // Parse node/edge counts from the next few entries
    for (let j = i + 1; j < Math.min(i + 3, history.length); j++) {
      const next = history[j].description.toLowerCase();
      const nodeMatch = next.match(/(\d+)\s*new\s*node/);
      const edgeMatch = next.match(/(\d+)\s*new\s*edge/);
      if (nodeMatch) newNodes += parseInt(nodeMatch[1]);
      if (edgeMatch) newEdges += parseInt(edgeMatch[1]);
      if (next.includes('objective achieved')) objAchieved = true;
    }

    // Update running state
    nodeCount += newNodes;
    edgeCount += newEdges;
    if (objAchieved) objectivesAchieved++;
    if (desc.includes('admin') || desc.includes('session')) accessLevel = 'user';
    if (desc.includes('domain admin') || desc.includes('da ')) accessLevel = 'domain_admin';

    // Compute reward
    let reward = 0;
    reward += newNodes * 0.5;
    reward += newEdges * 0.3;
    if (objAchieved) reward += 5.0;
    if (desc.includes('admin_to') || desc.includes('has_session')) reward += 1.0;
    if (desc.includes('owns_cred')) reward += 1.0;
    if (desc.includes('fail') || desc.includes('denied')) reward -= 0.1;

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
    });
    step++;
  }

  return traces;
}

// ============================================================
// Full Retrospective
// ============================================================

export function runRetrospective(input: RetrospectiveInput): RetrospectiveResult {
  const inferenceSuggestions = analyzeInferenceGaps(input);
  const skillGaps = analyzeSkillGaps(input);
  const scoring = analyzeScoring(input);
  const reportMarkdown = generateReport(input);
  const trainingTraces = exportTrainingTraces(input);

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
    `Scoring recommendations: ${scoring.rationale.length} suggestions`,
    `Training traces: ${trainingTraces.length} steps`,
  ];

  return {
    inference_suggestions: inferenceSuggestions,
    skill_gaps: skillGaps,
    scoring,
    report_markdown: reportMarkdown,
    training_traces: trainingTraces,
    summary: summaryLines.join('\n'),
  };
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
