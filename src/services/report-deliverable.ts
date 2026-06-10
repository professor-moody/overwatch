import type { EngagementConfig, ExportedGraph } from '../types.js';
import type { FindingSeverity, ReportFinding, ReportProfile } from './report-generator.js';
import type { TrustSignalDto } from './trust-signal-summary.js';
import { displayFindingShortTitle } from './finding-presentation.js';

export type RiskPosture = 'critical' | 'elevated' | 'moderate' | 'low';

export interface ReportExecutiveSummary {
  profile: ReportProfile;
  risk_posture: RiskPosture;
  headline: string;
  scope_summary: string;
  objective_summary: string;
  finding_summary: string;
  evidence_summary: string;
  verification_summary: string;
  top_risk_themes: string[];
}

export type ActionPlanPriority = 'immediate' | 'near_term' | 'validation';

export interface ReportActionPlanItem {
  id: string;
  priority: ActionPlanPriority;
  title: string;
  action: string;
  rationale: string;
  verification: string;
  related_finding_ids: string[];
  related_findings: string[];
}

export interface DeliverableBuildInput {
  config: EngagementConfig;
  graph: ExportedGraph;
  findings: ReportFinding[];
  profile?: ReportProfile;
  evidenceCount?: number;
  trustSignals?: TrustSignalDto[];
}

const SEVERITY_ORDER: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
const ACTION_GROUP_ORDER = [
  'credential-rotation',
  'session-revocation',
  'cloud-permissions',
  'cloud-public-exposure',
  'application-authorization',
  'administrative-access-review',
  'verification-backlog',
];

export function buildExecutiveSummary(input: DeliverableBuildInput): ReportExecutiveSummary {
  const { config, graph, findings } = input;
  const profile = input.profile ?? 'operator';
  const counts = severityCounts(findings);
  const achieved = config.objectives.filter(obj => obj.achieved).length;
  const totalObjectives = config.objectives.length;
  const inferredEdges = graph.edges.filter(edge => !!edge.properties.inferred_by_rule && !edge.properties.confirmed_at).length;
  const estimatedCvss = findings.filter(finding => finding.cvss_estimated).length;
  const posture = riskPosture(counts);
  const themes = topRiskThemes(findings);
  const evidenceCount = input.evidenceCount ?? findings.reduce((count, finding) => count + (finding.proof_cards?.length ?? finding.evidence.length), 0);
  const trustCount = input.trustSignals?.length ?? 0;

  return {
    profile,
    risk_posture: posture,
    headline: headlineFor(posture, findings.length, themes),
    scope_summary: scopeSummary(config),
    objective_summary: totalObjectives === 0
      ? 'No explicit objectives were configured for this report.'
      : `${achieved} of ${totalObjectives} engagement objective${totalObjectives === 1 ? '' : 's'} ${achieved === 1 ? 'was' : 'were'} achieved.`,
    finding_summary: `${findings.length} reportable finding${findings.length === 1 ? '' : 's'} were identified${severitySentence(counts)}.`,
    evidence_summary: evidenceCount > 0
      ? `${evidenceCount} cited evidence artifact${evidenceCount === 1 ? '' : 's'} support the reported findings.`
      : 'No evidence artifacts were cited in this report profile.',
    verification_summary: verificationSummary({ inferredEdges, estimatedCvss, trustCount }),
    top_risk_themes: themes,
  };
}

export function buildActionPlan(input: DeliverableBuildInput): ReportActionPlanItem[] {
  const { findings, graph, config } = input;
  const groups: ReportActionPlanItem[] = [];

  const credentialFindings = findings.filter(finding => finding.category === 'credential');
  if (credentialFindings.length > 0) {
    groups.push({
      id: 'credential-rotation',
      priority: priorityFor(credentialFindings),
      title: 'Rotate and invalidate exposed credentials',
      action: 'Rotate affected credentials, revoke active tokens and sessions, and verify that exposed material can no longer authenticate.',
      rationale: 'Validated or captured credential material can enable unauthorized access and lateral movement until it is invalidated.',
      verification: 'Retest the same credential paths and confirm authentication fails; review account logs for use during the exposure window.',
      related_finding_ids: credentialFindings.map(f => f.id),
      related_findings: credentialFindings.map(displayFindingShortTitle),
    });
  }

  const cloudIdentityFindings = findings.filter(finding =>
    finding.category === 'cloud_exposure' && /identity|role|policy|permission|trust/i.test(`${finding.title} ${finding.description}`),
  );
  if (cloudIdentityFindings.length > 0) {
    groups.push({
      id: 'cloud-permissions',
      priority: priorityFor(cloudIdentityFindings),
      title: 'Reduce cloud role permissions and trust paths',
      action: 'Scope down broad cloud policies, remove unnecessary trust relationships, and require stronger controls on roles reachable from CI or federated identity.',
      rationale: 'Reachable administrative cloud permissions can turn an application or identity foothold into control of cloud resources.',
      verification: 'Re-run role-assumption and policy-enumeration checks to confirm the privileged path is no longer reachable.',
      related_finding_ids: cloudIdentityFindings.map(f => f.id),
      related_findings: cloudIdentityFindings.map(displayFindingShortTitle),
    });
  }

  const publicCloudFindings = findings.filter(finding =>
    finding.category === 'cloud_exposure' && /public|resource|bucket|storage/i.test(`${finding.title} ${finding.description}`),
  );
  if (publicCloudFindings.length > 0) {
    groups.push({
      id: 'cloud-public-exposure',
      priority: priorityFor(publicCloudFindings),
      title: 'Remove public access from exposed cloud resources',
      action: 'Restrict public access, review resource policies, and enable provider-level public access guardrails where available.',
      rationale: 'Public resource exposure can disclose sensitive data or provide an entry point into adjacent cloud workloads.',
      verification: 'Confirm unauthenticated access is blocked and resource policy review shows only intended principals.',
      related_finding_ids: publicCloudFindings.map(f => f.id),
      related_findings: publicCloudFindings.map(displayFindingShortTitle),
    });
  }

  const applicationFindings = findings.filter(finding =>
    finding.category === 'webapp'
    || (finding.category === 'vulnerability' && /idor|authorization|application|web|xss|sql|csrf|ssrf|rce|injection/i.test(`${finding.title} ${finding.description}`)),
  );
  if (applicationFindings.length > 0) {
    groups.push({
      id: 'application-authorization',
      priority: priorityFor(applicationFindings),
      title: 'Fix application authorization controls',
      action: 'Enforce server-side authorization checks, retest affected workflows, and add regression coverage for cross-user or cross-tenant data access.',
      rationale: 'Application authorization flaws can expose sensitive business data and create pivots into identity or cloud systems.',
      verification: 'Repeat the original proof steps with multiple accounts and confirm unauthorized object access is denied.',
      related_finding_ids: applicationFindings.map(f => f.id),
      related_findings: applicationFindings.map(displayFindingShortTitle),
    });
  }

  const hostFindings = findings.filter(finding => finding.category === 'compromised_host');
  if (hostFindings.length > 0) {
    groups.push({
      id: 'session-revocation',
      priority: priorityFor(hostFindings),
      title: 'Revoke active sessions and review accessed hosts',
      action: 'Revoke active sessions, force re-authentication, rotate affected account credentials, and review host logs for persistence or follow-on access.',
      rationale: 'Confirmed host access provides an execution point for credential collection, discovery, and lateral movement.',
      verification: 'Confirm sessions are closed, affected credentials no longer authenticate, and endpoint logs show no continuing access.',
      related_finding_ids: hostFindings.map(f => f.id),
      related_findings: hostFindings.map(displayFindingShortTitle),
    });
  }

  const accessPathFindings = findings.filter(finding => finding.category === 'access_path');
  if (accessPathFindings.length > 0) {
    groups.push({
      id: 'administrative-access-review',
      priority: priorityFor(accessPathFindings),
      title: 'Review administrative access paths',
      action: 'Validate whether delegated administrative rights are required, remove stale privileges, and monitor for use of the path until remediated.',
      rationale: 'Unnecessary administrative paths can become immediate takeover routes when a related credential or principal is compromised.',
      verification: 'Re-enumerate access rights and confirm the affected principal no longer has administrative reach.',
      related_finding_ids: accessPathFindings.map(f => f.id),
      related_findings: accessPathFindings.map(displayFindingShortTitle),
    });
  }

  const inferredEdges = graph.edges.filter(edge => (edge.properties.confidence ?? 0) < 1.0 && !edge.properties.tested);
  const pendingObjectives = config.objectives.filter(objective => !objective.achieved);
  if (inferredEdges.length > 0 || pendingObjectives.length > 0) {
    groups.push({
      id: 'verification-backlog',
      priority: 'validation',
      title: 'Validate inferred paths and remaining objectives',
      action: 'Retest inferred relationships, parser caveats, and unfinished objectives before treating absence of evidence as final.',
      rationale: 'Unvalidated relationships can either hide residual risk or overstate attackability until independently confirmed.',
      verification: 'Close each inferred-path item with direct evidence or mark it out of scope with an explicit rationale.',
      related_finding_ids: [],
      related_findings: [
        inferredEdges.length > 0 ? `${inferredEdges.length} inferred relationship${inferredEdges.length === 1 ? '' : 's'}` : undefined,
        pendingObjectives.length > 0 ? `${pendingObjectives.length} pending objective${pendingObjectives.length === 1 ? '' : 's'}` : undefined,
      ].filter((value): value is string => !!value),
    });
  }

  return groups
    .map(item => ({
      ...item,
      related_findings: [...new Set(item.related_findings)],
      related_finding_ids: [...new Set(item.related_finding_ids)],
    }))
    .sort((a, b) =>
      priorityRank(a.priority) - priorityRank(b.priority)
      || groupRank(a.id) - groupRank(b.id)
      || a.title.localeCompare(b.title),
    );
}

function severityCounts(findings: ReportFinding[]): Record<FindingSeverity, number> {
  return SEVERITY_ORDER.reduce((acc, severity) => {
    acc[severity] = findings.filter(finding => finding.severity === severity).length;
    return acc;
  }, {} as Record<FindingSeverity, number>);
}

function riskPosture(counts: Record<FindingSeverity, number>): RiskPosture {
  if (counts.critical > 0) return 'critical';
  if (counts.high >= 3) return 'elevated';
  if (counts.high > 0 || counts.medium > 0) return 'moderate';
  return 'low';
}

function headlineFor(posture: RiskPosture, count: number, themes: string[]): string {
  if (count === 0) return 'The assessment did not identify reportable security findings from the available evidence.';
  const themeText = themes.length > 0 ? ` The primary themes were ${sentenceList(themes)}.` : '';
  switch (posture) {
    case 'critical': return `The assessment identified critical exposure that should be remediated immediately.${themeText}`;
    case 'elevated': return `The assessment identified elevated risk across multiple practical attack paths.${themeText}`;
    case 'moderate': return `The assessment identified security weaknesses that should be remediated through the normal risk process.${themeText}`;
    case 'low': return `The assessment identified limited reportable risk from the available evidence.${themeText}`;
  }
}

function scopeSummary(config: EngagementConfig): string {
  const parts = [
    config.scope.cidrs.length > 0 ? `${config.scope.cidrs.length} CIDR range${config.scope.cidrs.length === 1 ? '' : 's'}` : undefined,
    config.scope.domains.length > 0 ? `${config.scope.domains.length} domain${config.scope.domains.length === 1 ? '' : 's'}` : undefined,
    config.scope.url_patterns?.length ? `${config.scope.url_patterns.length} URL pattern${config.scope.url_patterns.length === 1 ? '' : 's'}` : undefined,
    config.scope.aws_accounts?.length ? `${config.scope.aws_accounts.length} AWS account${config.scope.aws_accounts.length === 1 ? '' : 's'}` : undefined,
    config.scope.azure_subscriptions?.length ? `${config.scope.azure_subscriptions.length} Azure subscription${config.scope.azure_subscriptions.length === 1 ? '' : 's'}` : undefined,
    config.scope.gcp_projects?.length ? `${config.scope.gcp_projects.length} GCP project${config.scope.gcp_projects.length === 1 ? '' : 's'}` : undefined,
  ].filter((value): value is string => !!value);
  return parts.length > 0 ? `Testing covered ${sentenceList(parts)}.` : 'Testing scope was defined in the engagement configuration.';
}

function severitySentence(counts: Record<FindingSeverity, number>): string {
  const parts = SEVERITY_ORDER
    .filter(severity => counts[severity] > 0)
    .map(severity => `${counts[severity]} ${severity}`);
  return parts.length > 0 ? ` (${parts.join(', ')})` : '';
}

function verificationSummary(input: { inferredEdges: number; estimatedCvss: number; trustCount: number }): string {
  const parts = [
    input.inferredEdges > 0 ? `${input.inferredEdges} inferred relationship${input.inferredEdges === 1 ? '' : 's'} still require validation` : undefined,
    input.estimatedCvss > 0 ? `${input.estimatedCvss} finding${input.estimatedCvss === 1 ? ' uses' : 's use'} estimated CVSS` : undefined,
    input.trustCount > 0 ? `${input.trustCount} operator verification signal${input.trustCount === 1 ? '' : 's'} were present` : undefined,
  ].filter((value): value is string => !!value);
  return parts.length > 0 ? `${sentenceList(parts)}.` : 'No material parser, scoring, or inferred-path caveats were identified for this report.';
}

function topRiskThemes(findings: ReportFinding[]): string[] {
  const themes = new Set<string>();
  if (findings.some(f => f.category === 'cloud_exposure' && /role|identity|policy|permission|trust/i.test(`${f.title} ${f.description}`))) {
    themes.add('cloud permission paths');
  }
  if (findings.some(f => f.category === 'credential')) themes.add('credential exposure');
  if (findings.some(f => f.category === 'webapp' || /idor|authorization/i.test(`${f.title} ${f.description}`))) {
    themes.add('application authorization');
  }
  if (findings.some(f => f.category === 'cloud_exposure' && /public|resource|bucket|storage/i.test(`${f.title} ${f.description}`))) {
    themes.add('public cloud exposure');
  }
  if (findings.some(f => f.category === 'compromised_host' || f.category === 'access_path')) {
    themes.add('host and administrative access');
  }
  return [...themes].slice(0, 4);
}

function priorityFor(findings: ReportFinding[]): ActionPlanPriority {
  if (findings.some(finding => finding.severity === 'critical' || finding.severity === 'high')) return 'immediate';
  if (findings.some(finding => finding.severity === 'medium')) return 'near_term';
  return 'validation';
}

function priorityRank(priority: ActionPlanPriority): number {
  switch (priority) {
    case 'immediate': return 0;
    case 'near_term': return 1;
    case 'validation': return 2;
  }
}

function groupRank(id: string): number {
  const index = ACTION_GROUP_ORDER.indexOf(id);
  return index === -1 ? ACTION_GROUP_ORDER.length : index;
}

function sentenceList(values: string[]): string {
  const unique = [...new Set(values)];
  if (unique.length === 0) return '';
  if (unique.length === 1) return unique[0];
  if (unique.length === 2) return `${unique[0]} and ${unique[1]}`;
  return `${unique.slice(0, -1).join(', ')}, and ${unique[unique.length - 1]}`;
}
