import type { ExportedGraph, NodeProperties } from '../types.js';
import type { ReportFinding } from './report-generator.js';

export interface FindingPresentation {
  title: string;
  summary: string;
  impact: string;
  evidence_claim?: string;
  technical_context?: string;
  remediation_steps: string[];
}

export interface PresentFindingOptions {
  graph?: ExportedGraph;
}

export function presentFinding(finding: ReportFinding, opts: PresentFindingOptions = {}): FindingPresentation {
  const graph = opts.graph;
  const nodeIndex = graph ? buildNodeIndex(graph) : new Map<string, NodeProperties>();
  const primary = resolvePrimaryNode(finding, nodeIndex);
  const asset = primary ? nodeLabel(primary) : firstAsset(finding);
  const originalContext = compactWhitespace(finding.description);
  const remediationSteps = parseRemediationSteps(finding.remediation);

  let presentation: FindingPresentation;
  switch (finding.category) {
    case 'compromised_host':
      presentation = presentHostFinding(finding, primary, asset, remediationSteps);
      break;
    case 'access_path':
      presentation = presentAccessPathFinding(finding, asset, remediationSteps);
      break;
    case 'credential':
      presentation = presentCredentialFinding(finding, graph, nodeIndex, remediationSteps);
      break;
    case 'vulnerability':
      presentation = presentVulnerabilityFinding(finding, primary, asset, remediationSteps);
      break;
    case 'cloud_exposure':
      presentation = presentCloudFinding(finding, primary, asset, remediationSteps);
      break;
    case 'webapp':
      presentation = presentWebappFinding(finding, primary, asset, remediationSteps);
      break;
    default:
      presentation = {
        title: stripLegacyPrefix(finding.title),
        summary: originalContext || 'The engagement identified a reportable security condition.',
        impact: impactFromSeverity(finding.severity),
        evidence_claim: evidenceClaimFor(finding),
        technical_context: originalContext,
        remediation_steps: remediationSteps,
      };
  }

  return {
    ...presentation,
    title: cleanClientText(presentation.title),
    summary: cleanClientText(presentation.summary),
    impact: cleanClientText(presentation.impact),
    evidence_claim: presentation.evidence_claim ? cleanClientText(presentation.evidence_claim) : undefined,
    technical_context: presentation.technical_context || originalContext,
    remediation_steps: presentation.remediation_steps.length > 0
      ? presentation.remediation_steps.map(step => cleanClientText(step))
      : remediationSteps.map(step => cleanClientText(step)),
  };
}

export function displayFindingTitle(finding: ReportFinding): string {
  return finding.presentation?.title || finding.title;
}

export function displayFindingSummary(finding: ReportFinding): string {
  return finding.presentation?.summary || finding.description;
}

export function displayFindingImpact(finding: ReportFinding): string {
  return finding.presentation?.impact || impactFromSeverity(finding.severity);
}

export function displayFindingRemediation(finding: ReportFinding): string {
  const steps = finding.presentation?.remediation_steps;
  if (!steps || steps.length === 0) return finding.remediation;
  return steps.map((step, index) => `${index + 1}. ${step}`).join('\n');
}

export function displayFindingCategory(category: ReportFinding['category'] | string): string {
  switch (category) {
    case 'compromised_host': return 'Confirmed access';
    case 'credential': return 'Credential exposure';
    case 'vulnerability': return 'Vulnerability';
    case 'access_path': return 'Administrative path';
    case 'cloud_exposure': return 'Cloud exposure';
    case 'webapp': return 'Application exposure';
    default: return String(category).replace(/_/g, ' ');
  }
}

function presentHostFinding(
  finding: ReportFinding,
  node: NodeProperties | undefined,
  asset: string,
  remediationSteps: string[],
): FindingPresentation {
  const domainJoined = node?.domain_joined === true;
  const admin = finding.severity === 'critical' || /\badministrative\b/i.test(finding.description);
  const os = node?.os ? ` The host is running ${node.os}.` : '';
  return {
    title: admin ? `Administrative access confirmed on ${asset}` : `Confirmed host access on ${asset}`,
    summary: `${asset} was confirmed accessible during the engagement${domainJoined ? ' and is joined to the domain' : ''}.${os}`.trim(),
    impact: domainJoined
      ? 'A confirmed foothold on a domain-joined system can support credential theft, lateral movement, and broader access to internal resources.'
      : 'A confirmed host foothold gives an attacker an execution point for follow-on discovery and lateral movement.',
    evidence_claim: `Access to ${asset} was confirmed by engagement activity and linked evidence.`,
    technical_context: finding.description,
    remediation_steps: remediationSteps,
  };
}

function presentAccessPathFinding(
  finding: ReportFinding,
  asset: string,
  remediationSteps: string[],
): FindingPresentation {
  const [host, principal] = finding.affected_assets;
  return {
    title: `Administrative rights expose ${host || asset}`,
    summary: `${principal || 'A privileged principal'} has administrative rights to ${host || asset}, even though no live session or command execution has been recorded for that host.`,
    impact: 'The access path may allow rapid host takeover if the principal or its credentials are abused.',
    evidence_claim: `Administrative reach to ${host || asset} is represented in the engagement graph and related evidence.`,
    technical_context: finding.description,
    remediation_steps: remediationSteps,
  };
}

function presentCredentialFinding(
  finding: ReportFinding,
  graph: ExportedGraph | undefined,
  nodeIndex: Map<string, NodeProperties>,
  remediationSteps: string[],
): FindingPresentation {
  const credentialNodes = graph?.nodes
    .map(n => n.properties)
    .filter(n => n.type === 'credential' && finding.affected_assets.some(asset => matchesNodeAsset(n, asset))) ?? [];
  const representative = credentialNodes[0];
  const user = representative?.cred_user || representative?.label || firstAsset(finding);
  const kind = representative ? humanCredentialKind(representative) : inferCredentialKindFromText(finding.title, finding.description);
  const confirmedTargets = credentialNodes.flatMap(node => confirmedTargetsFor(node, graph, nodeIndex));
  const reachable = confirmedTargets.length > 0 || /confirmed authentication path|confirmed reachability/i.test(finding.description);
  const total = credentialNodes.length || finding.affected_assets.length || 1;

  return {
    title: total === 1
      ? `${kind} for ${user} requires rotation${reachable ? ' after confirmed authentication' : ''}`
      : `${total} captured credentials require rotation${reachable ? ' after confirmed authentication' : ''}`,
    summary: reachable
      ? `Captured credential material was validated against ${listPhrase(confirmedTargets.slice(0, 3)) || 'an in-scope target'}, confirming it can support authentication.`
      : `Captured credential material for ${listPhrase(finding.affected_assets.slice(0, 3)) || user} was recorded and should be treated as exposed until rotated.`,
    impact: representative?.privileged
      ? 'Privileged credential exposure can permit broad administrative action and should be treated as a potential account compromise.'
      : 'Reusable credential material can enable unauthorized access, lateral movement, and persistence if not rotated quickly.',
    evidence_claim: 'Credential capture and validation evidence supports the exposure and reachability assessment.',
    technical_context: finding.description,
    remediation_steps: remediationSteps,
  };
}

function presentVulnerabilityFinding(
  finding: ReportFinding,
  node: NodeProperties | undefined,
  asset: string,
  remediationSteps: string[],
): FindingPresentation {
  const vulnName = node?.cve || node?.label || stripLegacyPrefix(finding.title);
  const affected = finding.affected_assets.length > 0 ? listPhrase(finding.affected_assets.slice(0, 3)) : asset;
  const exploitable = node?.exploitable === true || /successfully exploited|exploitable: yes/i.test(finding.description);
  return {
    title: exploitable ? `${vulnName} is exploitable on ${affected}` : `${vulnName} affects ${affected}`,
    summary: `${vulnName} was identified on ${affected}${node?.cvss !== undefined ? ` with CVSS ${node.cvss}` : ''}.`,
    impact: exploitable
      ? 'Successful exploitation can provide unauthorized access or control of the affected service or host.'
      : 'The vulnerability increases attack surface and should be remediated before it can be chained with other weaknesses.',
    evidence_claim: `Evidence links ${vulnName} to the affected asset set.`,
    technical_context: finding.description,
    remediation_steps: remediationSteps,
  };
}

function presentCloudFinding(
  finding: ReportFinding,
  node: NodeProperties | undefined,
  asset: string,
  remediationSteps: string[],
): FindingPresentation {
  if (node?.type === 'cloud_resource' || /^Cloud Resource:/i.test(finding.title)) {
    const publicResource = node?.public === true || /publicly accessible/i.test(finding.description);
    return {
      title: publicResource ? `Public cloud resource exposure affects ${asset}` : `Cloud resource misconfiguration affects ${asset}`,
      summary: `${asset} was identified as a cloud resource with exposure or misconfiguration risk${node?.region ? ` in ${node.region}` : ''}.`,
      impact: publicResource
        ? 'Public access can expose sensitive data or create an entry point into the cloud environment.'
        : 'Misconfigured cloud resources can expand blast radius and weaken containment around sensitive workloads.',
      evidence_claim: `Cloud enumeration evidence supports the exposure assessment for ${asset}.`,
      technical_context: finding.description,
      remediation_steps: remediationSteps,
    };
  }

  const admin = finding.severity === 'critical' || /administrator|admin|fullaccess|\*/i.test(finding.description);
  return {
    title: admin ? `Administrative cloud role is reachable: ${asset}` : `Cloud identity permissions require review: ${asset}`,
    summary: `${asset} has cloud permissions or trust relationships that can be abused from the observed access path.`,
    impact: admin
      ? 'Broad cloud permissions can enable account takeover, data access, and changes to production infrastructure.'
      : 'Excessive or trusted cloud identity permissions can allow privilege expansion beyond the originally compromised asset.',
    evidence_claim: `Cloud identity and policy evidence supports the permission-risk assessment for ${asset}.`,
    technical_context: finding.description,
    remediation_steps: remediationSteps,
  };
}

function presentWebappFinding(
  finding: ReportFinding,
  node: NodeProperties | undefined,
  asset: string,
  remediationSteps: string[],
): FindingPresentation {
  const ownRefs = new Set([asset, node?.url, node?.label, node?.id].filter((value): value is string => !!value));
  const vulnAssets = finding.affected_assets.filter(a => !ownRefs.has(a));
  const vulnLabel = vulnAssets[0] || extractAfter(finding.description, 'Vulnerabilities:') || 'application weakness';
  const auth = /authenticated via|has login form/i.test(finding.description) || node?.has_login_form === true;
  return {
    title: `${asset} exposes ${humanizeVulnerabilityLabel(vulnLabel)}`,
    summary: `${asset} was assessed as an application finding${auth ? ' in an authenticated context' : ''}${node?.technology ? ` on ${node.technology}` : ''}.`,
    impact: 'Application weaknesses can expose data, weaken authentication boundaries, or provide a path into adjacent identity and cloud systems.',
    evidence_claim: `Application testing evidence supports the finding on ${asset}.`,
    technical_context: finding.description,
    remediation_steps: remediationSteps,
  };
}

function buildNodeIndex(graph: ExportedGraph): Map<string, NodeProperties> {
  const index = new Map<string, NodeProperties>();
  for (const n of graph.nodes) {
    const props = n.properties;
    const keys = [
      n.id,
      props.id,
      props.label,
      props.ip,
      props.hostname,
      props.username,
      props.cred_user,
      props.url,
      props.cve,
      props.arn,
      props.provider_resource_id,
    ].filter((value): value is string => typeof value === 'string' && value.length > 0);
    for (const key of keys) index.set(key, props);
  }
  return index;
}

function resolvePrimaryNode(finding: ReportFinding, index: Map<string, NodeProperties>): NodeProperties | undefined {
  const idSuffixes = [
    finding.id.replace(/^finding-host-/, ''),
    finding.id.replace(/^finding-access-[^-]+-/, ''),
    finding.id.replace(/^finding-vuln-/, ''),
    finding.id.replace(/^finding-cloud-/, ''),
    finding.id.replace(/^finding-webapp-/, ''),
  ];
  for (const id of idSuffixes) {
    const node = index.get(id);
    if (node) return node;
  }
  for (const asset of finding.affected_assets) {
    const node = index.get(asset);
    if (node) return node;
  }
  return undefined;
}

function confirmedTargetsFor(node: NodeProperties, graph: ExportedGraph | undefined, nodeIndex: Map<string, NodeProperties>): string[] {
  if (!graph) return [];
  return graph.edges
    .filter(e => e.source === node.id && ['VALID_ON', 'VALID_FOR_APP', 'VALID_FOR_IDP_PRINCIPAL', 'ASSUMES_ROLE'].includes(String(e.properties.type)) && (e.properties.confidence ?? 0) >= 0.9)
    .map(e => nodeLabel(nodeIndex.get(e.target)) || e.target);
}

function matchesNodeAsset(node: NodeProperties, asset: string): boolean {
  return [
    node.id,
    node.label,
    node.ip,
    node.hostname,
    node.username,
    node.cred_user,
    node.url,
    node.cve,
    node.arn,
    node.provider_resource_id,
  ].some(value => value === asset);
}

function nodeLabel(node?: NodeProperties): string {
  if (!node) return '';
  return node.label || node.hostname || node.ip || node.username || node.cred_user || node.url || node.id;
}

function firstAsset(finding: ReportFinding): string {
  return finding.affected_assets[0] || stripLegacyPrefix(finding.title) || finding.id;
}

function parseRemediationSteps(remediation: string): string[] {
  return remediation
    .split(/\n+/)
    .map(line => line.trim().replace(/^\d+\.\s*/, '').replace(/\*\*/g, ''))
    .filter(Boolean);
}

function impactFromSeverity(severity: ReportFinding['severity']): string {
  switch (severity) {
    case 'critical': return 'This finding can materially affect confidentiality, integrity, or availability and should be remediated immediately.';
    case 'high': return 'This finding creates a practical path to unauthorized access or privilege expansion.';
    case 'medium': return 'This finding increases exposure and should be remediated in the normal security backlog.';
    case 'low': return 'This finding represents a lower-risk weakness or hardening opportunity.';
    case 'info': return 'This item provides context for security operations and future verification.';
  }
}

function evidenceClaimFor(finding: ReportFinding): string {
  if (finding.evidence.length > 0) return 'Linked engagement evidence supports this finding.';
  return 'The finding is derived from the current engagement graph.';
}

function humanCredentialKind(node: NodeProperties): string {
  const kind = node.cred_material_kind || node.cred_type || 'credential';
  return humanCredentialKindFromString(kind);
}

function inferCredentialKindFromText(...values: string[]): string {
  return humanCredentialKindFromString(values.join(' '));
}

function humanCredentialKindFromString(value: string): string {
  const lower = value.toLowerCase();
  if (lower.includes('ntlm')) return 'Windows password hash';
  if (lower.includes('plaintext') || lower.includes('password')) return 'password';
  if (lower.includes('oidc')) return 'OIDC token';
  if (lower.includes('saml')) return 'SAML assertion';
  if (lower.includes('oauth')) return 'OAuth secret';
  if (lower.includes('pat')) return 'personal access token';
  if (lower.includes('session_cookie')) return 'session cookie';
  if (lower.includes('kerberos')) return 'Kerberos material';
  if (lower.includes('certificate')) return 'certificate credential';
  if (lower.includes('ssh')) return 'SSH key';
  if (lower.includes('aes')) return 'Kerberos key material';
  return 'credential';
}

function humanizeVulnerabilityLabel(value: string): string {
  const lower = value.toLowerCase();
  if (lower.includes('idor')) return 'an authorization flaw';
  if (lower.includes('ssrf')) return 'a server-side request forgery risk';
  if (lower.includes('sqli') || lower.includes('sql injection')) return 'a SQL injection risk';
  if (lower.includes('xss')) return 'a cross-site scripting risk';
  return value;
}

function listPhrase(values: string[]): string {
  const unique = [...new Set(values.filter(Boolean))];
  if (unique.length === 0) return '';
  if (unique.length === 1) return unique[0];
  if (unique.length === 2) return `${unique[0]} and ${unique[1]}`;
  return `${unique.slice(0, -1).join(', ')}, and ${unique[unique.length - 1]}`;
}

function stripLegacyPrefix(value: string): string {
  return value.replace(/^(Compromised Host|Administrative Access Path|Credential Obtained|Vulnerability|Cloud Identity|Cloud Resource|Web Application):\s*/i, '');
}

function extractAfter(value: string, marker: string): string | undefined {
  const index = value.toLowerCase().indexOf(marker.toLowerCase());
  if (index === -1) return undefined;
  return value.slice(index + marker.length).split('.')[0]?.trim();
}

function compactWhitespace(value: string): string {
  return value.replace(/\s+/g, ' ').trim();
}

function cleanClientText(value: string): string {
  return value
    .replace(/\bHAS_SESSION\b/g, 'active session')
    .replace(/\bADMIN_TO\b/g, 'administrative access')
    .replace(/\bOWNS_CRED\b/g, 'credential ownership')
    .replace(/\bVALID_ON\b/g, 'valid service authentication')
    .replace(/\bVALID_FOR_APP\b/g, 'valid application authentication')
    .replace(/\bVALID_FOR_IDP_PRINCIPAL\b/g, 'valid identity-provider authentication')
    .replace(/\bASSUMES_ROLE\b/g, 'role assumption')
    .replace(/\bcloud_identity\b/g, 'cloud identity')
    .replace(/\bcloud_resource\b/g, 'cloud resource')
    .replace(/\bntlm_hash\b/g, 'Windows password hash')
    .replace(/\boidc_access_token\b/g, 'OIDC access token')
    .replace(/\bplaintext_password\b/g, 'password')
    .replace(/\s+/g, ' ')
    .trim();
}
