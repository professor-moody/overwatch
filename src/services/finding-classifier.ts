// ============================================================
// Overwatch — Finding Classifier
// Maps findings to compliance frameworks (OWASP Top 10, NIST 800-53,
// PCI DSS) and MITRE ATT&CK techniques via CWE and edge type heuristics.
// ============================================================

import type { ReportFinding } from './report-generator.js';
import type { NodeProperties, ExportedGraph } from '../types.js';

// ============================================================
// Types
// ============================================================

export interface FindingClassification {
  cwe?: string;
  cwe_name?: string;
  owasp_category?: string;
  nist_controls: string[];
  pci_requirements: string[];
  attack_techniques: AttackTechnique[];
}

export interface AttackTechnique {
  id: string;       // e.g. T1003.006
  name: string;
}

// ============================================================
// CWE Mapping Tables
// ============================================================

// CWE → OWASP Top 10 (2021)
const CWE_TO_OWASP: Record<string, string> = {
  'CWE-79':   'A03:2021 Injection',
  'CWE-89':   'A03:2021 Injection',
  'CWE-94':   'A03:2021 Injection',
  'CWE-77':   'A03:2021 Injection',
  'CWE-78':   'A03:2021 Injection',
  'CWE-90':   'A03:2021 Injection',
  'CWE-91':   'A03:2021 Injection',
  'CWE-917':  'A03:2021 Injection',
  'CWE-74':   'A03:2021 Injection',
  'CWE-116':  'A03:2021 Injection',
  'CWE-287':  'A07:2021 Identification and Authentication Failures',
  'CWE-306':  'A07:2021 Identification and Authentication Failures',
  'CWE-307':  'A07:2021 Identification and Authentication Failures',
  'CWE-521':  'A07:2021 Identification and Authentication Failures',
  'CWE-522':  'A07:2021 Identification and Authentication Failures',
  'CWE-798':  'A07:2021 Identification and Authentication Failures',
  'CWE-620':  'A07:2021 Identification and Authentication Failures',
  'CWE-640':  'A07:2021 Identification and Authentication Failures',
  'CWE-256':  'A07:2021 Identification and Authentication Failures',
  'CWE-257':  'A07:2021 Identification and Authentication Failures',
  'CWE-261':  'A02:2021 Cryptographic Failures',
  'CWE-310':  'A02:2021 Cryptographic Failures',
  'CWE-311':  'A02:2021 Cryptographic Failures',
  'CWE-319':  'A02:2021 Cryptographic Failures',
  'CWE-327':  'A02:2021 Cryptographic Failures',
  'CWE-328':  'A02:2021 Cryptographic Failures',
  'CWE-330':  'A02:2021 Cryptographic Failures',
  'CWE-916':  'A02:2021 Cryptographic Failures',
  'CWE-200':  'A01:2021 Broken Access Control',
  'CWE-284':  'A01:2021 Broken Access Control',
  'CWE-285':  'A01:2021 Broken Access Control',
  'CWE-352':  'A01:2021 Broken Access Control',
  'CWE-639':  'A01:2021 Broken Access Control',
  'CWE-862':  'A01:2021 Broken Access Control',
  'CWE-863':  'A01:2021 Broken Access Control',
  'CWE-918':  'A10:2021 Server-Side Request Forgery',
  'CWE-16':   'A05:2021 Security Misconfiguration',
  'CWE-2':    'A05:2021 Security Misconfiguration',
  'CWE-209':  'A05:2021 Security Misconfiguration',
  'CWE-532':  'A09:2021 Security Logging and Monitoring Failures',
  'CWE-778':  'A09:2021 Security Logging and Monitoring Failures',
  'CWE-502':  'A08:2021 Software and Data Integrity Failures',
  'CWE-829':  'A08:2021 Software and Data Integrity Failures',
  'CWE-1104': 'A06:2021 Vulnerable and Outdated Components',
  'CWE-937':  'A06:2021 Vulnerable and Outdated Components',
  'CWE-611':  'A05:2021 Security Misconfiguration',
  'CWE-776':  'A05:2021 Security Misconfiguration',
};

// CWE → NIST 800-53 control families
const CWE_TO_NIST: Record<string, string[]> = {
  'CWE-79':   ['SI-10', 'SI-15'],
  'CWE-89':   ['SI-10'],
  'CWE-94':   ['SI-10', 'SI-3'],
  'CWE-78':   ['SI-10', 'SI-3'],
  'CWE-77':   ['SI-10'],
  'CWE-918':  ['SC-7', 'SI-10'],
  'CWE-287':  ['IA-2', 'IA-5'],
  'CWE-306':  ['IA-2'],
  'CWE-307':  ['AC-7'],
  'CWE-521':  ['IA-5'],
  'CWE-522':  ['IA-5', 'SC-13'],
  'CWE-798':  ['IA-5'],
  'CWE-256':  ['IA-5', 'SC-28'],
  'CWE-257':  ['IA-5', 'SC-28'],
  'CWE-284':  ['AC-3', 'AC-6'],
  'CWE-285':  ['AC-3'],
  'CWE-862':  ['AC-3'],
  'CWE-863':  ['AC-3'],
  'CWE-639':  ['AC-3'],
  'CWE-352':  ['SC-23'],
  'CWE-200':  ['AC-3', 'SC-28'],
  'CWE-311':  ['SC-8', 'SC-28'],
  'CWE-319':  ['SC-8'],
  'CWE-327':  ['SC-13'],
  'CWE-330':  ['SC-13'],
  'CWE-916':  ['SC-13', 'IA-5'],
  'CWE-16':   ['CM-6', 'CM-7'],
  'CWE-209':  ['SI-11'],
  'CWE-532':  ['AU-3', 'AU-9'],
  'CWE-778':  ['AU-2', 'AU-12'],
  'CWE-502':  ['SI-10'],
  'CWE-611':  ['SI-10'],
};

// CWE → PCI DSS v4.0 requirements
const CWE_TO_PCI: Record<string, string[]> = {
  'CWE-79':   ['6.2.4'],
  'CWE-89':   ['6.2.4'],
  'CWE-94':   ['6.2.4'],
  'CWE-78':   ['6.2.4'],
  'CWE-918':  ['6.2.4'],
  'CWE-287':  ['8.3'],
  'CWE-306':  ['8.3'],
  'CWE-307':  ['8.3.4'],
  'CWE-521':  ['8.3.6'],
  'CWE-522':  ['8.3.2'],
  'CWE-798':  ['2.2.7', '8.6'],
  'CWE-256':  ['8.3.2'],
  'CWE-284':  ['7.2'],
  'CWE-285':  ['7.2'],
  'CWE-862':  ['7.2'],
  'CWE-311':  ['4.2.1'],
  'CWE-319':  ['4.2.1'],
  'CWE-327':  ['4.2.1'],
  'CWE-16':   ['2.2'],
  'CWE-532':  ['10.3'],
  'CWE-778':  ['10.2'],
  'CWE-1104': ['6.3.2'],
};

// vuln_type → CWE (heuristic auto-detection)
const VULN_TYPE_TO_CWE: Record<string, { cwe: string; name: string }> = {
  'sqli':       { cwe: 'CWE-89',  name: 'SQL Injection' },
  'sql_injection': { cwe: 'CWE-89',  name: 'SQL Injection' },
  'xss':        { cwe: 'CWE-79',  name: 'Cross-site Scripting' },
  'ssrf':       { cwe: 'CWE-918', name: 'Server-Side Request Forgery' },
  'rce':        { cwe: 'CWE-94',  name: 'Code Injection' },
  'command_injection': { cwe: 'CWE-78',  name: 'OS Command Injection' },
  'lfi':        { cwe: 'CWE-98',  name: 'Local File Inclusion' },
  'rfi':        { cwe: 'CWE-98',  name: 'Remote File Inclusion' },
  'path_traversal': { cwe: 'CWE-22',  name: 'Path Traversal' },
  'xxe':        { cwe: 'CWE-611', name: 'XML External Entity' },
  'idor':       { cwe: 'CWE-639', name: 'Insecure Direct Object Reference' },
  'csrf':       { cwe: 'CWE-352', name: 'Cross-Site Request Forgery' },
  'open_redirect': { cwe: 'CWE-601', name: 'Open Redirect' },
  'deserialization': { cwe: 'CWE-502', name: 'Insecure Deserialization' },
  'auth_bypass': { cwe: 'CWE-287', name: 'Improper Authentication' },
  'default_credentials': { cwe: 'CWE-798', name: 'Hard-coded Credentials' },
  'weak_password': { cwe: 'CWE-521', name: 'Weak Password Requirements' },
  'cleartext_storage': { cwe: 'CWE-256', name: 'Plaintext Storage of Password' },
  'cleartext_transmission': { cwe: 'CWE-319', name: 'Cleartext Transmission' },
  'missing_encryption': { cwe: 'CWE-311', name: 'Missing Encryption' },
  'information_disclosure': { cwe: 'CWE-200', name: 'Information Exposure' },
  'misconfiguration': { cwe: 'CWE-16', name: 'Configuration' },
};

// Edge type → ATT&CK technique (pentest-relevant mappings)
const EDGE_TO_ATTACK: Record<string, AttackTechnique> = {
  'CAN_DCSYNC':     { id: 'T1003.006', name: 'DCSync' },
  'KERBEROASTABLE': { id: 'T1558.003', name: 'Kerberoasting' },
  'AS_REP_ROASTABLE': { id: 'T1558.004', name: 'AS-REP Roasting' },
  'ADMIN_TO':       { id: 'T1021', name: 'Remote Services' },
  'HAS_SESSION':    { id: 'T1078', name: 'Valid Accounts' },
  'CAN_RDPINTO':    { id: 'T1021.001', name: 'Remote Desktop Protocol' },
  'CAN_PSREMOTE':   { id: 'T1021.006', name: 'Windows Remote Management' },
  'VALID_ON':       { id: 'T1078', name: 'Valid Accounts' },
  'OWNS_CRED':      { id: 'T1003', name: 'OS Credential Dumping' },
  'DERIVED_FROM':   { id: 'T1003', name: 'OS Credential Dumping' },
  'DUMPED_FROM':    { id: 'T1003', name: 'OS Credential Dumping' },
  'SHARED_CREDENTIAL': { id: 'T1110.001', name: 'Password Guessing' },
  'POTENTIAL_AUTH':  { id: 'T1110', name: 'Brute Force' },
  'TESTED_CRED':    { id: 'T1110', name: 'Brute Force' },
  'FORCE_CHANGE_PASSWORD': { id: 'T1098', name: 'Account Manipulation' },
  'ADD_MEMBER':     { id: 'T1098.007', name: 'Additional Cloud Credentials' },
  'GENERIC_ALL':    { id: 'T1222', name: 'File and Directory Permissions Modification' },
  'WRITE_DACL':     { id: 'T1222', name: 'File and Directory Permissions Modification' },
  'WRITE_OWNER':    { id: 'T1222', name: 'File and Directory Permissions Modification' },
  'GENERIC_WRITE':  { id: 'T1222', name: 'File and Directory Permissions Modification' },
  'WRITEABLE_BY':   { id: 'T1222', name: 'File and Directory Permissions Modification' },
  'DELEGATES_TO':   { id: 'T1558.001', name: 'Golden Ticket' },
  'ALLOWED_TO_ACT': { id: 'T1550.003', name: 'Pass the Ticket' },
  'RBCD_TARGET':    { id: 'T1550.003', name: 'Pass the Ticket' },
  'RELAY_TARGET':   { id: 'T1557.001', name: 'LLMNR/NBT-NS Poisoning' },
  'NULL_SESSION':   { id: 'T1021.002', name: 'SMB/Windows Admin Shares' },
  'ESC1':           { id: 'T1649', name: 'Steal or Forge Authentication Certificates' },
  'ESC2':           { id: 'T1649', name: 'Steal or Forge Authentication Certificates' },
  'ESC3':           { id: 'T1649', name: 'Steal or Forge Authentication Certificates' },
  'ESC4':           { id: 'T1649', name: 'Steal or Forge Authentication Certificates' },
  'ESC5':           { id: 'T1649', name: 'Steal or Forge Authentication Certificates' },
  'ESC6':           { id: 'T1649', name: 'Steal or Forge Authentication Certificates' },
  'ESC7':           { id: 'T1649', name: 'Steal or Forge Authentication Certificates' },
  'ESC8':           { id: 'T1649', name: 'Steal or Forge Authentication Certificates' },
  'ESC9':           { id: 'T1649', name: 'Steal or Forge Authentication Certificates' },
  'ESC10':          { id: 'T1649', name: 'Steal or Forge Authentication Certificates' },
  'ESC11':          { id: 'T1649', name: 'Steal or Forge Authentication Certificates' },
  'ESC12':          { id: 'T1649', name: 'Steal or Forge Authentication Certificates' },
  'ESC13':          { id: 'T1649', name: 'Steal or Forge Authentication Certificates' },
  'CAN_READ_LAPS':  { id: 'T1552.006', name: 'Group Policy Preferences' },
  'CAN_READ_GMSA':  { id: 'T1552', name: 'Unsecured Credentials' },
  'ASSUMES_ROLE':   { id: 'T1098.003', name: 'Additional Cloud Roles' },
  'HAS_POLICY':     { id: 'T1078.004', name: 'Cloud Accounts' },
  'MANAGED_BY':     { id: 'T1078.004', name: 'Cloud Accounts' },
  'EXPLOITS':       { id: 'T1190', name: 'Exploit Public-Facing Application' },
  'VULNERABLE_TO':  { id: 'T1190', name: 'Exploit Public-Facing Application' },
  'AUTH_BYPASS':    { id: 'T1548', name: 'Abuse Elevation Control Mechanism' },
  'HAS_ENDPOINT':   { id: 'T1595.002', name: 'Vulnerability Scanning' },
};

// vuln_type → ATT&CK technique
const VULN_TO_ATTACK: Record<string, AttackTechnique> = {
  'sqli':       { id: 'T1190', name: 'Exploit Public-Facing Application' },
  'sql_injection': { id: 'T1190', name: 'Exploit Public-Facing Application' },
  'xss':        { id: 'T1189', name: 'Drive-by Compromise' },
  'ssrf':       { id: 'T1190', name: 'Exploit Public-Facing Application' },
  'rce':        { id: 'T1059', name: 'Command and Scripting Interpreter' },
  'command_injection': { id: 'T1059', name: 'Command and Scripting Interpreter' },
  'deserialization': { id: 'T1190', name: 'Exploit Public-Facing Application' },
  'xxe':        { id: 'T1190', name: 'Exploit Public-Facing Application' },
  'lfi':        { id: 'T1005', name: 'Data from Local System' },
  'path_traversal': { id: 'T1005', name: 'Data from Local System' },
  'default_credentials': { id: 'T1078.001', name: 'Default Accounts' },
};

// Finding category → ATT&CK technique fallback
const CATEGORY_TO_ATTACK: Record<string, AttackTechnique> = {
  'compromised_host': { id: 'T1021', name: 'Remote Services' },
  'credential':       { id: 'T1003', name: 'OS Credential Dumping' },
  'vulnerability':    { id: 'T1190', name: 'Exploit Public-Facing Application' },
  'cloud_exposure':   { id: 'T1078.004', name: 'Cloud Accounts' },
  'webapp':           { id: 'T1190', name: 'Exploit Public-Facing Application' },
};

// ============================================================
// Classifier
// ============================================================

export function classifyFinding(
  finding: ReportFinding,
  nodeMap: Map<string, NodeProperties>,
  graph: ExportedGraph,
): FindingClassification {
  const classification: FindingClassification = {
    nist_controls: [],
    pci_requirements: [],
    attack_techniques: [],
  };

  // --- CWE detection ---
  let cweId: string | undefined;
  let cweName: string | undefined;

  // 1. Explicit CWE on vulnerability node
  for (const assetId of finding.affected_assets) {
    const node = nodeMap.get(assetId);
    if (!node) continue;
    if (node.type === 'vulnerability') {
      if (node.vuln_type) {
        const mapped = VULN_TYPE_TO_CWE[node.vuln_type];
        if (mapped) { cweId = mapped.cwe; cweName = mapped.name; break; }
      }
    }
  }

  // 2. Heuristic from finding title/description
  if (!cweId) {
    const text = `${finding.title} ${finding.description}`.toLowerCase();
    for (const [vtype, mapped] of Object.entries(VULN_TYPE_TO_CWE)) {
      if (text.includes(vtype.replace(/_/g, ' ')) || text.includes(vtype)) {
        cweId = mapped.cwe; cweName = mapped.name; break;
      }
    }
  }

  // 3. Category-based CWE fallback for credential findings
  if (!cweId && finding.category === 'credential') {
    cweId = 'CWE-522'; cweName = 'Insufficiently Protected Credentials';
  }

  if (cweId) {
    classification.cwe = cweId;
    classification.cwe_name = cweName;

    // Map to frameworks
    const owasp = CWE_TO_OWASP[cweId];
    if (owasp) classification.owasp_category = owasp;

    const nist = CWE_TO_NIST[cweId];
    if (nist) classification.nist_controls = nist;

    const pci = CWE_TO_PCI[cweId];
    if (pci) classification.pci_requirements = pci;
  }

  // --- ATT&CK technique detection ---
  const seenTechniques = new Set<string>();

  // From graph edges connected to finding's affected assets
  for (const assetId of finding.affected_assets) {
    for (const edge of graph.edges) {
      if (edge.source !== assetId && edge.target !== assetId) continue;
      const technique = EDGE_TO_ATTACK[edge.properties.type];
      if (technique && !seenTechniques.has(technique.id)) {
        seenTechniques.add(technique.id);
        classification.attack_techniques.push(technique);
      }
    }
  }

  // From vuln_type
  for (const assetId of finding.affected_assets) {
    const node = nodeMap.get(assetId);
    if (!node?.vuln_type) continue;
    const technique = VULN_TO_ATTACK[node.vuln_type];
    if (technique && !seenTechniques.has(technique.id)) {
      seenTechniques.add(technique.id);
      classification.attack_techniques.push(technique);
    }
  }

  // Category fallback
  if (classification.attack_techniques.length === 0) {
    const fallback = CATEGORY_TO_ATTACK[finding.category];
    if (fallback) classification.attack_techniques.push(fallback);
  }

  return classification;
}

// ============================================================
// ATT&CK Navigator Layer Export
// ============================================================

export function generateNavigatorLayer(
  findings: ReportFinding[],
  graph: ExportedGraph,
  engagementName: string,
): object {
  const nodeMap = new Map<string, NodeProperties>();
  for (const n of graph.nodes) nodeMap.set(n.id, n.properties);

  // Collect all technique IDs and their finding counts
  const techniqueCounts = new Map<string, { count: number; name: string }>();

  for (const finding of findings) {
    const classification = classifyFinding(finding, nodeMap, graph);
    for (const tech of classification.attack_techniques) {
      const existing = techniqueCounts.get(tech.id);
      if (existing) existing.count++;
      else techniqueCounts.set(tech.id, { count: 1, name: tech.name });
    }
  }

  // Also include ATT&CK techniques from edges not directly tied to findings
  for (const edge of graph.edges) {
    const tech = EDGE_TO_ATTACK[edge.properties.type];
    if (tech && !techniqueCounts.has(tech.id)) {
      techniqueCounts.set(tech.id, { count: 1, name: tech.name });
    }
  }

  const maxCount = Math.max(1, ...Array.from(techniqueCounts.values()).map(t => t.count));

  const techniques = Array.from(techniqueCounts.entries()).map(([techId, data]) => {
    // Split sub-technique notation (T1003.006 → tactic: T1003, sub: 006)
    const parts = techId.split('.');
    return {
      techniqueID: parts[0],
      ...(parts[1] ? { tactic: parts[0] } : {}),
      score: Math.round((data.count / maxCount) * 100),
      color: '',
      comment: `${data.count} finding(s): ${data.name}`,
      enabled: true,
      metadata: [],
      links: [],
      showSubtechniques: !!parts[1],
    };
  });

  return {
    name: `Overwatch: ${engagementName}`,
    versions: { attack: '14', navigator: '4.9.1', layer: '4.5' },
    domain: 'enterprise-attack',
    description: `ATT&CK coverage from Overwatch engagement: ${engagementName}`,
    filters: { platforms: ['Windows', 'Linux', 'macOS', 'Azure AD', 'Office 365', 'SaaS', 'IaaS', 'Network', 'Containers'] },
    sorting: 0,
    layout: { layout: 'side', aggregateFunction: 'average', showID: true, showName: true, showAggregateScores: true, countUnscored: false },
    hideDisabled: false,
    techniques,
    gradient: { colors: ['#ffffff', '#ff6666'], minValue: 0, maxValue: 100 },
    legendItems: [],
    metadata: [{ name: 'generated_by', value: 'Overwatch' }],
    links: [],
    showTacticRowBackground: true,
    tacticRowBackground: '#dddddd',
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
    selectVisibleTechniques: false,
  };
}

// ============================================================
// Bulk Classification
// ============================================================

export function classifyAllFindings(
  findings: ReportFinding[],
  graph: ExportedGraph,
): Map<string, FindingClassification> {
  const nodeMap = new Map<string, NodeProperties>();
  for (const n of graph.nodes) nodeMap.set(n.id, n.properties);

  const result = new Map<string, FindingClassification>();
  for (const finding of findings) {
    result.set(finding.id, classifyFinding(finding, nodeMap, graph));
  }
  return result;
}

// ============================================================
// ATT&CK Technique Scope Profiles (C1)
// ============================================================

/** Techniques expected per engagement profile. */
export const PROFILE_TECHNIQUE_SCOPE: Record<string, string[]> = {
  'internal-pentest': [
    'T1003', 'T1003.006', 'T1558.003', 'T1558.004', 'T1078', 'T1021', 'T1021.001', 'T1021.002', 'T1021.006',
    'T1098', 'T1110', 'T1110.001', 'T1222', 'T1550.003', 'T1557.001', 'T1552', 'T1552.006', 'T1649',
    'T1558.001', 'T1098.007',
  ],
  'goad_ad': [
    'T1003', 'T1003.006', 'T1558.003', 'T1558.004', 'T1078', 'T1021', 'T1021.001', 'T1021.002', 'T1021.006',
    'T1098', 'T1110', 'T1110.001', 'T1222', 'T1550.003', 'T1557.001', 'T1552', 'T1552.006', 'T1649',
    'T1558.001', 'T1098.007',
  ],
  'external-assessment': [
    'T1190', 'T1189', 'T1059', 'T1005', 'T1078.001', 'T1078.004',
    'T1595', 'T1592', 'T1589', 'T1590', 'T1591',
  ],
  'red-team': [
    // Full matrix — all known techniques
    ...Object.values(EDGE_TO_ATTACK).map(t => t.id),
    ...Object.values(VULN_TO_ATTACK).map(t => t.id),
    ...Object.values(CATEGORY_TO_ATTACK).map(t => t.id),
    'T1595', 'T1592', 'T1589', 'T1590', 'T1591',
    'T1566', 'T1199', 'T1133',
  ],
  'cloud-assessment': [
    'T1078.004', 'T1098.003', 'T1190', 'T1059', 'T1078.001',
    'T1580', 'T1538', 'T1619',
  ],
  'assumed-breach': [
    'T1003', 'T1003.006', 'T1558.003', 'T1558.004', 'T1078', 'T1021', 'T1021.001', 'T1021.002', 'T1021.006',
    'T1098', 'T1222', 'T1550.003', 'T1649', 'T1552', 'T1552.006',
  ],
  'ctf': [
    // Full matrix for labs
    ...Object.values(EDGE_TO_ATTACK).map(t => t.id),
    ...Object.values(VULN_TO_ATTACK).map(t => t.id),
    ...Object.values(CATEGORY_TO_ATTACK).map(t => t.id),
  ],
};

/**
 * Get the set of technique IDs expected for a given engagement profile.
 * Returns deduplicated sorted array.
 */
export function getTechniqueScope(profile: string): string[] {
  const raw = PROFILE_TECHNIQUE_SCOPE[profile] || PROFILE_TECHNIQUE_SCOPE['red-team'] || [];
  return [...new Set(raw)].sort();
}

// ============================================================
// ATT&CK Gap Analysis (C2)
// ============================================================

export interface GapItem {
  technique_id: string;
  name: string;
  reason_untested: string;
  suggested_action?: string;
}

export interface GapAnalysisResult {
  profile: string;
  total_in_scope: number;
  tested_count: number;
  untested_count: number;
  coverage_pct: number;
  gaps: GapItem[];
  tested: string[];
}

/** Build a set of technique IDs that have been exercised in the engagement. */
export function getTestedTechniques(
  findings: ReportFinding[],
  graph: ExportedGraph,
): Set<string> {
  const tested = new Set<string>();
  const nodeMap = new Map<string, NodeProperties>();
  for (const n of graph.nodes) nodeMap.set(n.id, n.properties);

  for (const finding of findings) {
    const cls = classifyFinding(finding, nodeMap, graph);
    for (const t of cls.attack_techniques) tested.add(t.id);
  }

  // Also include techniques from graph edges
  for (const edge of graph.edges) {
    const tech = EDGE_TO_ATTACK[edge.properties.type];
    if (tech) tested.add(tech.id);
  }

  return tested;
}

/** Compute ATT&CK gap analysis for the given profile. */
export function computeGapAnalysis(
  findings: ReportFinding[],
  graph: ExportedGraph,
  profile: string,
): GapAnalysisResult {
  const testedSet = getTestedTechniques(findings, graph);
  const scope = getTechniqueScope(profile);

  // Build a name lookup from all known mappings
  const nameLookup = new Map<string, string>();
  for (const t of Object.values(EDGE_TO_ATTACK)) nameLookup.set(t.id, t.name);
  for (const t of Object.values(VULN_TO_ATTACK)) nameLookup.set(t.id, t.name);
  for (const t of Object.values(CATEGORY_TO_ATTACK)) nameLookup.set(t.id, t.name);

  const gaps: GapItem[] = [];
  const tested: string[] = [];

  for (const techId of scope) {
    if (testedSet.has(techId)) {
      tested.push(techId);
    } else {
      gaps.push({
        technique_id: techId,
        name: nameLookup.get(techId) || techId,
        reason_untested: 'Not observed in findings or graph edges',
        suggested_action: `Consider testing ${nameLookup.get(techId) || techId} (${techId})`,
      });
    }
  }

  const totalInScope = scope.length;
  return {
    profile,
    total_in_scope: totalInScope,
    tested_count: tested.length,
    untested_count: gaps.length,
    coverage_pct: totalInScope > 0 ? Math.round((tested.length / totalInScope) * 100) : 100,
    gaps,
    tested,
  };
}

/**
 * Generate an ATT&CK Navigator layer with gap annotations.
 * Tested techniques are scored normally; untested in-scope techniques are shown in amber.
 */
export function generateNavigatorLayerWithGaps(
  findings: ReportFinding[],
  graph: ExportedGraph,
  engagementName: string,
  profile: string,
): object {
  const baseLayer = generateNavigatorLayer(findings, graph, engagementName) as any;
  const gapResult = computeGapAnalysis(findings, graph, profile);

  // Add untested techniques with gap annotation
  const existingIds = new Set(baseLayer.techniques.map((t: any) => t.techniqueID));
  for (const gap of gapResult.gaps) {
    const parts = gap.technique_id.split('.');
    if (!existingIds.has(parts[0])) {
      baseLayer.techniques.push({
        techniqueID: parts[0],
        ...(parts[1] ? { tactic: parts[0] } : {}),
        score: 0,
        color: '#ffcc00', // amber for untested
        comment: `GAP: ${gap.name} — ${gap.reason_untested}`,
        enabled: true,
        metadata: [{ name: 'gap', value: 'true' }],
        links: [],
        showSubtechniques: !!parts[1],
      });
      existingIds.add(parts[0]);
    }
  }

  baseLayer.description = `${baseLayer.description} | Coverage: ${gapResult.coverage_pct}% (${gapResult.tested_count}/${gapResult.total_in_scope})`;
  return baseLayer;
}

// Exported for testing
export { CWE_TO_OWASP, CWE_TO_NIST, CWE_TO_PCI, VULN_TYPE_TO_CWE, EDGE_TO_ATTACK, VULN_TO_ATTACK, CATEGORY_TO_ATTACK };
