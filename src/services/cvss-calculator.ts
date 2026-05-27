// ============================================================
// Overwatch — CVSS v3.1 Base Score Calculator
// Computes CVSS base scores from vector strings or estimates
// them from graph context when no CVE/vector is available.
// ============================================================

import type { ReportFinding } from './report-generator.js';
import type { ExportedGraph, NodeProperties } from '../types.js';

// ============================================================
// Types
// ============================================================

export interface CvssVector {
  attackVector: 'N' | 'A' | 'L' | 'P';       // Network, Adjacent, Local, Physical
  attackComplexity: 'L' | 'H';                 // Low, High
  privilegesRequired: 'N' | 'L' | 'H';         // None, Low, High
  userInteraction: 'N' | 'R';                   // None, Required
  scope: 'U' | 'C';                             // Unchanged, Changed
  confidentialityImpact: 'N' | 'L' | 'H';      // None, Low, High
  integrityImpact: 'N' | 'L' | 'H';
  availabilityImpact: 'N' | 'L' | 'H';
}

// ============================================================
// CVSS v3.1 Metric Weights (from CVSS v3.1 Specification)
// ============================================================

const AV_WEIGHTS: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
const AC_WEIGHTS: Record<string, number> = { L: 0.77, H: 0.44 };
const PR_WEIGHTS_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_WEIGHTS_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.50 };
const UI_WEIGHTS: Record<string, number> = { N: 0.85, R: 0.62 };
const IMPACT_WEIGHTS: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };

// ============================================================
// Core CVSS v3.1 Computation
// ============================================================

export function computeBaseScore(vector: CvssVector): number {
  const { attackVector, attackComplexity, privilegesRequired, userInteraction, scope, confidentialityImpact, integrityImpact, availabilityImpact } = vector;

  const av = AV_WEIGHTS[attackVector] ?? 0;
  const ac = AC_WEIGHTS[attackComplexity] ?? 0;
  const prWeights = scope === 'C' ? PR_WEIGHTS_CHANGED : PR_WEIGHTS_UNCHANGED;
  const pr = prWeights[privilegesRequired] ?? 0;
  const ui = UI_WEIGHTS[userInteraction] ?? 0;

  const iC = IMPACT_WEIGHTS[confidentialityImpact] ?? 0;
  const iI = IMPACT_WEIGHTS[integrityImpact] ?? 0;
  const iA = IMPACT_WEIGHTS[availabilityImpact] ?? 0;

  // ISS (Impact Sub-Score)
  const iss = 1 - ((1 - iC) * (1 - iI) * (1 - iA));

  // Impact
  let impact: number;
  if (scope === 'U') {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }

  // If impact <= 0, base score is 0
  if (impact <= 0) return 0;

  // Exploitability
  const exploitability = 8.22 * av * ac * pr * ui;

  // Base Score
  let baseScore: number;
  if (scope === 'U') {
    baseScore = Math.min(impact + exploitability, 10);
  } else {
    baseScore = Math.min(1.08 * (impact + exploitability), 10);
  }

  // Round up to nearest 0.1 (CVSS spec: "roundup" function)
  return roundUp(baseScore);
}

export function vectorToString(vector: CvssVector): string {
  return `CVSS:3.1/AV:${vector.attackVector}/AC:${vector.attackComplexity}/PR:${vector.privilegesRequired}/UI:${vector.userInteraction}/S:${vector.scope}/C:${vector.confidentialityImpact}/I:${vector.integrityImpact}/A:${vector.availabilityImpact}`;
}

export function parseVectorString(vs: string): CvssVector | null {
  const stripped = vs.replace(/^CVSS:3\.[01]\//, '');
  const parts = new Map<string, string>();
  for (const segment of stripped.split('/')) {
    const [key, value] = segment.split(':');
    if (key && value) parts.set(key, value);
  }

  const av = parts.get('AV');
  const ac = parts.get('AC');
  const pr = parts.get('PR');
  const ui = parts.get('UI');
  const s = parts.get('S');
  const c = parts.get('C');
  const i = parts.get('I');
  const a = parts.get('A');

  if (!av || !ac || !pr || !ui || !s || !c || !i || !a) return null;
  if (!['N', 'A', 'L', 'P'].includes(av)) return null;
  if (!['L', 'H'].includes(ac)) return null;
  if (!['N', 'L', 'H'].includes(pr)) return null;
  if (!['N', 'R'].includes(ui)) return null;
  if (!['U', 'C'].includes(s)) return null;
  if (!['N', 'L', 'H'].includes(c) || !['N', 'L', 'H'].includes(i) || !['N', 'L', 'H'].includes(a)) return null;

  return {
    attackVector: av as CvssVector['attackVector'],
    attackComplexity: ac as CvssVector['attackComplexity'],
    privilegesRequired: pr as CvssVector['privilegesRequired'],
    userInteraction: ui as CvssVector['userInteraction'],
    scope: s as CvssVector['scope'],
    confidentialityImpact: c as CvssVector['confidentialityImpact'],
    integrityImpact: i as CvssVector['integrityImpact'],
    availabilityImpact: a as CvssVector['availabilityImpact'],
  };
}

// ============================================================
// Context-Based CVSS Estimation
// Infers a CVSS vector from graph topology and finding metadata
// when no explicit vector or CVE score is available.
// ============================================================

export function estimateCvssFromContext(
  finding: ReportFinding,
  graph: ExportedGraph,
  nodeMap: Map<string, NodeProperties>,
): { vector: CvssVector; score: number; estimated: true } {
  const affectedNodes = finding.affected_assets
    .map(assetId => nodeMap.get(assetId))
    .filter((node): node is NodeProperties => !!node);
  const descLower = finding.description.toLowerCase();

  // --- Attack Vector ---
  // Network only when the affected asset has an explicit public/external
  // exposure signal. Internal services with open ports are Adjacent, not
  // internet-reachable by default.
  let attackVector: CvssVector['attackVector'] = 'L';
  for (const node of affectedNodes) {
    if (isPubliclyExposed(node, graph) || finding.category === 'cloud_exposure') {
      attackVector = 'N'; break;
    }
    if (node.type === 'service' && node.port) {
      attackVector = 'A';
    }
    if (node.type === 'host') {
      const hasNetworkService = graph.edges.some(e =>
        (e.source === node.id && e.properties.type === 'RUNS') ||
        (e.target === node.id && e.properties.type === 'REACHABLE')
      );
      if (hasNetworkService && attackVector === 'L') attackVector = 'A';
    }
  }

  // --- Attack Complexity ---
  // Low for direct exploitation; High for multi-step chains
  let attackComplexity: CvssVector['attackComplexity'] = 'L';
  if (finding.category === 'access_path') attackComplexity = 'H';

  // --- Privileges Required ---
  let privilegesRequired: CvssVector['privilegesRequired'] = 'N';
  if (finding.category === 'credential') {
    // Credential findings imply we already had some access
    privilegesRequired = 'L';
    if (affectedNodes.some(isPrivilegedCredentialOrOwner)) {
      privilegesRequired = 'H';
    }
  }
  // Check if finding involves authenticated access
  if (descLower.includes('authenticated') || descLower.includes('session')) {
    privilegesRequired = 'L';
  }
  if (descLower.includes('admin') || descLower.includes('privileged')) {
    privilegesRequired = 'H';
  }

  // --- User Interaction ---
  let userInteraction: CvssVector['userInteraction'] = 'N';
  if (descLower.includes('xss') || descLower.includes('csrf') || descLower.includes('phishing')) {
    userInteraction = 'R';
  }

  // --- Scope ---
  // Changed if exploitation leads to access beyond the vulnerability's scope
  let scope: CvssVector['scope'] = 'U';
  if (finding.category === 'compromised_host') {
    scope = 'C';
  }
  if (
    descLower.includes('lateral') ||
    descLower.includes('pivot') ||
    descLower.includes('cross-tier') ||
    hasCrossBoundaryEvidence(finding.affected_assets, graph)
  ) {
    scope = 'C';
  }

  // --- Impact ---
  let confidentialityImpact: CvssVector['confidentialityImpact'] = 'L';
  let integrityImpact: CvssVector['integrityImpact'] = 'N';
  let availabilityImpact: CvssVector['availabilityImpact'] = 'N';

  switch (finding.category) {
    case 'compromised_host':
      confidentialityImpact = 'H';
      integrityImpact = 'H';
      availabilityImpact = 'H';
      break;
    case 'credential':
      confidentialityImpact = 'H';
      integrityImpact = 'L';
      break;
    case 'access_path':
      confidentialityImpact = 'L';
      integrityImpact = 'L';
      break;
    case 'vulnerability':
      confidentialityImpact = 'H';
      integrityImpact = 'H';
      // Check exploitability
      for (const assetId of finding.affected_assets) {
        const node = nodeMap.get(assetId);
        if (node?.type === 'vulnerability' && node.exploitable) {
          availabilityImpact = 'H';
          break;
        }
      }
      break;
    case 'cloud_exposure':
      confidentialityImpact = 'H';
      integrityImpact = 'L';
      break;
    case 'webapp':
      confidentialityImpact = 'L';
      integrityImpact = 'L';
      // Upgrade if vuln is exploited
      for (const assetId of finding.affected_assets) {
        const node = nodeMap.get(assetId);
        if (node?.type === 'vulnerability') {
          confidentialityImpact = 'H';
          integrityImpact = 'H';
          break;
        }
      }
      break;
  }

  const vector: CvssVector = {
    attackVector,
    attackComplexity,
    privilegesRequired,
    userInteraction,
    scope,
    confidentialityImpact,
    integrityImpact,
    availabilityImpact,
  };

  return { vector, score: computeBaseScore(vector), estimated: true };
}

// ============================================================
// Helpers
// ============================================================

// CVSS v3.1 "roundup" — round to nearest 0.1 toward positive infinity
function roundUp(x: number): number {
  const rounded = Math.ceil(x * 10) / 10;
  return rounded;
}

function isPubliclyExposed(node: NodeProperties, graph: ExportedGraph): boolean {
  if (node.type === 'webapp') return true;
  if (node.public === true || node.publicly_accessible === true || node.exposed_to_internet === true || node.public_exposure === true) {
    return true;
  }
  return graph.edges.some(e => {
    if (e.source !== node.id && e.target !== node.id) return false;
    if (e.properties.type === 'EXPOSED_TO') return true;
    const exposure = String(e.properties.exposure || e.properties.scope || '').toLowerCase();
    return exposure.includes('public') || exposure.includes('internet') || exposure.includes('external');
  });
}

function isPrivilegedCredentialOrOwner(node: NodeProperties): boolean {
  return node.privileged === true ||
    node.domain_admin === true ||
    node.local_admin === true ||
    node.admin === true ||
    /admin|privileged|root/i.test(String(node.cred_user || node.username || node.label || ''));
}

function hasCrossBoundaryEvidence(assetIds: string[], graph: ExportedGraph): boolean {
  const ids = new Set(assetIds);
  const lateralEdges = new Set([
    'ADMIN_TO',
    'ASSUMES_ROLE',
    'POTENTIAL_AUTH',
    'VALID_FOR_APP',
    'TRUSTS',
    'CAN_DCSYNC',
    'ESC1',
    'ESC2',
    'ESC3',
    'ESC4',
    'ESC5',
    'ESC6',
    'ESC7',
    'ESC8',
    'ESC9',
    'ESC10',
    'ESC11',
    'ESC13',
  ]);
  return graph.edges.some(e =>
    (ids.has(e.source) || ids.has(e.target)) &&
    lateralEdges.has(String(e.properties.type))
  );
}
