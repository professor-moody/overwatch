import type { FindingDto } from './api';

export function findingTitle(finding: FindingDto): string {
  return finding.presentation?.title || finding.title;
}

/**
 * Evidence-panel entry-point findings, SPREAD across the severities present (up to
 * `perSeverity` from each, highest first, capped at `cap`). /api/findings is sorted by
 * risk, so a plain top-N only ever surfaces critical/high — this lets medium/low findings
 * be reachable as entry points too. Only findings with a navigable affected asset qualify
 * (the entry point opens that node's evidence; assetless ones aren't clickable).
 */
export function severityDiverseEntryFindings(findings: FindingDto[], perSeverity = 3, cap = 12): FindingDto[] {
  const withAsset = findings.filter(f => f.affected_assets?.[0]);
  const order: FindingDto['severity'][] = ['critical', 'high', 'medium', 'low', 'info'];
  const picked: FindingDto[] = [];
  for (const sev of order) picked.push(...withAsset.filter(f => f.severity === sev).slice(0, perSeverity));
  return picked.slice(0, cap);
}

export function findingSummary(finding: FindingDto): string {
  return finding.presentation?.summary || finding.description;
}

export function findingImpact(finding: FindingDto): string | undefined {
  return finding.presentation?.impact;
}

export function findingRemediation(finding: FindingDto): string {
  const steps = finding.presentation?.remediation_steps;
  if (!steps || steps.length === 0) return finding.remediation;
  return steps.map((step, index) => `${index + 1}. ${step}`).join('\n');
}

/** A short label for WHAT the finding is — the CWE name when classified, else the
 *  category label. Used to anchor the evidence block to the vuln it proves. */
export function findingVulnLabel(finding: FindingDto): string {
  return finding.classification?.cwe?.name || findingCategoryLabel(finding.category);
}

export function findingCategoryLabel(category: string): string {
  switch (category) {
    case 'compromised_host': return 'Confirmed access';
    case 'credential': return 'Credential exposure';
    case 'vulnerability': return 'Vulnerability';
    case 'access_path': return 'Administrative path';
    case 'cloud_exposure': return 'Cloud exposure';
    case 'webapp': return 'Application exposure';
    default: return category.replace(/_/g, ' ');
  }
}
