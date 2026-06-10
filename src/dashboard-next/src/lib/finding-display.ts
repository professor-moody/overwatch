import type { FindingDto } from './api';

export function findingTitle(finding: FindingDto): string {
  return finding.presentation?.title || finding.title;
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
