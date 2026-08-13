// ============================================================
// Canonical "does this finding have real proof" predicate
// ============================================================
// One definition of proof, shared by the engagement scorecard and finding-readiness so
// the two can never disagree about what counts. Proof means *retrievable evidence* — an
// evidence-store blob, inlined raw output, or a matched-signal excerpt (the specific bytes
// that justify the claim). A command line or an exit code is METHODOLOGY/metadata, not
// proof: "we ran nmap and it exited 0" does not, by itself, show what was found.

import type { EvidenceChain, ReportFinding } from './report-generator.js';

/** The subset of an evidence chain that carries retrievable proof. */
type ProofBearing = Pick<
  EvidenceChain,
  'stdout_evidence_id' | 'stderr_evidence_id' | 'raw_output' | 'evidence_content' | 'excerpts'
>;

/** True when a single evidence chain cites captured bytes or a matched-signal excerpt. */
export function chainHasCapturedProof(chain: ProofBearing): boolean {
  return !!chain.stdout_evidence_id
    || !!chain.stderr_evidence_id
    || !!chain.raw_output
    || !!chain.evidence_content
    || (Array.isArray(chain.excerpts) && chain.excerpts.length > 0);
}

/** True when a finding has at least one evidence chain carrying retrievable proof. */
export function hasCapturedProof(finding: Pick<ReportFinding, 'evidence'>): boolean {
  return (finding.evidence ?? []).some(chainHasCapturedProof);
}
