import { useCallback, useEffect, useState } from 'react';
import { getScorecard, type Scorecard } from '../../lib/api';
import { PanelSection, MetricTile } from '../shared/primitives';

const pct = (share: number): string => `${Math.round((share ?? 0) * 100)}%`;

/**
 * Live engagement-quality scorecard — the same ground-truth-free dimensions the report renders
 * (verified vs. hypothesized claims, attack-path validation, proof-ready findings, objective
 * attainment incl. lapsed milestones, unsupported critical claims, and promotion/evidence
 * contradictions), fetched from GET /api/scorecard so an operator sees output quality live.
 */
export function EngagementQualityCard() {
  const [scorecard, setScorecard] = useState<Scorecard | null>(null);
  const [error, setError] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setScorecard(await getScorecard());
      setError(false);
    } catch {
      setError(true);
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 15_000);
    return () => clearInterval(timer);
  }, [refresh]);

  if (!scorecard) {
    return (
      <PanelSection title="Engagement Quality">
        <div className="text-xs text-muted-foreground">{error ? 'Scorecard unavailable.' : 'Loading…'}</div>
      </PanelSection>
    );
  }

  const sc = scorecard;
  const liveClaims = sc.verification.verified + sc.verification.unverified;
  const lapsed = sc.objectives.achieved - sc.objectives.currently_satisfied;

  return (
    <PanelSection title="Engagement Quality" meta="ground-truth-free">
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-2">
        <MetricTile
          dense
          label="Verified claims"
          value={pct(sc.verification.verified_share)}
          sub={`${sc.verification.verified} of ${liveClaims} live confirmed`}
        />
        <MetricTile
          dense
          label="Attack path validated"
          value={pct(sc.attack_paths.validation_share)}
          sub={`${sc.attack_paths.validated} of ${sc.attack_paths.total} access edges`}
        />
        <MetricTile
          dense
          label="Proof-ready findings"
          value={pct(sc.findings.proof_ready_share)}
          sub={`${sc.findings.proof_ready} of ${sc.findings.total}`}
        />
        <MetricTile
          dense
          label="Objectives satisfied"
          value={`${sc.objectives.currently_satisfied}/${sc.objectives.total}`}
          sub={lapsed > 0 ? `${lapsed} lapsed — re-validate` : `${sc.objectives.proof_ready} proof-backed`}
        />
        <MetricTile
          dense
          label="Unsupported critical"
          value={sc.unsupported_critical_claims}
          sub="high/critical, no proof"
        />
        <MetricTile
          dense
          label="Contradictions"
          value={sc.contradicted_claims}
          sub="promotion vs. evidence"
        />
      </div>
      {sc.contradictions.length > 0 && (
        <div className="mt-2 space-y-1">
          {sc.contradictions.slice(0, 3).map((c, index) => (
            <div key={`${c.target_id}-${index}`} className="text-[11px] text-warning break-words">
              ⚠ {c.target_ref}: promoted {c.promoted_state}
              {c.reason ? ` — "${c.reason}"` : ''}
            </div>
          ))}
          {sc.contradictions.length > 3 && (
            <div className="text-[11px] text-muted-foreground">…and {sc.contradictions.length - 3} more</div>
          )}
        </div>
      )}
    </PanelSection>
  );
}
