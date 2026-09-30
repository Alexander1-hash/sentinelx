import type { AdaptiveInvestigationContext } from "@/lib/security/adaptive-context";

export type EvidenceAssessment = {
  evidenceId: string;
  freshness: "fresh" | "recent" | "stale" | "old" | "unknown";
  freshnessScore: number;
  corroborationScore: number;
  sourceDiversityScore: number;
  temporalConsistencyScore: number;
  qualityScore: number;
  usableForClaim: boolean;
  reasons: string[];
};

export type EvidenceReasoningResult = {
  assessed: EvidenceAssessment[];
  aggregateScore: number;
  sourceCount: number;
  freshEvidenceCount: number;
  staleEvidenceCount: number;
  conflicts: string[];
  gaps: string[];
  rationale: string[];
};

const FRESH_MINUTES = 15;
const RECENT_MINUTES = 60;
const STALE_MINUTES = 360;

function clamp(value: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Math.round(value)));
}

function minutesSince(value: string, now: number) {
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return null;
  return Math.max(0, (now - timestamp) / 60000);
}

export function assessEvidence(
  context: AdaptiveInvestigationContext,
  now = Date.now(),
): EvidenceReasoningResult {
  const profiles = context.currentState.correlatedEvidenceProfiles;
  const uniqueSources = new Set(profiles.map((item) => item.source || "unknown"));
  const latest = context.currentState.latestEvidenceAt
    ? new Date(context.currentState.latestEvidenceAt).getTime()
    : null;

  const conflicts: string[] = [...context.contradictions];
  const gaps: string[] = [];
  const assessed = profiles.map((profile) => {
    const age = minutesSince(profile.observedAt, now);
    let freshness: EvidenceAssessment["freshness"] = "unknown";
    let freshnessScore = 20;

    if (age !== null && age <= FRESH_MINUTES) {
      freshness = "fresh";
      freshnessScore = 100;
    } else if (age !== null && age <= RECENT_MINUTES) {
      freshness = "recent";
      freshnessScore = 85;
    } else if (age !== null && age <= STALE_MINUTES) {
      freshness = "stale";
      freshnessScore = 60;
    } else if (age !== null) {
      freshness = "old";
      freshnessScore = 30;
    }

    const corroboratingTypes = new Set(
      profiles
        .filter((other) => other.id !== profile.id)
        .map((other) => other.evidenceType),
    );
    const corroborationScore = clamp(
      30 +
      Math.min(4, profiles.filter((other) => other.id !== profile.id).length) * 8 +
      Math.min(3, corroboratingTypes.size) * 7,
    );

    // Source diversity is only a heuristic: records from distinct source labels
    // are not assumed to be statistically independent.
    const sourceDiversityScore = clamp(
      uniqueSources.size <= 1 ? 35 : 35 + Math.min(5, uniqueSources.size - 1) * 12,
    );

    const temporalConsistencyScore = latest === null
      ? 50
      : (() => {
          const timestamp = new Date(profile.observedAt).getTime();
          if (!Number.isFinite(timestamp) || !Number.isFinite(latest)) return 30;
          const deltaMinutes = Math.abs(timestamp - latest) / 60000;
          return deltaMinutes <= 60 ? 100 : deltaMinutes <= 360 ? 75 : 50;
        })();

    const qualityScore = clamp(
      freshnessScore * 0.35 +
      corroborationScore * 0.25 +
      sourceDiversityScore * 0.2 +
      temporalConsistencyScore * 0.2,
    );

    const reasons = [
      freshness === "fresh" ? "Observed within the configured fresh-evidence window." : null,
      freshness === "recent" ? "Observed recently, but outside the freshest window." : null,
      freshness === "stale" ? "Older telemetry lowers confidence and should be refreshed before high-confidence conclusions." : null,
      freshness === "old" ? "Old telemetry should not carry strong weight for current-state conclusions." : null,
      uniqueSources.size > 1
        ? "Multiple source labels are present; this is a diversity signal, not proof of independent corroboration."
        : "Only one source label is represented in the correlated evidence set.",
      corroboratingTypes.size > 0 ? "Other evidence types are present in the same investigation context." : "No additional evidence type corroborates this record.",
    ].filter((item): item is string => Boolean(item));

    return {
      evidenceId: profile.id,
      freshness,
      freshnessScore,
      corroborationScore,
      sourceDiversityScore,
      temporalConsistencyScore,
      qualityScore,
      usableForClaim: qualityScore >= 60 && freshness !== "old",
      reasons,
    };
  });

  const freshEvidenceCount = assessed.filter((item) => item.freshness === "fresh" || item.freshness === "recent").length;
  const staleEvidenceCount = assessed.filter((item) => item.freshness === "stale" || item.freshness === "old").length;

  if (profiles.length === 0) {
    gaps.push("No correlated evidence is available for evidence-quality reasoning.");
  }
  if (profiles.length > 0 && freshEvidenceCount === 0) {
    gaps.push("No fresh or recent correlated evidence is available.");
  }
  if (uniqueSources.size <= 1 && profiles.length > 1) {
    gaps.push("Correlated evidence is concentrated in one source label; independent corroboration remains unproven.");
  }
  if (context.contradictions.length > 0) {
    conflicts.push("Existing investigation contradictions reduce the amount of evidence that can safely support a conclusion.");
  }

  const aggregateScore = assessed.length === 0
    ? 15
    : clamp(assessed.reduce((sum, item) => sum + item.qualityScore, 0) / assessed.length);

  const rationale = [
    `${assessed.length} correlated evidence record(s) were assessed.`,
    `${freshEvidenceCount} record(s) are fresh or recent; ${staleEvidenceCount} are stale or old.`,
    `${uniqueSources.size} distinct source label(s) are represented.`,
    aggregateScore >= 75
      ? "Evidence quality is sufficiently strong to support investigation claims, subject to contradictions and missing evidence."
      : aggregateScore >= 50
        ? "Evidence quality is mixed; conclusions should retain uncertainty and prioritize targeted evidence collection."
        : "Evidence quality is limited; fresh corroborating evidence should be collected before strengthening conclusions.",
  ];

  return {
    assessed,
    aggregateScore,
    sourceCount: uniqueSources.size,
    freshEvidenceCount,
    staleEvidenceCount,
    conflicts: [...new Set(conflicts)].slice(0, 8),
    gaps: [...new Set(gaps)].slice(0, 8),
    rationale,
  };
}
