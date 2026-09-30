import type { AdaptiveInvestigationContext } from "@/lib/security/adaptive-context";

export type TemporalAssessment = {
  sequence: "current" | "historical" | "mixed" | "unknown";
  recencyMinutes: number | null;
  evidenceSpanMinutes: number | null;
  orderedEvidenceIds: string[];
  anomalies: string[];
  rationale: string[];
};

function validTimes(context: AdaptiveInvestigationContext) {
  return context.currentState.correlatedEvidenceProfiles
    .map((item) => ({ id: item.id, time: new Date(item.observedAt).getTime() }))
    .filter((item) => Number.isFinite(item.time))
    .sort((a, b) => b.time - a.time);
}

export function assessTemporalState(
  context: AdaptiveInvestigationContext,
  now = Date.now(),
): TemporalAssessment {
  const evidence = validTimes(context);
  const latest = evidence[0]?.time ?? null;
  const oldest = evidence[evidence.length - 1]?.time ?? null;
  const recencyMinutes = latest === null ? null : Math.max(0, (now - latest) / 60000);
  const evidenceSpanMinutes =
    latest === null || oldest === null ? null : Math.max(0, (latest - oldest) / 60000);

  const anomalies: string[] = [];
  const rationale: string[] = [];

  if (latest !== null && latest > now + 5 * 60000) {
    anomalies.push("At least one correlated evidence timestamp is materially in the future relative to the investigation clock.");
  }

  const verification = context.historicalState.latestVerification;
  if (verification) {
    const verificationTime = new Date(verification.occurredAt).getTime();
    if (Number.isFinite(verificationTime) && latest !== null && latest > verificationTime) {
      anomalies.push("Current correlated evidence was observed after the latest recorded verification; historical verification cannot be treated as the current state.");
    }
  }

  const sequence: TemporalAssessment["sequence"] =
    evidence.length === 0
      ? "unknown"
      : recencyMinutes !== null && recencyMinutes <= 60
        ? evidenceSpanMinutes !== null && evidenceSpanMinutes > 24 * 60
          ? "mixed"
          : "current"
        : evidenceSpanMinutes !== null && evidenceSpanMinutes > 24 * 60
          ? "historical"
          : "mixed";

  rationale.push(
    evidence.length === 0
      ? "No timestamped correlated evidence is available for temporal reasoning."
      : `${evidence.length} correlated evidence record(s) were ordered by observation time.`,
  );
  rationale.push(
    recencyMinutes === null
      ? "Current evidence recency cannot be established."
      : `The newest correlated evidence is approximately ${Math.round(recencyMinutes)} minute(s) old.`,
  );
  if (evidenceSpanMinutes !== null && evidenceSpanMinutes > 24 * 60) {
    rationale.push("The evidence spans more than 24 hours, so historical and current signals should not be treated as one undifferentiated state.");
  }

  return {
    sequence,
    recencyMinutes: recencyMinutes === null ? null : Math.round(recencyMinutes),
    evidenceSpanMinutes: evidenceSpanMinutes === null ? null : Math.round(evidenceSpanMinutes),
    orderedEvidenceIds: evidence.map((item) => item.id).slice(0, 100),
    anomalies: [...new Set(anomalies)].slice(0, 8),
    rationale,
  };
}
