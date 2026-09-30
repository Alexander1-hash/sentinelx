import type { AdaptiveInvestigationContext } from "@/lib/security/adaptive-context";

export type ContradictionRecord = {
  id: string;
  leftEvidenceId: string;
  rightEvidenceId: string;
  reason: string;
  type: "temporal" | "state" | "source" | "verification" | "semantic";
  resolution: "left_stronger" | "right_stronger" | "unresolved";
  confidence: number;
  rationale: string[];
};

export type ContradictionResolutionResult = {
  contradictions: ContradictionRecord[];
  unresolvedCount: number;
  resolvedCount: number;
  unresolvedReasons: string[];
  rationale: string[];
};

function clamp(value: number) {
  return Math.max(0, Math.min(100, Math.round(value)));
}

/**
 * Resolves only contradictions for which the available records provide an
 * explicit deterministic basis. Ambiguous conflicts remain unresolved.
 */
export function resolveContradictions(
  context: AdaptiveInvestigationContext,
  now = Date.now(),
): ContradictionResolutionResult {
  const records: ContradictionRecord[] = [];
  const profiles = context.currentState.correlatedEvidenceProfiles;
  const latestVerification = context.historicalState.latestVerification;
  const latestVerificationTime = latestVerification
    ? new Date(latestVerification.occurredAt).getTime()
    : null;

  if (
    latestVerification &&
    latestVerificationTime !== null &&
    Number.isFinite(latestVerificationTime)
  ) {
    for (const evidence of profiles) {
      const evidenceTime = new Date(evidence.observedAt).getTime();
      if (!Number.isFinite(evidenceTime) || evidenceTime <= latestVerificationTime) continue;

      const verificationState = latestVerification.state;
      if (verificationState === "resolved" || verificationState === "unknown") {
        records.push({
          id: `temporal-verification-${evidence.id}-${latestVerification.id}`,
          leftEvidenceId: latestVerification.id,
          rightEvidenceId: evidence.id,
          reason: `Evidence was observed after a ${verificationState} verification.`,
          type: "temporal",
          resolution: "unresolved",
          confidence: 92,
          rationale: [
            `Verification occurred at ${latestVerification.occurredAt}.`,
            `Evidence occurred later at ${evidence.observedAt}.`,
            "The later evidence may represent a changed current state, so the historical verification cannot be treated as the current truth.",
          ],
        });
      }
    }
  }

  if (
    context.currentState.findingStatus === "open" &&
    latestVerification?.state === "resolved"
  ) {
    records.push({
      id: `state-finding-open-${latestVerification.id}`,
      leftEvidenceId: "finding-state",
      rightEvidenceId: latestVerification.id,
      reason: "The finding remains open while the latest explicit verification records resolution.",
      type: "state",
      resolution: "unresolved",
      confidence: 88,
      rationale: [
        "The active finding state and verification state describe different points in time or state.",
        "No current evidence is sufficient to silently replace one state with the other.",
        "Current evidence should reconcile the active finding before the finding is changed.",
      ],
    });
  }

  for (const contradiction of context.contradictions) {
    const alreadyRepresented = records.some((record) => record.reason === contradiction);
    if (alreadyRepresented) continue;

    records.push({
      id: `context-contradiction-${records.length + 1}`,
      leftEvidenceId: "context",
      rightEvidenceId: "context",
      reason: contradiction,
      type: "semantic",
      resolution: "unresolved",
      confidence: 70,
      rationale: [
        "The adaptive context explicitly recorded a contradiction.",
        "The available context does not expose enough structured evidence to resolve it safely.",
      ],
    });
  }

  const unresolved = records.filter((record) => record.resolution === "unresolved");
  const resolved = records.filter((record) => record.resolution !== "unresolved");

  const rationale = [
    records.length
      ? `Contradiction analysis inspected ${records.length} structured conflict(s).`
      : "No explicit contradiction required resolution.",
    resolved.length
      ? `${resolved.length} contradiction(s) were resolved using deterministic evidence rules.`
      : "No contradiction was resolved automatically.",
    unresolved.length
      ? "Unresolved contradictions are preserved rather than hidden or arbitrarily selected."
      : "All detected contradictions have a deterministic resolution.",
    `Analysis timestamp: ${new Date(now).toISOString()}.`,
  ];

  return {
    contradictions: records.slice(0, 20),
    unresolvedCount: unresolved.length,
    resolvedCount: resolved.length,
    unresolvedReasons: unresolved.map((record) => record.reason).slice(0, 20),
    rationale,
  };
}
