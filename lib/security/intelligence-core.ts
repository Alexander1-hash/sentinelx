import type { AdaptiveInvestigationContext } from "@/lib/security/adaptive-context";

export type IntelligenceClaim = {
  id: string;
  statement: string;
  evidenceIds: string[];
  confidence: number;
  uncertainty: string[];
  status: "supported" | "weakly_supported" | "unresolved" | "contradicted";
};

export type IntelligenceHypothesis = {
  id: string;
  statement: string;
  supportingSignals: string[];
  missingEvidence: string[];
  confidence: number;
  status: "active" | "weak" | "rejected";
};

export type IntelligenceDecisionContext = {
  priority: "observe" | "investigate" | "verify" | "review";
  rationale: string[];
  requiredEvidence: string[];
  authorizationRequired: boolean;
};

export type IntelligenceCoreResult = {
  generatedAt: string;
  state: "coherent" | "uncertain" | "contradictory";
  confidence: number;
  claims: IntelligenceClaim[];
  hypotheses: IntelligenceHypothesis[];
  contradictions: string[];
  unknowns: string[];
  nextEvidence: string[];
  decisionContext: IntelligenceDecisionContext;
  boundary: string;
};

function clamp(value: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Math.round(value)));
}

function hasVerification(context: AdaptiveInvestigationContext) {
  return context.historicalState.verifications > 0 && Boolean(context.historicalState.latestVerification);
}

export function buildIntelligenceCore(
  context: AdaptiveInvestigationContext,
  now = Date.now(),
): IntelligenceCoreResult {
  const evidenceCount = context.currentState.correlatedEvidenceCount;
  const eventCount = context.currentState.correlatedEventCount;
  const evidenceIds = context.currentState.correlatedEvidenceIds;
  const relationshipCount = context.currentState.confirmedConnectedAssets;
  const contradictions = [...context.contradictions];
  const unknowns = [...context.unknowns];

  const claims: IntelligenceClaim[] = [];
  const hypotheses: IntelligenceHypothesis[] = [];

  if (evidenceCount > 0) {
    const evidenceConfidence = clamp(
      35 + evidenceCount * 9 + Math.min(eventCount, 5) * 4,
    );

    claims.push({
      id: "current-evidence",
      statement: `${evidenceCount} correlated evidence record(s) support the current investigation context.`,
      evidenceIds: evidenceIds.slice(0, 20),
      confidence: evidenceConfidence,
      uncertainty: context.nextEvidenceNeeded.slice(0, 3),
      status: evidenceConfidence >= 70 ? "supported" : "weakly_supported",
    });
  } else {
    claims.push({
      id: "current-evidence-gap",
      statement: "No correlated evidence currently supports a strong conclusion about the finding.",
      evidenceIds: [],
      confidence: 15,
      uncertainty: ["Fresh telemetry is required before strengthening the conclusion."],
      status: "unresolved",
    });
  }

  if (relationshipCount > 0) {
    hypotheses.push({
      id: "connected-impact",
      statement: `${relationshipCount} confirmed first-hop relationship(s) provide a basis for investigating connected assets.`,
      supportingSignals: ["confirmed asset relationships"],
      missingEvidence: context.nextEvidenceNeeded.slice(0, 3),
      confidence: clamp(35 + relationshipCount * 12),
      status: "active",
    });
  }

  if (context.learningState.state === "persisting") {
    hypotheses.push({
      id: "persistence",
      statement: "The latest explicit verification indicates the condition persists.",
      supportingSignals: ["latest verification"],
      missingEvidence: context.nextEvidenceNeeded.slice(0, 3),
      confidence: 80,
      status: "active",
    });
  } else if (context.learningState.state === "returned") {
    hypotheses.push({
      id: "recurrence",
      statement: "The latest explicit verification indicates the condition returned.",
      supportingSignals: ["latest verification"],
      missingEvidence: context.nextEvidenceNeeded.slice(0, 3),
      confidence: 80,
      status: "active",
    });
  }

  if (context.learningState.state === "unknown") {
    unknowns.push("The latest verification is inconclusive; effectiveness cannot be established.");
  }

  if (context.learningState.state === "resolved") {
    claims.push({
      id: "historical-resolution",
      statement: "A prior explicit verification recorded resolution.",
      evidenceIds: evidenceIds.slice(0, 20),
      confidence: 80,
      uncertainty: ["Historical resolution does not prove the current finding is resolved."],
      status: context.currentState.findingStatus === "open" ? "weakly_supported" : "supported",
    });
  }

  const state: IntelligenceCoreResult["state"] =
    contradictions.length > 0
      ? "contradictory"
      : unknowns.length > 2 || context.confidence === "limited"
        ? "uncertain"
        : "coherent";

  const confidence = clamp(
    context.confidence === "strong" ? 82 : context.confidence === "moderate" ? 64 : 42,
    0,
    100,
  );

  const decisionContext: IntelligenceDecisionContext = {
    priority:
      contradictions.length > 0 || unknowns.length > 2
        ? "investigate"
        : hasVerification(context)
          ? "verify"
          : "review",
    rationale: [
      ...context.reasoning.slice(0, 4),
      ...contradictions.slice(0, 2).map((item) => `Contradiction: ${item}`),
    ],
    requiredEvidence: context.nextEvidenceNeeded.slice(0, 6),
    authorizationRequired: true,
  };

  return {
    generatedAt: new Date(now).toISOString(),
    state,
    confidence,
    claims: claims.slice(0, 8),
    hypotheses: hypotheses.slice(0, 8),
    contradictions: contradictions.slice(0, 8),
    unknowns: unknowns.slice(0, 10),
    nextEvidence: context.nextEvidenceNeeded.slice(0, 8),
    decisionContext,
    boundary:
      "The intelligence core organizes recorded evidence and uncertainty. It does not establish compromise, attribution, causation, or response success without explicit supporting evidence.",
  };
}
