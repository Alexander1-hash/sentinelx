import type { AdaptiveInvestigationContext } from "@/lib/security/adaptive-context";

export type IntelligenceEvaluation = {
  findingId: string;
  evidenceGrounding: number;
  uncertaintyCalibration: number;
  verificationDiscipline: number;
  contextConsistency: number;
  actionability: number;
  safetyBoundary: number;
  overall: number;
  strengths: string[];
  gaps: string[];
};

type EvaluationFinding = {
  id: string;
  severity: string;
  status: string;
  summary?: string | null;
};

export function evaluateIntelligence(
  findings: EvaluationFinding[],
  contexts: Record<string, AdaptiveInvestigationContext>,
): IntelligenceEvaluation[] {
  return findings.map((finding) => {
    const context = contexts[finding.id];
    const strengths: string[] = [];
    const gaps: string[] = [];

    const evidenceGrounding = context
      ? Math.min(100, 40 + context.currentState.correlatedEvidenceCount * 12 + context.currentState.correlatedEventCount * 4)
      : 20;

    const uncertaintyCalibration = context
      ? Math.max(20, 100 - context.unknowns.length * 10 - context.contradictions.length * 8)
      : 20;

    const verificationDiscipline = context?.historicalState.latestVerification
      ? 100
      : context?.responseLearning.verifications
        ? 70
        : 45;

    const contextConsistency = context
      ? Math.max(25, 100 - context.contradictions.length * 18)
      : 25;

    const actionability = context
      ? Math.min(100, 45 + context.nextEvidenceNeeded.length * 15 + context.reasoning.length * 5)
      : 30;

    const safetyBoundary = context?.reasoning.some((item) =>
      /does not infer|not proof|missing telemetry|confirmed relationships/i.test(item),
    )
      ? 100
      : 60;

    if (evidenceGrounding >= 70) strengths.push("Strong current evidence linkage.");
    else gaps.push("More direct evidence would improve grounding.");

    if (uncertaintyCalibration >= 70) strengths.push("Uncertainty and contradictions are explicitly represented.");
    else gaps.push("The context contains unresolved uncertainty or contradictions.");

    if (verificationDiscipline >= 80) strengths.push("Response verification is explicitly represented.");
    else gaps.push("No recent explicit post-response verification is linked.");

    if (contextConsistency >= 80) strengths.push("Cross-module context is internally consistent.");
    else gaps.push("Contradictory context requires reconciliation.");

    if (safetyBoundary >= 90) strengths.push("Safety boundaries are explicit.");
    else gaps.push("The evaluation found limited explicit safety-boundary evidence.");

    const overall = Math.round(
      evidenceGrounding * 0.25 +
      uncertaintyCalibration * 0.2 +
      verificationDiscipline * 0.15 +
      contextConsistency * 0.15 +
      actionability * 0.1 +
      safetyBoundary * 0.15,
    );

    return {
      findingId: finding.id,
      evidenceGrounding,
      uncertaintyCalibration,
      verificationDiscipline,
      contextConsistency,
      actionability,
      safetyBoundary,
      overall,
      strengths: strengths.slice(0, 4),
      gaps: gaps.slice(0, 4),
    };
  });
}

export function summarizeIntelligenceEvaluation(results: IntelligenceEvaluation[]) {
  if (!results.length) {
    return {
      evaluatedFindings: 0,
      overall: 0,
      dimensions: {
        evidenceGrounding: 0,
        uncertaintyCalibration: 0,
        verificationDiscipline: 0,
        contextConsistency: 0,
        actionability: 0,
        safetyBoundary: 0,
      },
      boundary: "No intelligence findings were available for evaluation.",
    };
  }

  const average = (key: keyof Pick<IntelligenceEvaluation, "evidenceGrounding" | "uncertaintyCalibration" | "verificationDiscipline" | "contextConsistency" | "actionability" | "safetyBoundary">) =>
    Math.round(results.reduce((sum, item) => sum + item[key], 0) / results.length);

  return {
    evaluatedFindings: results.length,
    overall: Math.round(results.reduce((sum, item) => sum + item.overall, 0) / results.length),
    dimensions: {
      evidenceGrounding: average("evidenceGrounding"),
      uncertaintyCalibration: average("uncertaintyCalibration"),
      verificationDiscipline: average("verificationDiscipline"),
      contextConsistency: average("contextConsistency"),
      actionability: average("actionability"),
      safetyBoundary: average("safetyBoundary"),
    },
    boundary: "This is a deterministic evaluation of recorded context quality. It does not prove that a finding is true, resolved, or compromised.",
  };
}
