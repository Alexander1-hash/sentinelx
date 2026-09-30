import type { AdaptiveInvestigationContext } from "@/lib/security/adaptive-context";
import type { VerificationReasoningResult } from "@/lib/security/verification-reasoning";

export type LearningAssessment = {
  state: "resolved" | "persisting" | "returned" | "unknown" | "insufficient_evidence";
  signal: "de_escalate" | "reinvestigate" | "recurrence_review" | "evidence_gap" | "none";
  confidence: number;
  evidenceIds: string[];
  rationale: string[];
};

export type LearningReasoningResult = { assessment: LearningAssessment; rationale: string[]; };

export function assessLearning(context: AdaptiveInvestigationContext, verification: VerificationReasoningResult): LearningReasoningResult {
  const state = context.learningState.state;
  const signal = state === "persisting" ? "reinvestigate" : state === "returned" ? "recurrence_review" : state === "resolved" ? "de_escalate" : state === "unknown" ? "evidence_gap" : "none";
  const learningState: LearningAssessment["state"] = state ?? "insufficient_evidence";
  const confidence = Math.max(0, Math.min(100, Math.round(verification.assessment.confidence * 0.7 + (context.responseLearning.length ? 20 : 0))));
  const evidenceIds = [...new Set([...verification.assessment.evidenceIds, ...context.currentState.correlatedEvidenceIds])].slice(0, 20);
  const rationale = [
    context.learningState.rationale,
    `Learning state is ${learningState}; signal is ${signal}.`,
    verification.assessment.status === "verified" ? "Verification provides evidence that can inform response learning." : "Verification is not fully corroborated, so learning remains bounded by the evidence gap.",
    "Historical learning informs future investigation but does not guarantee future response effectiveness.",
  ];
  return { assessment: { state: learningState, signal, confidence, evidenceIds, rationale }, rationale };
}