import type { AdaptiveInvestigationContext } from "@/lib/security/adaptive-context";
import type { HypothesisReasoningResult } from "@/lib/security/hypothesis-reasoning";
import type { IntelligenceGraphResult } from "@/lib/security/intelligence-graph";

export type IntelligenceDecisionAssessment = {
  priority: "observe" | "investigate" | "verify" | "review";
  rationale: string[];
  requiredEvidence: string[];
  relevantHypothesisIds: string[];
  unresolvedContradictions: string[];
  authorizationRequired: true;
};

export type DecisionReasoningResult = {
  assessment: IntelligenceDecisionAssessment;
  rationale: string[];
};

export function assessDecision(
  context: AdaptiveInvestigationContext,
  graph: IntelligenceGraphResult,
  hypotheses: HypothesisReasoningResult,
): DecisionReasoningResult {
  const unresolvedContradictions = context.contradictions.slice(0, 6);
  const relevantHypothesisIds = hypotheses.activeHypothesisIds.slice(0, 8);
  const requiredEvidence = [...new Set([
    ...context.nextEvidenceNeeded,
    ...hypotheses.assessments.flatMap((item) => item.missingEvidence),
  ])].slice(0, 8);
  const hasVerification = Boolean(context.historicalState.latestVerification);
  const hasEvidence = context.currentState.correlatedEvidenceCount > 0;
  const hasGraphRelationships = graph.edgeCount > 0;

  let priority: IntelligenceDecisionAssessment["priority"];
  if (unresolvedContradictions.length > 0) priority = "investigate";
  else if (hasVerification) priority = "verify";
  else if (hasEvidence || hasGraphRelationships) priority = "review";
  else priority = "observe";

  const rationale = [
    `Decision reasoning selected ${priority} from the currently recorded investigation state.`,
    unresolvedContradictions.length
      ? "Unresolved contradictions require reconciliation before a stronger conclusion is formed."
      : "No unresolved contradiction currently blocks the decision path.",
    requiredEvidence.length
      ? `${requiredEvidence.length} evidence requirement(s) remain available for the next review step.`
      : "No additional evidence requirement was derived from the current hypothesis graph.",
    relevantHypothesisIds.length
      ? `${relevantHypothesisIds.length} active or weakly supported hypothesis(es) inform the review.`
      : "No active hypothesis currently informs the review.",
    "Decision reasoning does not authorize a security action; operator authorization remains required.",
  ];

  return {
    assessment: {
      priority,
      rationale,
      requiredEvidence,
      relevantHypothesisIds,
      unresolvedContradictions,
      authorizationRequired: true,
    },
    rationale,
  };
}