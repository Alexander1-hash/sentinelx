import type { AdaptiveInvestigationContext } from "@/lib/security/adaptive-context";
import type { DecisionReasoningResult } from "@/lib/security/decision-reasoning";
import type { HypothesisReasoningResult } from "@/lib/security/hypothesis-reasoning";
import type { IntelligenceGraphResult } from "@/lib/security/intelligence-graph";

export type ResponseRecommendation = {
  actionType: "investigate_asset" | "review_finding" | "verify" | "none";
  reason: string;
  requiredEvidence: string[];
  authorizationRequired: true;
  executionAllowedByThisLayer: false;
};

export type ResponseReasoningResult = {
  recommendations: ResponseRecommendation[];
  boundary: string;
  rationale: string[];
};

export function assessResponsePath(
  context: AdaptiveInvestigationContext,
  graph: IntelligenceGraphResult,
  hypotheses: HypothesisReasoningResult,
  decision: DecisionReasoningResult,
): ResponseReasoningResult {
  const recommendations: ResponseRecommendation[] = [];
  const evidence = [...new Set([
    ...decision.assessment.requiredEvidence,
    ...hypotheses.assessments.flatMap((item) => item.missingEvidence),
  ])].slice(0, 8);

  if (decision.assessment.priority === "investigate") {
    recommendations.push({
      actionType: "investigate_asset",
      reason: "The current reasoning state contains unresolved contradictions or evidence gaps that should be investigated before a stronger response is considered.",
      requiredEvidence: evidence,
      authorizationRequired: true,
      executionAllowedByThisLayer: false,
    });
  }

  if (decision.assessment.priority === "verify") {
    recommendations.push({
      actionType: "verify",
      reason: "A verification record exists, so the next reasoning step is to establish whether the recorded response outcome matches current evidence.",
      requiredEvidence: evidence,
      authorizationRequired: true,
      executionAllowedByThisLayer: false,
    });
  }

  if (decision.assessment.priority === "review" || recommendations.length === 0) {
    recommendations.push({
      actionType: "review_finding",
      reason: `The graph contains ${graph.nodeCount} node(s) and ${graph.edgeCount} relationship(s); operator review remains the controlled next step.`,
      requiredEvidence: evidence,
      authorizationRequired: true,
      executionAllowedByThisLayer: false,
    });
  }

  if (context.currentState.findingStatus === "open" && context.historicalState.latestVerification?.state === "resolved") {
    recommendations.push({
      actionType: "verify",
      reason: "The finding remains open while the latest verification reports resolution, so current-state verification is required.",
      requiredEvidence: evidence,
      authorizationRequired: true,
      executionAllowedByThisLayer: false,
    });
  }

  return {
    recommendations: recommendations.slice(0, 4),
    boundary: "Response reasoning recommends an investigation or review path only. It never executes, authorizes, or claims success for a security action.",
    rationale: [
      `Response reasoning evaluated ${hypotheses.assessments.length} hypothesis assessment(s).`,
      `The selected decision priority is ${decision.assessment.priority}.`,
      "Mutating provider actions remain behind the existing operator-authorization, target-validation, and executor boundaries.",
    ],
  };
}