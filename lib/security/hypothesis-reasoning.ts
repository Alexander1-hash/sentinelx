import type { AdaptiveInvestigationContext } from "@/lib/security/adaptive-context";
import type { IntelligenceGraphResult } from "@/lib/security/intelligence-graph";

export type HypothesisAssessment = {
  hypothesisId: string;
  status: "supported" | "weak" | "blocked" | "contradicted";
  confidence: number;
  supportingNodeIds: string[];
  contradictingNodeIds: string[];
  missingEvidence: string[];
  rationale: string[];
};

export type HypothesisReasoningResult = {
  assessments: HypothesisAssessment[];
  activeHypothesisIds: string[];
  blockedHypothesisIds: string[];
  rationale: string[];
};

function clamp(value: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Math.round(value)));
}

/**
 * Evaluates existing hypotheses against the inspectable intelligence graph.
 * This does not create a new security conclusion; it grades how well each
 * already-defined hypothesis is supported, contradicted, or blocked.
 */
export function assessHypotheses(
  context: AdaptiveInvestigationContext,
  graph: IntelligenceGraphResult,
): HypothesisReasoningResult {
  const hypotheses = graph.nodes.filter((node) => node.type === "hypothesis");
  const assessments: HypothesisAssessment[] = [];

  for (const hypothesis of hypotheses) {
    const incoming = graph.edges.filter((edge) => edge.to === hypothesis.id);
    const outgoing = graph.edges.filter((edge) => edge.from === hypothesis.id);
    const supporting = incoming.filter((edge) => edge.type === "supports" || edge.type === "verifies" || edge.type === "requires").map((edge) => edge.from);
    const contradicting = [
      ...incoming.filter((edge) => edge.type === "contradicts").map((edge) => edge.from),
      ...outgoing.filter((edge) => edge.type === "contradicts").map((edge) => edge.to),
    ];
    const missingEvidence = [...context.nextEvidenceNeeded];
    let confidence = 30 + Math.min(supporting.length, 5) * 10 - Math.min(contradicting.length, 5) * 18;
    const evidenceNodes = graph.nodes.filter((node) => node.type === "evidence").map((node) => node.id);
    const eventNodes = graph.nodes.filter((node) => node.type === "event").map((node) => node.id);
    const verificationNodes = graph.nodes.filter((node) => node.type === "verification").map((node) => node.id);
    if (supporting.some((id) => evidenceNodes.includes(id))) confidence += 8;
    if (supporting.some((id) => eventNodes.includes(id))) confidence += 6;
    if (supporting.some((id) => verificationNodes.includes(id))) confidence += 12;
    if (hypothesis.id === "hypothesis:connected-impact") {
      confidence = Math.min(confidence, 65);
      missingEvidence.push("Evidence demonstrating actual impact on the connected asset is required before treating this as more than an investigation hypothesis.");
    }
    if (hypothesis.id.includes("response-") && verificationNodes.length === 0) {
      missingEvidence.push("An explicit verification record is required to strengthen the response-state hypothesis.");
    }
    const uniqueMissingEvidence = [...new Set(missingEvidence)].slice(0, 6);
    confidence = clamp(confidence);
    const status: HypothesisAssessment["status"] =
      contradicting.length > 0 ? "contradicted" : supporting.length === 0 ? "blocked" : confidence >= 70 ? "supported" : "weak";
    assessments.push({
      hypothesisId: hypothesis.id,
      status,
      confidence,
      supportingNodeIds: [...new Set(supporting)].slice(0, 20),
      contradictingNodeIds: [...new Set(contradicting)].slice(0, 20),
      missingEvidence: uniqueMissingEvidence,
      rationale: [
        supporting.length ? `${supporting.length} graph relationship(s) support or justify investigation of this hypothesis.` : "No graph relationship currently supports this hypothesis.",
        contradicting.length ? `${contradicting.length} graph relationship(s) contradict this hypothesis.` : "No direct graph contradiction was found.",
        uniqueMissingEvidence.length ? `${uniqueMissingEvidence.length} evidence requirement(s) remain open.` : "No additional evidence requirement was identified from the current context.",
        "Hypothesis status is bounded to the records represented in the current graph.",
      ],
    });
  }

  const activeHypothesisIds = assessments.filter((item) => item.status === "supported" || item.status === "weak").map((item) => item.hypothesisId);
  const blockedHypothesisIds = assessments.filter((item) => item.status === "blocked" || item.status === "contradicted").map((item) => item.hypothesisId);
  return {
    assessments,
    activeHypothesisIds,
    blockedHypothesisIds,
    rationale: [
      `Hypothesis reasoning assessed ${assessments.length} graph hypothesis node(s).`,
      activeHypothesisIds.length ? `${activeHypothesisIds.length} hypothesis(es) remain supported or weakly supported.` : "No hypothesis currently has sufficient graph support to remain active.",
      blockedHypothesisIds.length ? `${blockedHypothesisIds.length} hypothesis(es) are blocked or contradicted and should not be treated as established conclusions.` : "No hypothesis is currently blocked or contradicted.",
    ],
  };
}