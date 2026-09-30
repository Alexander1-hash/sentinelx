import type { AdaptiveInvestigationContext } from "@/lib/security/adaptive-context";
import type { IntelligenceGraphResult } from "@/lib/security/intelligence-graph";
import type { HypothesisReasoningResult } from "@/lib/security/hypothesis-reasoning";
import type { DecisionReasoningResult } from "@/lib/security/decision-reasoning";
import type { ResponseReasoningResult } from "@/lib/security/response-reasoning";
import type { VerificationReasoningResult } from "@/lib/security/verification-reasoning";
import type { LearningReasoningResult } from "@/lib/security/learning-reasoning";

export type ReasoningTraceStage =
  | "signals"
  | "evidence"
  | "events"
  | "finding"
  | "hypothesis"
  | "contradiction"
  | "decision"
  | "response"
  | "verification"
  | "learned_state";

export type ReasoningTraceStep = {
  stage: ReasoningTraceStage;
  status: "observed" | "inferred" | "blocked" | "contradicted" | "recommended";
  inputIds: string[];
  outputIds: string[];
  confidence: number | null;
  rationale: string[];
  unresolved: string[];
};

export type IntelligenceReasoningTrace = {
  traceId: string;
  generatedAt: string;
  findingId: string;
  stages: ReasoningTraceStep[];
  unresolvedQuestions: string[];
  evidenceChain: string[];
  boundary: string;
};

function unique(values: string[]) {
  return [...new Set(values.filter(Boolean))];
}

export function buildReasoningTrace(
  context: AdaptiveInvestigationContext,
  graph: IntelligenceGraphResult,
  hypotheses: HypothesisReasoningResult,
  decision: DecisionReasoningResult,
  response: ResponseReasoningResult,
  verification: VerificationReasoningResult,
  learning: LearningReasoningResult,
  now = Date.now(),
): IntelligenceReasoningTrace {
  const findingId = context.findingId;
  const evidenceIds = context.currentState.correlatedEvidenceIds.slice(0, 50);
  const eventIds = context.currentState.correlatedEventIds.slice(0, 50);
  const hypothesisIds = unique([
    ...hypotheses.activeHypothesisIds,
    ...hypotheses.blockedHypothesisIds,
    ...graph.nodes.filter((node) => node.type === "hypothesis").map((node) => node.id),
  ]).slice(0, 50);
  const contradictionIds = graph.nodes
    .filter((node) => node.type === "contradiction")
    .map((node) => node.id)
    .slice(0, 50);
  const decisionIds = ["decision:primary"];
  const responseIds = response.recommendations.map((_, index) => `response:${index + 1}`);
  const verificationIds = verification.assessment.verificationId
    ? [verification.assessment.verificationId]
    : [];
  const learnedStateIds = context.learningState.state
    ? [`learned-state:${context.learningState.state}`]
    : [];

  const stages: ReasoningTraceStep[] = [
    {
      stage: "signals",
      status: eventIds.length > 0 ? "observed" : "blocked",
      inputIds: eventIds,
      outputIds: eventIds,
      confidence: eventIds.length > 0 ? 100 : 0,
      rationale: eventIds.length > 0
        ? [`Observed ${eventIds.length} correlated security event signal(s).`]
        : ["No correlated security event signals are currently available."],
      unresolved: eventIds.length > 0 ? [] : ["Fresh event telemetry is unavailable."],
    },
    {
      stage: "evidence",
      status: evidenceIds.length > 0 ? "observed" : "blocked",
      inputIds: evidenceIds,
      outputIds: evidenceIds,
      confidence: evidenceIds.length > 0 ? context.confidence === "strong" ? 82 : context.confidence === "moderate" ? 64 : 42 : 0,
      rationale: evidenceIds.length > 0
        ? [
            `Evidence reasoning input contains ${context.currentState.correlatedEvidenceCount} correlated record(s).`,
            ...context.reasoning.slice(0, 2),
          ]
        : ["No correlated evidence is available to ground a strong conclusion."],
      unresolved: context.nextEvidenceNeeded.slice(0, 5),
    },
    {
      stage: "events",
      status: eventIds.length > 0 ? "observed" : "blocked",
      inputIds: eventIds,
      outputIds: eventIds,
      confidence: eventIds.length > 0 ? 60 : 0,
      rationale: ["Events are retained as signals and are not treated as proof of causation."],
      unresolved: eventIds.length > 0 ? [] : ["Event corroboration is unavailable."],
    },
    {
      stage: "finding",
      status: "observed",
      inputIds: [],
      outputIds: [findingId],
      confidence: 100,
      rationale: [`Finding context is recorded as ${context.currentState.findingStatus} with severity ${context.currentState.severity}.`],
      unresolved: [],
    },
    {
      stage: "hypothesis",
      status: hypothesisIds.length > 0
        ? hypotheses.activeHypothesisIds.length > 0 ? "inferred" : "blocked"
        : "blocked",
      inputIds: unique([...evidenceIds, ...eventIds]).slice(0, 50),
      outputIds: hypothesisIds,
      confidence: hypotheses.activeHypothesisIds.length > 0 ? 65 : 0,
      rationale: hypotheses.rationale.slice(0, 4),
      unresolved: graph.nodes
        .filter((node) => node.type === "hypothesis")
        .flatMap((node) => node.sourceIds)
        .filter((id) => !evidenceIds.includes(id))
        .slice(0, 5),
    },
    {
      stage: "contradiction",
      status: contradictionIds.length > 0 ? "contradicted" : "observed",
      inputIds: unique([...evidenceIds, ...verificationIds]).slice(0, 50),
      outputIds: contradictionIds,
      confidence: contradictionIds.length > 0 ? 50 : 100,
      rationale: contradictionIds.length > 0
        ? ["Contradictory relationships are preserved for operator review rather than silently discarded."]
        : ["No graph contradiction node is currently present."],
      unresolved: graph.isolatedNodeIds.filter((id) => contradictionIds.includes(id)).slice(0, 5),
    },
    {
      stage: "decision",
      status: "recommended",
      inputIds: unique([...hypothesisIds, ...contradictionIds]),
      outputIds: decisionIds,
      confidence: null,
      rationale: decision.assessment.rationale.slice(0, 5),
      unresolved: decision.assessment.requiredEvidence.slice(0, 6),
    },
    {
      stage: "response",
      status: response.recommendations.length > 0 ? "recommended" : "blocked",
      inputIds: decisionIds,
      outputIds: responseIds,
      confidence: null,
      rationale: response.rationale.slice(0, 5),
      unresolved: response.recommendations.flatMap((item) => item.requiredEvidence).slice(0, 6),
    },
    {
      stage: "verification",
      status:
        verification.assessment.status === "contradicted"
          ? "contradicted"
          : verification.assessment.status === "unverified"
            ? "blocked"
            : "observed",
      inputIds: unique([...responseIds, ...verification.assessment.evidenceIds]),
      outputIds: verificationIds,
      confidence: verification.assessment.confidence,
      rationale: verification.assessment.rationale.slice(0, 5),
      unresolved: verification.assessment.gaps.slice(0, 6),
    },
    {
      stage: "learned_state",
      status: learning.assessment.state === "insufficient_evidence" ? "blocked" : "inferred",
      inputIds: unique([...verificationIds, ...learning.assessment.evidenceIds]),
      outputIds: learnedStateIds,
      confidence: learning.assessment.confidence,
      rationale: learning.assessment.rationale.slice(0, 5),
      unresolved: learning.assessment.state === "insufficient_evidence"
        ? ["Learning state is not strong enough to support a durable conclusion."]
        : [],
    },
  ];

  const unresolvedQuestions = unique([
    ...context.unknowns,
    ...context.nextEvidenceNeeded,
    ...verification.assessment.gaps,
    ...decision.assessment.requiredEvidence,
    ...response.recommendations.flatMap((item) => item.requiredEvidence),
  ]).slice(0, 12);

  return {
    traceId: `reasoning:${findingId}:${new Date(now).getTime()}`,
    generatedAt: new Date(now).toISOString(),
    findingId,
    stages,
    unresolvedQuestions,
    evidenceChain: unique([
      ...evidenceIds,
      ...eventIds,
      ...hypothesisIds,
      ...contradictionIds,
      ...decisionIds,
      ...responseIds,
      ...verificationIds,
      ...learnedStateIds,
    ]).slice(0, 150),
    boundary:
      "The reasoning trace records how available signals, evidence, hypotheses, decisions, response recommendations, verification, and learning were connected. It is an audit/explanation structure, not proof of compromise, attribution, causation, or response success.",
  };
}