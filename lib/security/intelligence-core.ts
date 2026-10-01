import type { AdaptiveInvestigationContext } from "@/lib/security/adaptive-context";
import { assessEvidence, type EvidenceReasoningResult } from "@/lib/security/evidence-reasoning";
import { assessTemporalState, type TemporalAssessment } from "@/lib/security/temporal-reasoning";
import { resolveContradictions, type ContradictionResolutionResult } from "@/lib/security/contradiction-resolution";
import { buildIntelligenceGraph, type IntelligenceGraphResult } from "@/lib/security/intelligence-graph";
import { assessHypotheses, type HypothesisReasoningResult } from "@/lib/security/hypothesis-reasoning";
import { assessDecision, type DecisionReasoningResult } from "@/lib/security/decision-reasoning";
import { assessResponsePath, type ResponseReasoningResult } from "@/lib/security/response-reasoning";
import { assessVerification, type VerificationReasoningResult } from "@/lib/security/verification-reasoning";
import { assessLearning, type LearningReasoningResult } from "@/lib/security/learning-reasoning";
import { buildReasoningTrace, type IntelligenceReasoningTrace } from "@/lib/security/reasoning-trace";


export type IntelligenceFact = {
  id: string;
  statement: string;
  sourceIds: string[];
  sourceType: "evidence" | "event" | "finding" | "verification" | "relationship";
};

export type IntelligenceInference = {
  id: string;
  statement: string;
  derivedFrom: string[];
  confidence: number;
  status: "supported" | "tentative" | "blocked";
};

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
  facts: IntelligenceFact[];
  inferences: IntelligenceInference[];
  claims: IntelligenceClaim[];
  hypotheses: IntelligenceHypothesis[];
  contradictions: string[];
  unknowns: string[];
  nextEvidence: string[];
  decisionContext: IntelligenceDecisionContext;
  evidenceReasoning: EvidenceReasoningResult;
  temporalReasoning: TemporalAssessment;
  contradictionResolution: ContradictionResolutionResult;
  graph: IntelligenceGraphResult;
  hypothesisReasoning: HypothesisReasoningResult;
  decisionReasoning: DecisionReasoningResult;
  responseReasoning: ResponseReasoningResult;
  verificationReasoning: VerificationReasoningResult;
  learningReasoning: LearningReasoningResult;
  reasoningTrace: IntelligenceReasoningTrace;
  longitudinalReasoning: {
    available: boolean;
    traceCount: number;
    comparison: {
      evidenceAdded: string[];
      evidenceRemoved: string[];
      hypothesesAdded: string[];
      hypothesesRemoved: string[];
      stateChanged: boolean;
      previousLearnedState: string | null;
      currentLearnedState: string | null;
      responseEffectiveness: string;
      recurringPattern: string;
    };
    signals: string[];
    nextInvestigationChanges: string[];
    confidenceAdjustment: number;
    boundary: string;
  };
  boundary: string;
};

function clamp(value: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Math.round(value)));
}


function buildLongitudinalReasoning(
  context: AdaptiveInvestigationContext,
  hypotheses: HypothesisReasoningResult,
  verification: VerificationReasoningResult,
): IntelligenceCoreResult["longitudinalReasoning"] {
  const historicalTraces = context.historicalState.reasoningTraces
    .filter((item) => item.trace !== null)
    .filter((item) => item.trace?.findingId === context.findingId)
    .sort((a, b) => new Date(b.occurredAt).getTime() - new Date(a.occurredAt).getTime());

  const previous = historicalTraces[0];

  if (!previous?.trace) {
    return {
      available: false,
      traceCount: historicalTraces.length,
      comparison: {
        evidenceAdded: [], evidenceRemoved: [], hypothesesAdded: [], hypothesesRemoved: [],
        stateChanged: false,
        previousLearnedState: null, currentLearnedState: context.learningState.state,
        responseEffectiveness: "not_observable", recurringPattern: "insufficient_history",
      },
      signals: ["No prior substantive reasoning trace is available for comparison."],
      nextInvestigationChanges: ["Persist this reasoning trace so the next investigation can compare evidence, hypotheses, verification and learning."],
      confidenceAdjustment: 0,
      boundary: "Longitudinal reasoning compares recorded historical traces with current recorded context; historical continuity is not proof of compromise, causation, attribution, or response success.",
    };
  }

  const trace = previous.trace;
  const stages = Array.isArray(trace.stages) ? trace.stages : [];
  const stage = (name: string) => {
    const found = stages.find((item) => item && typeof item === "object" && (item as Record<string, unknown>).stage === name);
    return found && typeof found === "object" ? found as Record<string, unknown> : {};
  };
  const ids = (value: unknown) => Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
  const diff = (current: string[], prior: string[]) => {
    const priorSet = new Set(prior);
    const currentSet = new Set(current);
    return {
      added: current.filter((id) => !priorSet.has(id)).slice(0, 25),
      removed: prior.filter((id) => !currentSet.has(id)).slice(0, 25),
    };
  };

  const evidenceDiff = diff(context.currentState.correlatedEvidenceIds, ids(stage("evidence").inputIds));
  const hypothesisDiff = diff(
    [...hypotheses.activeHypothesisIds, ...hypotheses.blockedHypothesisIds],
    ids(stage("hypothesis").outputIds),
  );
  const priorLearned = ids(stage("learned_state").outputIds)[0]?.replace(/^learned-state:/, "") ?? null;
  const currentLearned = context.learningState.state;
  const stateChanged = priorLearned !== currentLearned && Boolean(priorLearned || currentLearned);
  const responseEffectiveness =
    currentLearned === "resolved" && (priorLearned === "persisting" || priorLearned === "returned")
      ? "improved" :
    (currentLearned === "persisting" && priorLearned === "persisting")
      ? "persisting" :
    (currentLearned === "returned" && priorLearned === "resolved")
      ? "returned_after_resolution" :
    (currentLearned === "returned" && priorLearned === "returned")
      ? "recurrent" :
    (currentLearned === "persisting" && priorLearned === "returned")
      ? "persistent_after_recurrence" :
    currentLearned === "resolved" && priorLearned === "resolved"
      ? "stable_resolved" :
    "unknown";
  const recurringPattern =
    responseEffectiveness === "returned_after_resolution" || responseEffectiveness === "recurrent"
      ? "recurrence" :
    responseEffectiveness === "persisting" || responseEffectiveness === "persistent_after_recurrence"
      ? "persistence" :
    stateChanged ? "state_change" : "stable";

  return {
    available: true,
    traceCount: context.historicalState.reasoningTraces.length,
    comparison: {
      evidenceAdded: evidenceDiff.added,
      evidenceRemoved: evidenceDiff.removed,
      hypothesesAdded: hypothesisDiff.added,
      hypothesesRemoved: hypothesisDiff.removed,
      stateChanged,
      previousLearnedState: priorLearned,
      currentLearnedState: currentLearned,
      responseEffectiveness,
      recurringPattern,
    },
    signals: [
      evidenceDiff.added.length ? evidenceDiff.added.length + " new evidence record(s) since the previous trace." : "No new correlated evidence IDs since the previous trace.",
      evidenceDiff.removed.length ? evidenceDiff.removed.length + " previously used evidence record(s) are no longer in the current correlated set." : "No previously used evidence records dropped out of the current set.",
      hypothesisDiff.added.length || hypothesisDiff.removed.length ? "Hypothesis structure changed since the previous trace." : "No hypothesis identifier change was detected.",
      stateChanged ? "Learned state changed from " + (priorLearned ?? "none") + " to " + (currentLearned ?? "none") + "." : "Learned state did not change.",
      verification.assessment.verificationId ? "A current explicit verification record is available for comparison." : "No current explicit verification record is available.",
    ].slice(0, 6),
    nextInvestigationChanges: [
      evidenceDiff.added.length ? "Prioritize newly observed evidence and test whether it strengthens or contradicts the previous reasoning." : null,
      evidenceDiff.removed.length ? "Re-check evidence that disappeared from the current correlation set." : null,
      stateChanged ? "Re-evaluate the current hypothesis because the learned state changed." : null,
      responseEffectiveness === "returned_after_resolution" ? "Treat the current state as a recurrence signal and compare the new evidence with the prior resolved trace." : null,
      responseEffectiveness === "recurrent" ? "Compare the current recurrence conditions with the prior recurrence before considering another response." : null,
      currentLearned === "persisting" ? "Investigate why the prior response did not establish a changed state and obtain fresh evidence." : null,
      currentLearned === "unknown" ? "Close the verification evidence gap before treating response effectiveness as established." : null,
    ].filter((item): item is string => Boolean(item)).slice(0, 8),
    confidenceAdjustment:
      responseEffectiveness === "persisting" || responseEffectiveness === "persistent_after_recurrence" ? -6 :
      responseEffectiveness === "returned_after_resolution" || responseEffectiveness === "recurrent" ? -8 :
      responseEffectiveness === "improved" ? 3 :
      0,
    boundary: "Longitudinal reasoning compares recorded historical traces with current recorded context; historical continuity is not proof of compromise, causation, attribution, or response success.",
  };
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
  const eventIds = context.currentState.correlatedEventIds;
  const relationshipCount = context.currentState.confirmedConnectedAssets;
  const evidenceReasoning = assessEvidence(context, now);
  const temporalReasoning = assessTemporalState(context, now);
  const contradictionResolution = resolveContradictions(context, now);
  const graph = buildIntelligenceGraph(context);
  const hypothesisReasoning = assessHypotheses(context, graph);
  const decisionReasoning = assessDecision(context, graph, hypothesisReasoning);
  const responseReasoning = assessResponsePath(context, graph, hypothesisReasoning, decisionReasoning);
  const verificationReasoning = assessVerification(context, now);
  const learningReasoning = assessLearning(context, verificationReasoning);
  const longitudinalReasoning = buildLongitudinalReasoning(context, hypothesisReasoning, verificationReasoning);
  const contradictions = [...new Set([
    ...context.contradictions,
    ...evidenceReasoning.conflicts,
    ...contradictionResolution.unresolvedReasons,
  ])];
  const evidenceGaps = [...new Set([
    ...context.nextEvidenceNeeded,
    ...evidenceReasoning.gaps,
    ...temporalReasoning.anomalies.map((item) => `Temporal anomaly: ${item}`),
  ])];
  const unknowns = [...context.unknowns];

  const facts: IntelligenceFact[] = [];
  const inferences: IntelligenceInference[] = [];
  const claims: IntelligenceClaim[] = [];
  const hypotheses: IntelligenceHypothesis[] = [];

  facts.push({
    id: "finding-state",
    statement: `The finding is currently recorded as ${context.currentState.findingStatus} with severity ${context.currentState.severity}.`,
    sourceIds: [],
    sourceType: "finding",
  });

  if (evidenceCount > 0) {
    facts.push({
      id: "correlated-evidence",
      statement: `${evidenceCount} evidence record(s) are correlated with the finding context.`,
      sourceIds: evidenceIds.slice(0, 20),
      sourceType: "evidence",
    });
  }

  if (eventCount > 0) {
    facts.push({
      id: "correlated-events",
      statement: `${eventCount} security event signal(s) are correlated with the finding context.`,
      sourceIds: eventIds.slice(0, 20),
      sourceType: "event",
    });
  }

  if (relationshipCount > 0) {
    facts.push({
      id: "confirmed-relationships",
      statement: `${relationshipCount} confirmed first-hop asset relationship(s) are available.`,
      sourceIds: [],
      sourceType: "relationship",
    });
  }

  if (context.historicalState.reasoningTraces.length > 0) {
    facts.push({
      id: "historical-reasoning",
      statement: `${context.historicalState.reasoningTraces.length} prior reasoning trace(s) are available for longitudinal context.`,
      sourceIds: context.historicalState.reasoningTraces.slice(0, 20).map((trace) => trace.id),
      sourceType: "finding",
    });
  }

  if (context.historicalState.latestVerification) {
    facts.push({
      id: "latest-verification",
      statement: `The latest explicit verification is recorded as ${context.historicalState.latestVerification.state}.`,
      sourceIds: [context.historicalState.latestVerification.id],
      sourceType: "verification",
    });
  }

  if (evidenceCount > 0) {
    const evidenceConfidence = clamp(
      20 +
      evidenceReasoning.aggregateScore * 0.55 +
      Math.min(eventCount, 5) * 4,
    );

    claims.push({
      id: "current-evidence",
      statement: `${evidenceCount} correlated evidence record(s) support the current investigation context.`,
      evidenceIds: evidenceIds.slice(0, 20),
      confidence: evidenceConfidence,
      uncertainty: evidenceGaps.slice(0, 3),
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

  if (evidenceCount > 0 && eventCount > 0) {
    inferences.push({
      id: "evidence-event-correlation",
      statement: "Correlated evidence and event signals provide converging current-context support.",
      derivedFrom: ["correlated-evidence", "correlated-events"],
      confidence: clamp(50 + Math.min(evidenceCount, 5) * 7 + Math.min(eventCount, 5) * 5),
      status: "supported",
    });
  }

  if (relationshipCount > 0) {
    inferences.push({
      id: "relationship-investigation",
      statement: "Confirmed relationships justify investigating connected assets, but do not by themselves establish impact or compromise.",
      derivedFrom: ["confirmed-relationships"],
      confidence: clamp(35 + relationshipCount * 12),
      status: "tentative",
    });
  }

  if (relationshipCount > 0) {
    hypotheses.push({
      id: "connected-impact",
      statement: `${relationshipCount} confirmed first-hop relationship(s) provide a basis for investigating connected assets.`,
      supportingSignals: ["confirmed asset relationships"],
      missingEvidence: evidenceGaps.slice(0, 3),
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
      evidenceIds: [],
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
    (context.confidence === "strong" ? 82 : context.confidence === "moderate" ? 64 : 42) + longitudinalReasoning.confidenceAdjustment,
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
      ...context.reasoning.slice(0, 3),
      ...evidenceReasoning.rationale.slice(0, 2),
      ...temporalReasoning.rationale.slice(0, 2),
      ...contradictionResolution.rationale.slice(0, 2),
      ...(context.historicalState.reasoningTraces.length > 0
        ? [`${context.historicalState.reasoningTraces.length} prior reasoning trace(s) are available as historical explanation context.`]
        : []),
      ...longitudinalReasoning.signals.slice(0, 3),
      ...contradictions.slice(0, 2).map((item) => `Contradiction: ${item}`),
    ],
    requiredEvidence: evidenceGaps.slice(0, 6),
    authorizationRequired: true,
  };

  const reasoningTrace = buildReasoningTrace(
    context,
    graph,
    hypothesisReasoning,
    decisionReasoning,
    responseReasoning,
    verificationReasoning,
    learningReasoning,
    now,
  );

  return {
    generatedAt: new Date(now).toISOString(),
    state,
    confidence,
    facts: [
      ...facts,
      ...(evidenceCount > 0
        ? [{
            id: "evidence-quality",
            statement: `Evidence reasoning assessed the correlated set at ${evidenceReasoning.aggregateScore}/100, with ${evidenceReasoning.freshEvidenceCount} fresh/recent record(s) and ${evidenceReasoning.sourceCount} source label(s).`,
            sourceIds: evidenceIds.slice(0, 20),
            sourceType: "evidence" as const,
          }]
        : []),
    ].slice(0, 12),
    inferences: inferences.slice(0, 12),
    claims: claims.slice(0, 8),
    hypotheses: hypotheses.slice(0, 8),
    contradictions: contradictions.slice(0, 8),
    unknowns: unknowns.slice(0, 10),
    nextEvidence: evidenceGaps.slice(0, 8),
    decisionContext,
    evidenceReasoning,
    temporalReasoning,
    contradictionResolution,
    graph,
    hypothesisReasoning,
    decisionReasoning,
    responseReasoning,
    verificationReasoning,
    learningReasoning,
    reasoningTrace,
    longitudinalReasoning,
    boundary:
      "The intelligence core organizes recorded evidence and uncertainty. It does not establish compromise, attribution, causation, or response success without explicit supporting evidence.",
  };
}
