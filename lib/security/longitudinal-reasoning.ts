import type { AdaptiveInvestigationContext } from "@/lib/security/adaptive-context";
import type { HypothesisReasoningResult } from "@/lib/security/hypothesis-reasoning";
import type { VerificationReasoningResult } from "@/lib/security/verification-reasoning";
import type { LearningReasoningResult } from "@/lib/security/learning-reasoning";

export type LongitudinalReasoning = {
  available: boolean;
  traceCount: number;
  previousTrace: {
    id: string;
    traceId: string;
    occurredAt: string;
    confidence: number | null;
    evidenceIds: string[];
    eventIds: string[];
    hypothesisIds: string[];
    learnedState: string | null;
  } | null;
  comparison: {
    evidenceAdded: string[];
    evidenceRemoved: string[];
    eventsAdded: string[];
    eventsRemoved: string[];
    hypothesesAdded: string[];
    hypothesesRemoved: string[];
    stateChanged: boolean;
    previousLearnedState: string | null;
    currentLearnedState: string | null;
    verificationChanged: boolean;
    responseEffectiveness: "improved" | "persisting" | "returned" | "unknown" | "not_observable";
    recurringPattern: "recurrence" | "persistence" | "state_change" | "stable" | "insufficient_history";
  };
  signals: string[];
  nextInvestigationChanges: string[];
  confidenceAdjustment: number;
  boundary: string;
};

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? value as Record<string, unknown> : {};
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function stage(trace: Record<string, unknown>, name: string) {
  const stages = Array.isArray(trace.stages) ? trace.stages : [];
  return asRecord(stages.find((item) => asRecord(item).stage === name));
}

function snapshotFromMemory(memory: {
  id: string;
  traceId: string;
  occurredAt: string;
  confidence: number | null;
  trace: Record<string, unknown>;
}): LongitudinalReasoning["previousTrace"] {
  const evidence = stage(memory.trace, "evidence");
  const signals = stage(memory.trace, "signals");
  const hypotheses = stage(memory.trace, "hypothesis");
  const learned = stage(memory.trace, "learned_state");
  return {
    id: memory.id,
    traceId: memory.traceId,
    occurredAt: memory.occurredAt,
    confidence: memory.confidence,
    evidenceIds: stringArray(evidence.inputIds),
    eventIds: stringArray(signals.inputIds),
    hypothesisIds: stringArray(hypotheses.outputIds),
    learnedState: typeof stringArray(learned.outputIds)[0] === "string"
      ? stringArray(learned.outputIds)[0].replace(/^learned-state:/, "")
      : null,
  };
}

function difference(current: string[], previous: string[]) {
  const previousSet = new Set(previous);
  const currentSet = new Set(current);
  return {
    added: current.filter((id) => !previousSet.has(id)).slice(0, 25),
    removed: previous.filter((id) => !currentSet.has(id)).slice(0, 25),
  };
}

export function buildLongitudinalReasoning(
  context: AdaptiveInvestigationContext,
  hypotheses: HypothesisReasoningResult,
  verification: VerificationReasoningResult,
  learning: LearningReasoningResult,
): LongitudinalReasoning {
  const previousMemory = context.historicalState.reasoningTraces
    .filter((trace) => trace.trace !== null)
    .sort((a, b) => new Date(b.occurredAt).getTime() - new Date(a.occurredAt).getTime())[0];

  const traceCount = context.historicalState.reasoningTraces.length;
  if (!previousMemory?.trace) {
    return {
      available: false,
      traceCount,
      previousTrace: null,
      comparison: {
        evidenceAdded: [],
        evidenceRemoved: [],
        eventsAdded: [],
        eventsRemoved: [],
        hypothesesAdded: [],
        hypothesesRemoved: [],
        stateChanged: false,
        previousLearnedState: null,
        currentLearnedState: context.learningState.state,
        verificationChanged: Boolean(verification.assessment.verificationId),
        responseEffectiveness: "not_observable",
        recurringPattern: "insufficient_history",
      },
      signals: ["No prior reasoning trace with substantive trace data is available yet."],
      nextInvestigationChanges: ["Persist the current reasoning trace so the next investigation can compare evidence, hypotheses, verification and learning over time."],
      confidenceAdjustment: 0,
      boundary: "Longitudinal reasoning compares persisted historical traces with current recorded context. It does not turn historical similarity into proof of compromise, causation, attribution, or response success.",
    };
  }

  const prior = snapshotFromMemory(previousMemory);
  if (!prior) {
    return {
      available: false,
      traceCount,
      previousTrace: null,
      comparison: {
        evidenceAdded: [], evidenceRemoved: [], eventsAdded: [], eventsRemoved: [],
        hypothesesAdded: [], hypothesesRemoved: [], stateChanged: false,
        previousLearnedState: null, currentLearnedState: context.learningState.state,
        verificationChanged: false, responseEffectiveness: "not_observable",
        recurringPattern: "insufficient_history",
      },
      signals: ["The prior reasoning trace could not be normalized."],
      nextInvestigationChanges: ["Preserve a complete reasoning trace before attempting longitudinal comparison."],
      confidenceAdjustment: 0,
      boundary: "Longitudinal reasoning is bounded by the structure of persisted reasoning traces.",
    };
  }

  const currentEvidence = context.currentState.correlatedEvidenceIds.slice(0, 100);
  const currentEvents = context.currentState.correlatedEventIds.slice(0, 100);
  const currentHypotheses = [...hypotheses.activeHypothesisIds, ...hypotheses.blockedHypothesisIds]
    .filter((id, index, list) => list.indexOf(id) === index)
    .slice(0, 50);

  const evidence = difference(currentEvidence, prior.evidenceIds);
  const events = difference(currentEvents, prior.eventIds);
  const hypothesisDiff = difference(currentHypotheses, prior.hypothesisIds);
  const previousState = prior.learnedState;
  const currentState = context.learningState.state;
  const stateChanged = previousState !== currentState && Boolean(previousState || currentState);
  const verificationChanged = Boolean(
    verification.assessment.verificationId ||
    (context.historicalState.latestVerification &&
      new Date(context.historicalState.latestVerification.occurredAt).getTime() > new Date(previous.occurredAt).getTime()),
  );

  let responseEffectiveness: LongitudinalReasoning["comparison"]["responseEffectiveness"] = "unknown";
  if (currentState === "persisting") responseEffectiveness = "persisting";
  else if (currentState === "returned") responseEffectiveness = "returned";
  else if (currentState === "resolved" && previousState !== "resolved") responseEffectiveness = "improved";

  let recurringPattern: LongitudinalReasoning["comparison"]["recurringPattern"] = "stable";
  if (currentState === "returned") recurringPattern = "recurrence";
  else if (currentState === "persisting") recurringPattern = "persistence";
  else if (stateChanged) recurringPattern = "state_change";

  const signals = [
    evidence.added.length ? evidence.added.length + " evidence record(s) are new since the previous reasoning trace." : "No new correlated evidence IDs were detected against the previous trace.",
    evidence.removed.length ? evidence.removed.length + " previously used evidence record(s) are no longer in the current correlated set." : "No previously used evidence records dropped out of the current correlated set.",
    events.added.length ? events.added.length + " new event signal(s) are present since the previous trace." : "No new event IDs were detected against the previous trace.",
    hypothesisDiff.added.length || hypothesisDiff.removed.length
      ? "Hypothesis structure changed: +" + hypothesisDiff.added.length + " / -" + hypothesisDiff.removed.length + "."
      : "No hypothesis identifier change was detected.",
    stateChanged
      ? "Learned state changed from " + (previousState ?? "none") + " to " + (currentState ?? "none") + "."
      : "Learned state remains " + (currentState ?? "unresolved") + ".",
    context.historicalState.latestVerification
      ? "Latest explicit verification is " + context.historicalState.latestVerification.state + "."
      : "No current explicit verification is available.",
  ].slice(0, 8);

  const nextInvestigationChanges = [
    evidence.added.length ? "Prioritize newly observed evidence and determine whether it strengthens, weakens, or contradicts the previous reasoning." : null,
    evidence.removed.length ? "Re-check evidence that disappeared from the current correlation set before treating the previous conclusion as still supported." : null,
    events.added.length ? "Use new event signals for temporal comparison rather than assuming they prove causation." : null,
    stateChanged ? "Re-evaluate the current hypothesis because learned state changed from " + (previousState ?? "none") + " to " + (currentState ?? "none") + "." : null,
    currentState === "returned" ? "Compare recurrence conditions with the prior response outcome and identify what changed before considering another response." : null,
    currentState === "persisting" ? "Investigate why the prior response did not establish a changed state and obtain fresh evidence before escalating conclusions." : null,
    currentState === "unknown" ? "Close the verification evidence gap before treating response effectiveness as established." : null,
    !stateChanged && !evidence.added.length && !events.added.length ? "Current reasoning remains broadly consistent with the previous trace; continue checking for fresh evidence rather than treating consistency as proof." : null,
  ].filter((value): value is string => Boolean(value)).slice(0, 8);

  const confidenceAdjustment =
    responseEffectiveness === "persisting" || responseEffectiveness === "returned" ? -8 :
    responseEffectiveness === "improved" ? 4 : 0;

  return {
    available: true,
    traceCount,
    previousTrace: prior,
    comparison: {
      evidenceAdded: evidence.added,
      evidenceRemoved: evidence.removed,
      eventsAdded: events.added,
      eventsRemoved: events.removed,
      hypothesesAdded: hypothesisDiff.added,
      hypothesesRemoved: hypothesisDiff.removed,
      stateChanged,
      previousLearnedState: previousState,
      currentLearnedState: currentState,
      verificationChanged,
      responseEffectiveness,
      recurringPattern,
    },
    signals,
    nextInvestigationChanges,
    confidenceAdjustment,
    boundary: "Longitudinal reasoning compares persisted historical traces with current recorded context. Historical continuity is evidence about the investigation process, not proof of compromise, causation, attribution, or response success.",
  };
}
