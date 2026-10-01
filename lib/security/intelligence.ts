export type IntelligenceFinding = {
  id: string;
  asset_id: string | null;
  title: string;
  severity: string;
  status: string;
  detected_at: string | null;
};

export type IntelligenceEvidence = {
  id: string;
  asset_id: string | null;
  evidence_type: string;
  observed_at: string;
};

export type IntelligenceEvent = {
  id: string;
  asset_id: string | null;
  severity: string;
  observed_at: string;
};

export type IntelligenceRelationship = {
  source_asset_id: string;
  target_asset_id: string;
  confidence: number | null;
  status: string;
};

export type IntelligenceMemory = {
  id: string;
  memory_type: string;
  subject_id: string | null;
  occurred_at: string;
  state: string;
  data: Record<string, unknown>;
};

export type IntelligenceAsset = {
  id: string;
  name: string;
  asset_type: string;
  criticality: string | null;
  status: string;
};

import type { AdaptiveInvestigationContext } from "@/lib/security/adaptive-context";

export type IntelligenceResponseLearning = {
  findingId: string;
  responseOutcomes: number;
  verifications: number;
  resolved: number;
  persisting: number;
  returned: number;
  unknown: number;
  lastVerificationState: string | null;
  lastVerifiedAt: string | null;
};

const severityWeight: Record<string, number> = {
  critical: 100,
  high: 70,
  medium: 40,
  low: 15,
  info: 5,
  unknown: 0,
};

function recencyWeight(value: string | null, now: number) {
  if (!value) return 0;
  const time = new Date(value).getTime();
  if (!Number.isFinite(time)) return 0;
  const ageHours = Math.max(0, (now - time) / 36e5);
  return Math.max(0, 30 - Math.min(30, ageHours / 8));
}

export type SecurityStateChange = { findingId: string; previousState: string | null; currentState: string; changedAt: string | null; changeType: "opened" | "acknowledged" | "resolved" | "reopened" | "state_changed" | "unchanged"; evidenceFreshnessMinutes: number | null; evidenceCount: number; eventCount: number };

export function reconcileSecurityState(input: { findings: IntelligenceFinding[]; evidence: IntelligenceEvidence[]; events: IntelligenceEvent[]; memories: IntelligenceMemory[]; now?: number }) {
  const now = input.now ?? Date.now();
  const latestMemory = new Map<string, IntelligenceMemory>();
  for (const memory of input.memories) {
    if (!["finding_state", "verification", "evidence_change"].includes(memory.memory_type)) continue;
    const findingId = typeof memory.data?.finding_id === "string" ? memory.data.finding_id : memory.subject_id;
    if (!findingId) continue;
    const prior = latestMemory.get(findingId);
    if (!prior || new Date(memory.occurred_at).getTime() > new Date(prior.occurred_at).getTime()) latestMemory.set(findingId, memory);
  }
  const current = input.findings.map((finding) => {
    const memory = latestMemory.get(finding.id); const data = memory?.data ?? {};
    const previousState = typeof data.previous_state === "string" ? data.previous_state : typeof data.previous_security_state === "string" ? data.previous_security_state : null;
    const currentState = typeof data.current_state === "string" ? data.current_state : typeof data.current_security_state === "string" ? data.current_security_state : finding.status;
    const previous = previousState?.toLowerCase() ?? null; const state = currentState.toLowerCase();
    const changeType: SecurityStateChange["changeType"] = previous === null ? "unchanged" : previous === state ? "unchanged" : ["resolved", "closed"].includes(state) ? "resolved" : ["open", "reopened"].includes(state) && ["resolved", "closed"].includes(previous) ? "reopened" : state === "acknowledged" && previous === "open" ? "acknowledged" : "state_changed";
    const findingEvidence = input.evidence.filter((item) => item.asset_id && item.asset_id === finding.asset_id);
    const findingEvents = input.events.filter((item) => item.asset_id && item.asset_id === finding.asset_id);
    const latestEvidenceAt = findingEvidence.reduce((latest, item) => { const time = new Date(item.observed_at).getTime(); return time > latest ? time : latest; }, 0);
    const evidenceFreshnessMinutes = latestEvidenceAt ? Math.max(0, Math.round((now - latestEvidenceAt) / 60000)) : null;
    return { findingId: finding.id, previousState, currentState, changedAt: memory?.occurred_at ?? finding.detected_at ?? null, changeType, evidenceFreshnessMinutes, evidenceCount: findingEvidence.length, eventCount: findingEvents.length };
  });
  const changes = current.filter((item) => item.changeType !== "unchanged");
  const unknowns = [current.some((item) => item.evidenceFreshnessMinutes === null) ? "At least one finding has no asset-linked evidence timestamp." : null, current.some((item) => item.evidenceFreshnessMinutes !== null && item.evidenceFreshnessMinutes > 60) ? "Some finding evidence is older than 60 minutes and may not represent current state." : null, changes.some((item) => item.currentState.toLowerCase() === "resolved" && item.evidenceCount === 0) ? "A resolved state is recorded without asset-linked evidence; explicit verification evidence is still required." : null].filter((value): value is string => Boolean(value));
  return { current, changes, changedCount: changes.length, unknowns, stateConfidence: unknowns.length === 0 ? "strong" : changes.length > 0 ? "moderate" : "limited", boundary: "Reconciliation describes the latest organization-scoped state recorded by Trinorin. It does not infer compromise, causation, attacker intent, or resolution from missing telemetry." } as const;
}

export function synthesizeSecurityIntelligence(input: {
  findings: IntelligenceFinding[];
  evidence: IntelligenceEvidence[];
  events: IntelligenceEvent[];
  relationships: IntelligenceRelationship[];
  memories: IntelligenceMemory[];
  assets: IntelligenceAsset[];
  now?: number;
  adaptiveContexts?: Record<string, AdaptiveInvestigationContext>;
}) {
  const now = input.now ?? Date.now();
  const assetMap = new Map(input.assets.map((asset) => [asset.id, asset]));
  const evidenceByAsset = new Map<string, number>();
  const eventsByAsset = new Map<string, number>();
  const findingsByAsset = new Map<string, IntelligenceFinding[]>();
  const neighbors = new Map<string, Set<string>>();

  for (const item of input.evidence) {
    if (item.asset_id) evidenceByAsset.set(item.asset_id, (evidenceByAsset.get(item.asset_id) ?? 0) + 1);
  }
  for (const item of input.events) {
    if (item.asset_id) eventsByAsset.set(item.asset_id, (eventsByAsset.get(item.asset_id) ?? 0) + 1);
  }
  for (const finding of input.findings) {
    if (finding.asset_id) {
      const list = findingsByAsset.get(finding.asset_id) ?? [];
      list.push(finding);
      findingsByAsset.set(finding.asset_id, list);
    }
  }
  for (const edge of input.relationships) {
    if (edge.status !== "confirmed") continue;
    const a = neighbors.get(edge.source_asset_id) ?? new Set<string>();
    const b = neighbors.get(edge.target_asset_id) ?? new Set<string>();
    a.add(edge.target_asset_id);
    b.add(edge.source_asset_id);
    neighbors.set(edge.source_asset_id, a);
    neighbors.set(edge.target_asset_id, b);
  }

  const memoryData = (memory: IntelligenceMemory) => memory.data ?? {};
  const nestedRecord = (value: unknown): Record<string, unknown> =>
    value && typeof value === "object" ? (value as Record<string, unknown>) : {};

  const actionFindingIds = new Map<string, string>();
  for (const memory of input.memories) {
    const data = memoryData(memory);
    const directFindingId = typeof data.finding_id === "string" ? data.finding_id : null;
    const actionId = typeof data.action_id === "string" ? data.action_id : null;
    const verification = nestedRecord(data.verification);
    const findingSnapshot = nestedRecord(verification.finding_snapshot);
    const verificationFindingId = typeof findingSnapshot.id === "string" ? findingSnapshot.id : null;

    if (actionId && directFindingId) actionFindingIds.set(actionId, directFindingId);
    if (actionId && verificationFindingId) actionFindingIds.set(actionId, verificationFindingId);

    const result = nestedRecord(data.result);
    const outcomeFindingSnapshot = nestedRecord(result.finding_snapshot);
    if (actionId && typeof outcomeFindingSnapshot.id === "string") {
      actionFindingIds.set(actionId, outcomeFindingSnapshot.id);
    }
  }

  const responseLearningByFinding = new Map<string, IntelligenceResponseLearning>();
  for (const memory of input.memories) {
    if (!["response_outcome", "verification"].includes(memory.memory_type)) continue;

    const data = memoryData(memory);
    const actionId = typeof data.action_id === "string" ? data.action_id : null;
    const directFindingId = typeof data.finding_id === "string" ? data.finding_id : null;
    const verification = nestedRecord(data.verification);
    const findingSnapshot = nestedRecord(verification.finding_snapshot);
    const verificationFindingId = typeof findingSnapshot.id === "string" ? findingSnapshot.id : null;
    const findingId =
      directFindingId ??
      verificationFindingId ??
      (actionId ? actionFindingIds.get(actionId) ?? null : null);

    if (!findingId) continue;

    const current = responseLearningByFinding.get(findingId) ?? {
      findingId, responseOutcomes: 0, verifications: 0, resolved: 0,
      persisting: 0, returned: 0, unknown: 0, lastVerificationState: null, lastVerifiedAt: null,
    };

    if (memory.memory_type === "response_outcome") current.responseOutcomes += 1;
    if (memory.memory_type === "verification") {
      current.verifications += 1;
      const state = typeof data.state === "string" ? data.state : typeof verification.state === "string" ? verification.state : memory.state;
      if (state === "resolved") current.resolved += 1;
      else if (state === "persisting") current.persisting += 1;
      else if (state === "returned") current.returned += 1;
      else current.unknown += 1;
      const verifiedAt = typeof verification.verified_at === "string" ? verification.verified_at : memory.occurred_at;
      if (!current.lastVerifiedAt || new Date(verifiedAt).getTime() > new Date(current.lastVerifiedAt).getTime()) {
        current.lastVerifiedAt = verifiedAt;
        current.lastVerificationState = state;
      }
    }
    responseLearningByFinding.set(findingId, current);
  }

  const responseLearning = Array.from(responseLearningByFinding.values()).sort((a, b) => {
    const aTime = a.lastVerifiedAt ? new Date(a.lastVerifiedAt).getTime() : 0;
    const bTime = b.lastVerifiedAt ? new Date(b.lastVerifiedAt).getTime() : 0;
    return bTime - aTime;
  }).slice(0, 25);

  const stateReconciliation = reconcileSecurityState({ findings: input.findings, evidence: input.evidence, events: input.events, memories: input.memories, now });

  const activeFindings = input.findings.filter((finding) => ["open", "acknowledged"].includes(finding.status));
  const priorities = activeFindings.map((finding) => {
    const evidenceCount = finding.asset_id ? evidenceByAsset.get(finding.asset_id) ?? 0 : 0;
    const eventCount = finding.asset_id ? eventsByAsset.get(finding.asset_id) ?? 0 : 0;
    const neighborCount = finding.asset_id ? neighbors.get(finding.asset_id)?.size ?? 0 : 0;
    const recurrence = input.memories.filter((memory) => memory.subject_id === finding.id || memory.data.finding_id === finding.id).length;
    const learning = responseLearningByFinding.get(finding.id);
    const adaptiveContext = input.adaptiveContexts?.[finding.id] ?? null;
    const verificationSignal = learning?.lastVerificationState === "persisting" || learning?.lastVerificationState === "returned" ? 6 : 0;
    const adaptiveVerificationSignal = adaptiveContext?.historicalState.latestVerification?.state === "persisting" || adaptiveContext?.historicalState.latestVerification?.state === "returned" ? 4 : 0;
    const contradictionSignal = adaptiveContext?.contradictions.length ? 4 : 0;
    const freshnessSignal = adaptiveContext?.currentState.evidenceFreshnessMinutes !== null && adaptiveContext?.currentState.evidenceFreshnessMinutes !== undefined && adaptiveContext.currentState.evidenceFreshnessMinutes <= 60 ? 3 : 0;
    const score = Math.min(100,
      (severityWeight[finding.severity.toLowerCase()] ?? 0) + recencyWeight(finding.detected_at, now) +
      Math.min(15, evidenceCount * 3) + Math.min(10, eventCount * 2) + Math.min(10, neighborCount * 2) +
      Math.min(10, recurrence * 2) + verificationSignal + adaptiveVerificationSignal + contradictionSignal + freshnessSignal,
    );
    const asset = finding.asset_id ? assetMap.get(finding.asset_id) : null;
    return {
      findingId: finding.id, title: finding.title, severity: finding.severity, score, asset: asset?.name ?? null, assetId: finding.asset_id,
      evidenceCount, eventCount, connectedAssets: neighborCount, historicalRecords: recurrence, responseLearning: learning ?? null,
      adaptiveContext: adaptiveContext
        ? {
            confidence: adaptiveContext.confidence,
            evidenceFreshnessMinutes: adaptiveContext.currentState.evidenceFreshnessMinutes,
            correlatedEvidenceCount: adaptiveContext.currentState.correlatedEvidenceCount,
            correlatedEventCount: adaptiveContext.currentState.correlatedEventCount,
            confirmedReachability: adaptiveContext.confirmedReachability.length,
            contradictions: adaptiveContext.contradictions,
            latestVerification: adaptiveContext.historicalState.latestVerification,
            learningState: adaptiveContext.learningState,
            nextEvidenceNeeded: adaptiveContext.nextEvidenceNeeded.slice(0, 3),
          }
        : null,
      decisionSupport: {
        state:
          adaptiveContext?.contradictions.length
            ? "reconcile_context"
            : adaptiveContext?.nextEvidenceNeeded.length
              ? "collect_evidence"
              : learning?.lastVerificationState === "persisting" || learning?.lastVerificationState === "returned"
                ? "review_response"
                : "human_review",
        humanDecisionRequired: true,
        recommendedNextStep:
          adaptiveContext?.contradictions[0]
            ?? adaptiveContext?.nextEvidenceNeeded[0]
            ?? (learning?.lastVerificationState === "persisting" || learning?.lastVerificationState === "returned"
              ? "Review the latest response outcome and determine whether further action is warranted."
              : "Review the finding, supporting evidence, affected asset and available response options."),
        evidenceSufficiency:
          adaptiveContext?.confidence === "strong" && !adaptiveContext.contradictions.length
            ? "strong"
            : adaptiveContext?.confidence === "moderate"
              ? "moderate"
              : "limited",
        authorizationState: "not_authorized",
      },
      reasons: [
        finding.severity + " severity",
        evidenceCount ? evidenceCount + " linked evidence record" + (evidenceCount === 1 ? "" : "s") : "no directly linked evidence",
        neighborCount ? neighborCount + " confirmed connected asset" + (neighborCount === 1 ? "" : "s") : "no confirmed asset connection",
        recurrence ? recurrence + " historical memory record" + (recurrence === 1 ? "" : "s") : "no historical memory for this finding",
        learning?.lastVerificationState ? "latest verified response state: " + learning.lastVerificationState : "no verified response learning linked to this finding",
        adaptiveContext?.learningState?.learningSignal && adaptiveContext.learningState.learningSignal !== "none"
          ? "adaptive learning signal: " + adaptiveContext.learningState.learningSignal
          : "no adaptive response learning signal available",
        adaptiveContext?.confidence ? `adaptive context confidence: ${adaptiveContext.confidence}` : "no adaptive investigation context available",
        adaptiveContext?.contradictions.length ? `${adaptiveContext.contradictions.length} context contradiction(s) require reconciliation` : "no recorded adaptive contradictions",
        adaptiveContext?.nextEvidenceNeeded[0] ? `next evidence: ${adaptiveContext.nextEvidenceNeeded[0]}` : "no additional evidence request recorded",
      ],
    };
  }).sort((a, b) => b.score - a.score).slice(0, 8);

  const coverageGaps = [
    input.assets.length === 0 ? "No protected assets are registered." : null,
    input.evidence.length === 0 ? "No security evidence has been recorded." : null,
    input.events.length === 0 ? "No security events have been recorded." : null,
    input.relationships.filter((edge) => edge.status === "confirmed").length === 0
      ? "No confirmed asset relationships are available for blast-radius reasoning."
      : null,
    activeFindings.some((finding) => !finding.asset_id)
      ? "At least one active finding has no affected asset link."
      : null,
  ].filter((value): value is string => Boolean(value));

  const recentMemory = [...input.memories]
    .sort((a, b) => new Date(b.occurred_at).getTime() - new Date(a.occurred_at).getTime())
    .slice(0, 12);

  const lifecycle = {
    observe: input.events.length + input.evidence.length,
    detect: input.findings.length,
    investigate: input.memories.filter((memory) => memory.memory_type === "investigation").length,
    decide: input.memories.filter((memory) => memory.memory_type === "operator_decision").length,
    respond: input.memories.filter((memory) => memory.memory_type === "response_outcome").length,
    verify: input.memories.filter((memory) => memory.memory_type === "verification").length,
    learn: input.memories.filter((memory) =>
      ["evidence_change", "finding_state", "response_outcome", "verification", "reasoning_trace"].includes(memory.memory_type)
    ).length,
  };

  return {
    summary: {
      protectedAssets: input.assets.length,
      activeFindings: activeFindings.length,
      evidenceRecords: input.evidence.length,
      securityEvents: input.events.length,
      confirmedRelationships: input.relationships.filter((edge) => edge.status === "confirmed").length,
      memoryRecords: input.memories.length,
      intelligenceCoverage: Math.max(
        0,
        Math.round(
          100 -
            coverageGaps.length * 15 -
            (input.assets.length && !input.evidence.length ? 15 : 0),
        ),
      ),
    },
    priorities,
    coverageGaps,
    lifecycle,
    recentMemory,
    responseLearning,
    stateReconciliation,
    boundary:
      "Trinorin intelligence is evidence-first. Priority scores organize recorded signals for investigation; they do not prove compromise, attacker intent, causation, or future outcome.",
  };
}
