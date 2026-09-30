export type AdaptiveFinding = {
  id: string;
  asset_id: string | null;
  title: string;
  finding_type: string;
  severity: string;
  status: string;
  detected_at?: string | null;
  summary?: string | null;
};

export type AdaptiveEvidence = {
  id: string;
  asset_id?: string | null;
  evidence_type: string;
  source: string;
  title: string;
  summary?: string | null;
  observed_at: string;
  data?: Record<string, unknown>;
};

export type AdaptiveEvent = {
  id: string;
  asset_id?: string | null;
  severity?: string | null;
  observed_at: string;
};

export type AdaptiveRelationship = {
  source_asset_id: string;
  target_asset_id: string;
  relationship_type?: string;
  confidence: number | null;
  status: string;
};

export type AdaptiveMemory = {
  id: string;
  memory_type: string;
  subject_id: string | null;
  title: string;
  summary: string;
  state: string;
  occurred_at: string;
  data: Record<string, unknown>;
};

export type AdaptiveAsset = {
  id: string;
  name: string;
  asset_type: string;
  criticality: string | null;
  status: string;
};

export type AdaptiveResponseLearning = {
  occurred_at: string;
  action_type: string | null;
  state: string;
  evidence_count: number;
  summary: string;
  matchContext: string;
};

export type AdaptiveLearningState = {
  state: "resolved" | "persisting" | "returned" | "unknown" | null;
  occurredAt: string | null;
  actionType: string | null;
  evidenceCount: number;
  learningSignal: "de_escalate" | "reinvestigate" | "recurrence_review" | "evidence_gap" | "none";
  rationale: string;
};

export type AdaptiveInvestigationContext = {
  generatedAt: string;
  confidence: "strong" | "moderate" | "limited";
  currentState: {
    findingStatus: string;
    severity: string;
    affectedAsset: AdaptiveAsset | null;
    latestEvidenceAt: string | null;
    evidenceFreshnessMinutes: number | null;
    correlatedEvidenceCount: number;
    correlatedEvidenceIds: string[];
    correlatedEvidenceProfiles: Array<{
      id: string;
      source: string;
      evidenceType: string;
      observedAt: string;
    }>;
    correlatedEventCount: number;
    correlatedEventIds: string[];
    confirmedConnectedAssets: number;
  };
  historicalState: {
    priorFindingStates: Array<{
      occurredAt: string;
      previousState: string | null;
      currentState: string | null;
      summary: string;
    }>;
    priorInvestigations: number;
    priorOperatorDecisions: number;
    responseOutcomes: number;
    verifications: number;
    latestVerification: { id: string; state: string; occurredAt: string } | null;
  };
  responseLearning: AdaptiveResponseLearning[];
  learningState: AdaptiveLearningState;
  confirmedReachability: Array<{
    asset: AdaptiveAsset;
    hops: number;
    confidence: number;
    chain: string[];
  }>;
  contradictions: string[];
  unknowns: string[];
  nextEvidenceNeeded: string[];
  reasoning: string[];
};

function asTime(value: string | null | undefined) {
  if (!value) return null;
  const time = new Date(value).getTime();
  return Number.isFinite(time) ? time : null;
}

function extractFindingId(memory: AdaptiveMemory) {
  const direct = memory.data?.finding_id;
  if (typeof direct === "string") return direct;
  if (memory.memory_type === "finding_state") return memory.subject_id;
  const snapshot = memory.data?.verification;
  if (snapshot && typeof snapshot === "object") {
    const finding = (snapshot as Record<string, unknown>).finding_snapshot;
    if (finding && typeof finding === "object" && typeof (finding as Record<string, unknown>).id === "string") {
      return (finding as Record<string, unknown>).id as string;
    }
  }
  return null;
}

export function buildAdaptiveInvestigationContext(input: {
  finding: AdaptiveFinding;
  evidence: AdaptiveEvidence[];
  events: AdaptiveEvent[];
  relationships: AdaptiveRelationship[];
  assets: AdaptiveAsset[];
  memories: AdaptiveMemory[];
  responseLearning?: AdaptiveResponseLearning[];
  now?: number;
}): AdaptiveInvestigationContext {
  const now = input.now ?? Date.now();
  const assetMap = new Map(input.assets.map((asset) => [asset.id, asset]));
  const rootAssetId = input.finding.asset_id;

  const relatedAssetIds = new Set<string>();
  if (rootAssetId) relatedAssetIds.add(rootAssetId);

  for (const edge of input.relationships) {
    if (edge.status !== "confirmed") continue;
    if (edge.source_asset_id === rootAssetId) relatedAssetIds.add(edge.target_asset_id);
    if (edge.target_asset_id === rootAssetId) relatedAssetIds.add(edge.source_asset_id);
  }

  const findingTime = asTime(input.finding.detected_at);
  const windowMs = 24 * 60 * 60 * 1000;

  const correlatedEvidence = input.evidence.filter((item) => {
    const directAsset = Boolean(item.asset_id && relatedAssetIds.has(item.asset_id));
    const observed = asTime(item.observed_at);
    const withinWindow = findingTime !== null && observed !== null && Math.abs(observed - findingTime) <= windowMs;
    const text = [item.title, item.summary ?? "", item.evidence_type, item.source].join(" ").toLowerCase();
    const termMatch = [input.finding.title, input.finding.finding_type]
      .filter(Boolean)
      .some((term) => text.includes(term.toLowerCase()));
    return directAsset || (withinWindow && termMatch);
  });

  const correlatedEvents = input.events.filter((item) => {
    const directAsset = Boolean(item.asset_id && relatedAssetIds.has(item.asset_id));
    const observed = asTime(item.observed_at);
    return directAsset || (findingTime !== null && observed !== null && Math.abs(observed - findingTime) <= windowMs);
  });

  const latestEvidenceAt = correlatedEvidence
    .map((item) => asTime(item.observed_at))
    .filter((value): value is number => value !== null)
    .sort((a, b) => b - a)[0] ?? null;

  const evidenceFreshnessMinutes = latestEvidenceAt === null
    ? null
    : Math.max(0, Math.round((now - latestEvidenceAt) / 60000));

  const confirmedEdges = input.relationships.filter(
    (edge) =>
      edge.status === "confirmed" &&
      (edge.source_asset_id === rootAssetId || edge.target_asset_id === rootAssetId),
  );

  const reachability = new Map<string, { hops: number; confidence: number; chain: string[] }>();
  if (rootAssetId) {
    const queue = [{ id: rootAssetId, hops: 0, confidence: 1, chain: [] as string[] }];
    const seen = new Map<string, number>([[rootAssetId, 0]]);

    while (queue.length) {
      const current = queue.shift()!;
      if (current.hops >= 4) continue;

      for (const edge of input.relationships) {
        if (edge.status !== "confirmed" || edge.source_asset_id !== current.id) continue;
        if (!assetMap.has(edge.target_asset_id)) continue;

        const hops = current.hops + 1;
        if ((seen.get(edge.target_asset_id) ?? Infinity) <= hops) continue;

        const confidence = Math.min(current.confidence, edge.confidence ?? 0);
        const chain = [...current.chain, edge.relationship_type ?? "connected"];
        seen.set(edge.target_asset_id, hops);
        reachability.set(edge.target_asset_id, { hops, confidence, chain });
        queue.push({ id: edge.target_asset_id, hops, confidence, chain });
      }
    }
  }

  const confirmedReachability = [...reachability.entries()]
    .map(([id, value]) => ({ asset: assetMap.get(id), ...value }))
    .filter((item): item is { asset: AdaptiveAsset; hops: number; confidence: number; chain: string[] } => Boolean(item.asset))
    .sort((a, b) => a.hops - b.hops || b.confidence - a.confidence)
    .slice(0, 25);

  const relevantMemory = input.memories.filter((memory) => {
    const memoryFindingId = extractFindingId(memory);
    if (memoryFindingId === input.finding.id) return true;
    const memoryAssetId = typeof memory.data?.asset_id === "string"
      ? memory.data.asset_id
      : typeof memory.data?.affected_asset_id === "string"
        ? memory.data.affected_asset_id
        : null;
    return Boolean(rootAssetId && memoryAssetId === rootAssetId);
  });

  const findingStates = relevantMemory
    .filter((memory) => memory.memory_type === "finding_state")
    .slice(0, 10);

  const investigations = relevantMemory.filter((memory) => memory.memory_type === "investigation");
  const decisions = relevantMemory.filter((memory) => memory.memory_type === "operator_decision");
  const outcomes = relevantMemory.filter((memory) => memory.memory_type === "response_outcome");
  const verifications = relevantMemory.filter((memory) => memory.memory_type === "verification");

  const latestVerification = [...verifications]
    .sort((a, b) => (asTime(b.occurred_at) ?? 0) - (asTime(a.occurred_at) ?? 0))
    .map((memory) => {
      const state = typeof memory.data?.state === "string"
        ? memory.data.state
        : typeof memory.data?.verification === "object" && memory.data.verification !== null &&
          typeof (memory.data.verification as Record<string, unknown>).state === "string"
          ? (memory.data.verification as Record<string, unknown>).state as string
          : memory.state;
      return { id: memory.id, state, occurredAt: memory.occurred_at };
    })[0] ?? null;

  const latestVerificationMemory = [...verifications]
    .sort((a, b) => (asTime(b.occurred_at) ?? 0) - (asTime(a.occurred_at) ?? 0))[0] ?? null;

  const latestVerificationState =
    latestVerification?.state === "resolved" ||
    latestVerification?.state === "persisting" ||
    latestVerification?.state === "returned" ||
    latestVerification?.state === "unknown"
      ? latestVerification.state
      : null;

  const latestVerificationData = latestVerificationMemory?.data ?? {};
  const latestVerificationEvidenceCount = Array.isArray(latestVerificationData.evidence)
    ? latestVerificationData.evidence.length
    : Array.isArray((latestVerificationData.verification as Record<string, unknown> | undefined)?.evidence)
      ? ((latestVerificationData.verification as Record<string, unknown>).evidence as unknown[]).length
      : 0;

  const learningState: AdaptiveLearningState = {
    state: latestVerificationState,
    occurredAt: latestVerification?.occurredAt ?? null,
    actionType:
      typeof latestVerificationData.action_type === "string"
        ? latestVerificationData.action_type
        : typeof latestVerificationData.actionType === "string"
          ? latestVerificationData.actionType
          : null,
    evidenceCount: latestVerificationEvidenceCount,
    learningSignal:
      latestVerificationState === "persisting"
        ? "reinvestigate"
        : latestVerificationState === "returned"
          ? "recurrence_review"
          : latestVerificationState === "unknown"
            ? "evidence_gap"
            : latestVerificationState === "resolved"
              ? "de_escalate"
              : "none",
    rationale:
      latestVerificationState === "persisting"
        ? "The latest explicit verification says the condition persists; Trinorin should prioritize fresh evidence and review whether the authorized response changed the current state."
        : latestVerificationState === "returned"
          ? "The latest explicit verification says the condition returned; Trinorin should prioritize recurrence evidence and compare the current state with the prior response outcome."
          : latestVerificationState === "unknown"
            ? "The latest explicit verification is inconclusive; Trinorin should request evidence rather than infer resolution."
            : latestVerificationState === "resolved"
              ? "The latest explicit verification reports resolution; this is historical response learning, not proof that the current finding is resolved."
              : "No explicit verification learning is available yet.",
  };

  const contradictions: string[] = [];

  if (input.finding.status === "open" && latestVerification?.state === "resolved") {
    contradictions.push("The finding remains active while the latest explicit response verification is marked resolved; current evidence needs reconciliation.");
  }

  if ((latestVerification?.state === "persisting" || latestVerification?.state === "returned") && correlatedEvidence.length === 0) {
    contradictions.push("A prior explicit verification indicates persistence or return, but no correlated current evidence was found.");
  }

  if (latestVerification?.state === "resolved" && latestEvidenceAt !== null && findingTime !== null && latestEvidenceAt > findingTime) {
    contradictions.push("Evidence observed after the finding was detected exists alongside a resolved verification state; chronology should be reviewed.");
  }

  const unknowns = [
    !rootAssetId ? "No affected asset is linked to the finding." : null,
    correlatedEvidence.length === 0 ? "No correlated evidence was found in the current investigation window." : null,
    correlatedEvents.length === 0 ? "No correlated security events were found in the current investigation window." : null,
    confirmedEdges.length === 0 ? "No confirmed first-hop asset relationship is available." : null,
    latestVerification === null ? "No explicit post-response verification is recorded." : null,
    latestVerificationState === "unknown" ? "The latest verification is inconclusive, so response effectiveness remains unknown." : null,
    latestVerificationState === "persisting" && correlatedEvidence.length === 0
      ? "The latest verification says the condition persists, but current correlated evidence is absent; response effectiveness cannot be independently checked."
      : null,
    latestVerificationState === "returned" && correlatedEvidence.length === 0
      ? "The latest verification says the condition returned, but current correlated evidence is absent; recurrence cannot be independently characterized."
      : null,
    "The available records do not establish attacker attribution, successful exploitation, or compromise unless explicit evidence says so.",
  ].filter((value): value is string => Boolean(value));

  const nextEvidenceNeeded = [
    correlatedEvidence.length === 0 ? "Obtain fresh telemetry or evidence directly from the affected asset." : null,
    evidenceFreshnessMinutes !== null && evidenceFreshnessMinutes > 60
      ? "Refresh telemetry because the latest correlated evidence is more than one hour old."
      : null,
    latestVerification === null && outcomes.length > 0
      ? "Record explicit post-response evidence before treating the response as verified."
      : null,
    latestVerificationState === "persisting"
      ? "Collect fresh evidence from the affected asset and review whether the prior response changed the observed condition."
      : null,
    latestVerificationState === "returned"
      ? "Collect recurrence evidence, compare it with the prior response evidence, and investigate what changed before deciding on another response."
      : null,
    latestVerificationState === "unknown"
      ? "Obtain fresh telemetry and an explicit verification result; do not infer resolution from missing telemetry."
      : null,
    latestVerificationState === "resolved" && input.finding.status === "open"
      ? "Reconcile the active finding with the resolved verification using current evidence before changing the finding state."
      : null,
    contradictions.length > 0 ? "Reconcile the contradictory state using current evidence and timestamps." : null,
    confirmedEdges.length === 0 && rootAssetId
      ? "Establish or validate confirmed relationships before expanding blast-radius reasoning."
      : null,
  ].filter((value): value is string => Boolean(value));

  const reasoning = [
    rootAssetId ? "Investigation is anchored to the finding's affected asset." : "Investigation is not asset-anchored.",
    correlatedEvidence.length
      ? `${correlatedEvidence.length} evidence record(s) correlate by asset, time, or finding context.`
      : "No evidence record currently correlates strongly enough to support the finding.",
    correlatedEvents.length
      ? `${correlatedEvents.length} event signal(s) are available for temporal context.`
      : "No event signal is currently available for temporal context.",
    confirmedReachability.length
      ? `${confirmedReachability.length} downstream asset(s) are reachable through confirmed relationships.`
      : "No confirmed downstream reachability was established.",
    latestVerification
      ? `Latest explicit verification state is ${latestVerification.state}; adaptive learning signal is ${learningState.learningSignal}.`
      : "No explicit verification state is available.",
    learningState.learningSignal === "reinvestigate"
      ? "Prior response learning indicates the condition persisted, so the next investigation should prioritize current evidence and response effectiveness."
      : null,
    learningState.learningSignal === "recurrence_review"
      ? "Prior response learning indicates recurrence, so the next investigation should compare the current state with the previous response and look for changed conditions."
      : null,
    learningState.learningSignal === "evidence_gap"
      ? "Prior response learning is inconclusive, so the next investigation should close the evidence gap before any conclusion."
      : null,
    learningState.learningSignal === "de_escalate"
      ? "Prior response learning reports resolution; Trinorin keeps that as historical context and still checks current evidence before treating an active finding as resolved."
      : null,
  ];

  const confidence: AdaptiveInvestigationContext["confidence"] =
    contradictions.length === 0 && correlatedEvidence.length >= 5 && (confirmedReachability.length > 0 || correlatedEvents.length >= 3)
      ? "strong"
      : correlatedEvidence.length >= 2 || correlatedEvents.length >= 2
        ? "moderate"
        : "limited";

  return {
    generatedAt: new Date(now).toISOString(),
    confidence,
    currentState: {
      findingStatus: input.finding.status,
      severity: input.finding.severity,
      affectedAsset: rootAssetId ? assetMap.get(rootAssetId) ?? null : null,
      latestEvidenceAt: latestEvidenceAt !== null ? new Date(latestEvidenceAt).toISOString() : null,
      evidenceFreshnessMinutes,
      correlatedEvidenceCount: correlatedEvidence.length,
      correlatedEvidenceIds: correlatedEvidence.map((item) => item.id).slice(0, 100),
      correlatedEvidenceProfiles: correlatedEvidence.map((item) => ({
        id: item.id,
        source: item.source,
        evidenceType: item.evidence_type,
        observedAt: item.observed_at,
      })).slice(0, 100),
      correlatedEventCount: correlatedEvents.length,
      correlatedEventIds: correlatedEvents.map((item) => item.id).slice(0, 100),
      confirmedConnectedAssets: confirmedEdges.length,
    },
    historicalState: {
      priorFindingStates: findingStates.map((memory) => ({
        occurredAt: memory.occurred_at,
        previousState: typeof memory.data?.previous_state === "string" ? memory.data.previous_state : null,
        currentState: typeof memory.data?.current_state === "string" ? memory.data.current_state : memory.state,
        summary: memory.summary,
      })),
      priorInvestigations: investigations.length,
      priorOperatorDecisions: decisions.length,
      responseOutcomes: outcomes.length,
      verifications: verifications.length,
      latestVerification,
    },
    responseLearning: input.responseLearning ?? [],
    learningState,
    confirmedReachability,
    contradictions,
    unknowns,
    nextEvidenceNeeded,
    reasoning: reasoning.filter((item): item is string => item !== null),
  };
}
