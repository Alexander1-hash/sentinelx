export type SecurityPatternMemory = {
  id: string;
  memory_type: string;
  subject_id: string | null;
  title: string;
  summary: string;
  state: string;
  data: Record<string, unknown>;
  occurred_at: string;
};

export type SecurityPattern = {
  id: string;
  pattern:
    | "recurrence"
    | "reopened_condition"
    | "repeated_evidence_change"
    | "repeated_ai_indicator"
    | "response_cycle"
    | "security_sequence";
  title: string;
  detail: string;
  confidence: "high" | "medium";
  memoryIds: string[];
  firstObserved: string;
  lastObserved: string;
  boundary: string;
  sequence?: string[];
};

const str = (value: unknown) =>
  typeof value === "string" && value.trim() ? value : null;

const stateOf = (memory: SecurityPatternMemory) =>
  str(memory.data.current_security_state) ??
  str(memory.data.current_state) ??
  memory.state;

function memoryKey(memory: SecurityPatternMemory) {
  const findingId =
    str(memory.data.finding_id) ??
    (memory.memory_type === "finding_state" ? memory.subject_id : null);
  const assetId =
    str(memory.data.asset_id) ??
    str(memory.data.affected_asset_id);
  const evidenceType = str(memory.data.evidence_type);
  const indicator =
    str(memory.data.indicator) ??
    str(memory.data.category);

  if (findingId) return "finding:" + findingId;
  if (assetId) return "asset:" + assetId;
  if (evidenceType) return "evidence:" + evidenceType;
  if (indicator) return "indicator:" + indicator;
  return null;
}

export function buildSecurityPatterns(
  memories: SecurityPatternMemory[],
): SecurityPattern[] {
  const patterns: SecurityPattern[] = [];
  const groups = new Map<string, SecurityPatternMemory[]>();

  for (const memory of memories) {
    const key = memoryKey(memory);
    if (!key) continue;
    const list = groups.get(key) ?? [];
    list.push(memory);
    groups.set(key, list);
  }

  for (const [key, list] of groups) {
    if (list.length < 2) continue;

    const ordered = [...list].sort(
      (a, b) =>
        new Date(a.occurred_at).getTime() -
        new Date(b.occurred_at).getTime(),
    );
    const first = ordered[0];
    const last = ordered[ordered.length - 1];
    const ids = ordered.slice(-8).map((item) => item.id);

    if (key.startsWith("finding:")) {
      patterns.push({
        id: "recurrence-" + key,
        pattern: "recurrence",
        title: "Recurring finding history detected",
        detail:
          "This finding has " +
          list.length +
          " recorded security-memory event(s) across time. Previous context should be reviewed before treating the latest observation as isolated.",
        confidence: "high",
        memoryIds: ids,
        firstObserved: first.occurred_at,
        lastObserved: last.occurred_at,
        boundary:
          "Recurrence is based on recorded memory, not proof that the condition is currently active.",
      });
    }

    const hasResolution = ordered.some(
      (memory) =>
        memory.memory_type === "evidence_change" &&
        ["resolved", "cleared", "healthy"].includes(stateOf(memory)),
    );

    const resolutionIndex = ordered.findIndex(
      (memory) =>
        memory.memory_type === "evidence_change" &&
        ["resolved", "cleared", "healthy"].includes(stateOf(memory)),
    );

    const hasLaterActive = ordered.some(
      (memory, index) =>
        index > resolutionIndex &&
        ["active", "degraded", "open"].includes(stateOf(memory)),
    );

    if (hasResolution && resolutionIndex >= 0 && hasLaterActive) {
      patterns.push({
        id: "reopened-" + key,
        pattern: "reopened_condition",
        title: "Condition appears to have returned after a recorded resolution",
        detail:
          "Historical memory contains a recorded cleared/resolved state followed by a later active/degraded/open state.",
        confidence: "high",
        memoryIds: ids,
        firstObserved: first.occurred_at,
        lastObserved: last.occurred_at,
        boundary:
          "This is a temporal pattern in recorded state transitions; current telemetry is required to establish present state.",
      });
    }
  }

  const evidenceGroups = new Map<string, SecurityPatternMemory[]>();
  for (const memory of memories.filter(
    (item) => item.memory_type === "evidence_change",
  )) {
    const key =
      (str(memory.data.source) ?? "unknown") +
      ":" +
      (str(memory.data.title) ?? memory.title) +
      ":" +
      (str(memory.data.asset_id) ?? "none");
    const list = evidenceGroups.get(key) ?? [];
    list.push(memory);
    evidenceGroups.set(key, list);
  }

  for (const [key, list] of evidenceGroups) {
    if (list.length < 3) continue;
    patterns.push({
      id: "evidence-repeat-" + key,
      pattern: "repeated_evidence_change",
      title: "Repeated evidence changes detected",
      detail:
        list.length +
        " recorded evidence transitions match the same source/title/asset context.",
      confidence: "medium",
      memoryIds: list.slice(0, 8).map((item) => item.id),
      firstObserved: list[list.length - 1].occurred_at,
      lastObserved: list[0].occurred_at,
      boundary:
        "Repeated change is an investigation signal, not proof of compromise.",
    });
  }

  const aiMemories = memories.filter((memory) =>
    /(prompt injection|jailbreak|indirect prompt|credential|secret exposure|sensitive data|tool call|mcp|excessive permission|shadow ai)/i.test(
      (memory.title + " " + memory.summary + " " + JSON.stringify(memory.data)).toLowerCase(),
    ),
  );

  const aiGroups = new Map<string, SecurityPatternMemory[]>();
  for (const memory of aiMemories) {
    const category =
      str(memory.data.category) ??
      str(memory.data.indicator) ??
      "ai-security-signal";
    const list = aiGroups.get(category) ?? [];
    list.push(memory);
    aiGroups.set(category, list);
  }

  for (const [category, list] of aiGroups) {
    if (list.length < 2) continue;
    patterns.push({
      id: "ai-repeat-" + category,
      pattern: "repeated_ai_indicator",
      title: "Repeated AI security indicator: " + category,
      detail:
        list.length +
        " recorded memory event(s) contain the same AI-security indicator category.",
      confidence: "medium",
      memoryIds: list.slice(0, 8).map((item) => item.id),
      firstObserved: list[list.length - 1].occurred_at,
      lastObserved: list[0].occurred_at,
      boundary:
        "The indicator is evidence context only. It does not establish malicious behavior or compromise.",
    });
  }

  const chronological = [...memories].sort(
    (a, b) =>
      new Date(a.occurred_at).getTime() - new Date(b.occurred_at).getTime(),
  );

  const sequencePatterns = [
    {
      name: "AI indicator → finding → investigation",
      types: ["ai", "finding_state", "investigation"],
      detail:
        "Recorded memory shows an AI-security indicator followed by a finding state and a later investigation.",
    },
    {
      name: "Finding → investigation → operator decision",
      types: ["finding_state", "investigation", "operator_decision"],
      detail:
        "Recorded memory shows a finding followed by investigation and an operator decision.",
    },
    {
      name: "Operator decision → response outcome",
      types: ["operator_decision", "response_outcome"],
      detail:
        "Recorded memory shows an operator decision followed by a recorded response outcome.",
    },
    {
      name: "Resolution → later active condition",
      types: ["resolved", "active"],
      detail:
        "Recorded evidence history shows a resolution state followed later by an active state.",
    },
  ] as const;

  const isAiMemory = (memory: SecurityPatternMemory) =>
    /(prompt injection|jailbreak|indirect prompt|credential|secret exposure|sensitive data|tool call|mcp|excessive permission|shadow ai)/i.test(
      memory.title + " " + memory.summary + " " + JSON.stringify(memory.data),
    );

  const contextIds = (memory: SecurityPatternMemory) => {
    const ids = new Set<string>();

    const findingId =
      str(memory.data.finding_id) ??
      (memory.memory_type === "finding_state" ? memory.subject_id : null);
    const assetId =
      str(memory.data.asset_id) ??
      str(memory.data.affected_asset_id);
    const evidenceId = str(memory.data.evidence_id) ?? str(memory.data.current_evidence_id);
    const actionId = str(memory.data.action_id);

    if (findingId) ids.add("finding:" + findingId);
    if (assetId) ids.add("asset:" + assetId);
    if (evidenceId) ids.add("evidence:" + evidenceId);
    if (actionId) ids.add("action:" + actionId);

    return ids;
  };

  const sharesContext = (
    chain: SecurityPatternMemory[],
    candidate: SecurityPatternMemory,
  ) => {
    const chainContext = new Set<string>();
    for (const memory of chain) {
      for (const id of contextIds(memory)) chainContext.add(id);
    }

    const candidateContext = contextIds(candidate);

    // Strongly prefer shared finding/asset/evidence/action context. If neither
    // side has usable context, do not manufacture a relationship between them.
    if (chainContext.size === 0 || candidateContext.size === 0) return false;

    for (const id of candidateContext) {
      if (chainContext.has(id)) return true;
    }

    return false;
  };

  const sequenceMatches: Array<{ definition: (typeof sequencePatterns)[number]; matched: SecurityPatternMemory[] }> = [];
  for (const sequence of sequencePatterns) {
    for (let start = 0; start < chronological.length; start += 1) {
      const first = chronological[start];
      const firstMatches =
        sequence.types[0] === "ai"
          ? isAiMemory(first)
          : sequence.types[0] === "resolved"
            ? first.memory_type === "evidence_change" &&
              ["resolved", "cleared", "healthy"].includes(stateOf(first))
            : sequence.types[0] === "active"
              ? ["active", "degraded", "open"].includes(stateOf(first))
              : first.memory_type === sequence.types[0];

      if (!firstMatches) continue;

      const matched = [first];
      let cursor = start + 1;

      for (let step = 1; step < sequence.types.length && cursor < chronological.length; step += 1) {
        let found: SecurityPatternMemory | null = null;

        while (cursor < chronological.length) {
          const candidate = chronological[cursor];
          const type = sequence.types[step];
          const matches =
            type === "ai"
              ? isAiMemory(candidate)
              : type === "active"
                ? ["active", "degraded", "open"].includes(stateOf(candidate))
                : type === "resolved"
                  ? candidate.memory_type === "evidence_change" &&
                    ["resolved", "cleared", "healthy"].includes(stateOf(candidate))
                  : candidate.memory_type === type;

          cursor += 1;

          if (matches && sharesContext(matched, candidate)) {
            found = candidate;
            break;
          }
        }

        if (!found) break;
        matched.push(found);
      }

      if (matched.length === sequence.types.length) {
        sequenceMatches.push({ definition: sequence, matched });
        break;
      }
    }
  }

  for (const sequenceMatch of sequenceMatches) {
    const matched = sequenceMatch.matched;
    const definition = sequenceMatch.definition;
    if (!matched.length) continue;

    patterns.push({
      id: "sequence-" + index + "-" + matched.map((item) => item.id).join("-"),
      pattern: "security_sequence",
      title: "Security sequence detected: " + definition.name,
      detail: definition.detail,
      confidence: "medium",
      memoryIds: matched.map((item) => item.id),
      firstObserved: matched[0].occurred_at,
      lastObserved: matched[matched.length - 1].occurred_at,
      boundary:
        "This sequence connects recorded historical events. It does not prove causation, compromise, or current security state.",
      sequence: matched.map((item) => {
        if (item.memory_type === "evidence_change") {
          const state = stateOf(item);
          if (["resolved", "cleared", "healthy"].includes(state)) return "resolution";
          if (["active", "degraded", "open"].includes(state)) return "active condition";
        }
        if (item.memory_type === "finding_state") return "finding";
        if (item.memory_type === "operator_decision") return "operator decision";
        if (item.memory_type === "response_outcome") return "response outcome";
        if (item.memory_type === "investigation") return "investigation";
        if (isAiMemory(item)) return "AI security indicator";
        return item.memory_type;
      }),
    });
  }

  const decisions = memories.filter(
    (memory) => memory.memory_type === "operator_decision",
  );
  const outcomes = memories.filter(
    (memory) => memory.memory_type === "response_outcome",
  );

  const decisionGroups = new Map<string, SecurityPatternMemory[]>();
  for (const decision of decisions) {
    const actionId = str(decision.data.action_id) ?? decision.subject_id;
    if (!actionId) continue;
    const list = decisionGroups.get(actionId) ?? [];
    list.push(decision);
    decisionGroups.set(actionId, list);
  }

  for (const [actionId, actionDecisions] of decisionGroups) {
    const hasOutcome = outcomes.some(
      (outcome) => str(outcome.data.action_id) === actionId,
    );

    if (!hasOutcome) {
      patterns.push({
        id: "response-pending-outcome-" + actionId,
        pattern: "response_cycle",
        title: "Authorized response has no recorded outcome",
        detail:
          "An operator decision is recorded for this action, but no explicit executor outcome is currently recorded for the same action.",
        confidence: "medium",
        memoryIds: actionDecisions.slice(0, 8).map((item) => item.id),
        firstObserved: actionDecisions[actionDecisions.length - 1].occurred_at,
        lastObserved: actionDecisions[0].occurred_at,
        boundary:
          "Missing outcome memory does not mean the action failed or succeeded; it means the executor result is not recorded.",
      });
    }
  }

  for (const outcome of outcomes) {
    const actionId = str(outcome.data.action_id);
    if (!actionId) continue;

    const relatedDecisions = decisions.filter(
      (decision) => (str(decision.data.action_id) ?? decision.subject_id) === actionId,
    );

    if (relatedDecisions.length === 0) {
      patterns.push({
        id: "response-unlinked-outcome-" + outcome.id,
        pattern: "response_cycle",
        title: "Response outcome has no linked operator decision",
        detail:
          "An explicit executor outcome exists, but no matching operator decision memory was found for the same action context.",
        confidence: "medium",
        memoryIds: [outcome.id],
        firstObserved: outcome.occurred_at,
        lastObserved: outcome.occurred_at,
        boundary:
          "The outcome is recorded evidence, but the missing decision link limits the historical response chain.",
      });
    }
  }

  return Array.from(new Map(patterns.map((pattern) => [pattern.id, pattern])).values())
    .sort(
      (a, b) =>
        new Date(b.lastObserved).getTime() -
        new Date(a.lastObserved).getTime(),
    )
    .slice(0, 25);
}

export function summarizeSecurityPatterns(patterns: SecurityPattern[]) {
  return {
    total: patterns.length,
    recurrence: patterns.filter((p) => p.pattern === "recurrence").length,
    reopened: patterns.filter((p) => p.pattern === "reopened_condition").length,
    evidence: patterns.filter((p) => p.pattern === "repeated_evidence_change").length,
    ai: patterns.filter((p) => p.pattern === "repeated_ai_indicator").length,
    response: patterns.filter((p) => p.pattern === "response_cycle").length,
    sequences: patterns.filter((p) => p.pattern === "security_sequence").length,
  };
}
