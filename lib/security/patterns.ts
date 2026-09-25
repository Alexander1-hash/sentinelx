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
    | "response_cycle";
  title: string;
  detail: string;
  confidence: "high" | "medium";
  memoryIds: string[];
  firstObserved: string;
  lastObserved: string;
  boundary: string;
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

  const decisions = memories.filter(
    (memory) => memory.memory_type === "operator_decision",
  );
  const outcomes = memories.filter(
    (memory) => memory.memory_type === "response_outcome",
  );

  if (decisions.length > 0 && outcomes.length === 0) {
    patterns.push({
      id: "response-pending-outcome",
      pattern: "response_cycle",
      title: "Response decisions exist without recorded outcomes",
      detail:
        decisions.length +
        " operator decision memory event(s) exist, but no response outcome memory is currently recorded.",
      confidence: "medium",
      memoryIds: decisions.slice(0, 8).map((item) => item.id),
      firstObserved:
        decisions[decisions.length - 1]?.occurred_at ??
        new Date().toISOString(),
      lastObserved: decisions[0]?.occurred_at ?? new Date().toISOString(),
      boundary:
        "No outcome memory does not mean an action failed or succeeded; it means the outcome is not recorded.",
    });
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
  };
}
