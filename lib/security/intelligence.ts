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

export function synthesizeSecurityIntelligence(input: {
  findings: IntelligenceFinding[];
  evidence: IntelligenceEvidence[];
  events: IntelligenceEvent[];
  relationships: IntelligenceRelationship[];
  memories: IntelligenceMemory[];
  assets: IntelligenceAsset[];
  now?: number;
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

  const activeFindings = input.findings.filter((finding) => ["open", "acknowledged"].includes(finding.status));
  const priorities = activeFindings
    .map((finding) => {
      const evidenceCount = finding.asset_id ? evidenceByAsset.get(finding.asset_id) ?? 0 : 0;
      const eventCount = finding.asset_id ? eventsByAsset.get(finding.asset_id) ?? 0 : 0;
      const neighborCount = finding.asset_id ? neighbors.get(finding.asset_id)?.size ?? 0 : 0;
      const recurrence = input.memories.filter((memory) =>
        memory.subject_id === finding.id || memory.data.finding_id === finding.id
      ).length;
      const score = Math.min(
        100,
        (severityWeight[finding.severity.toLowerCase()] ?? 0) +
          recencyWeight(finding.detected_at, now) +
          Math.min(15, evidenceCount * 3) +
          Math.min(10, eventCount * 2) +
          Math.min(10, neighborCount * 2) +
          Math.min(10, recurrence * 2),
      );
      const asset = finding.asset_id ? assetMap.get(finding.asset_id) : null;
      return {
        findingId: finding.id,
        title: finding.title,
        severity: finding.severity,
        score,
        asset: asset?.name ?? null,
        assetId: finding.asset_id,
        evidenceCount,
        eventCount,
        connectedAssets: neighborCount,
        historicalRecords: recurrence,
        reasons: [
          `${finding.severity} severity`,
          evidenceCount ? `${evidenceCount} linked evidence record${evidenceCount === 1 ? "" : "s"}` : "no directly linked evidence",
          neighborCount ? `${neighborCount} confirmed connected asset${neighborCount === 1 ? "" : "s"}` : "no confirmed asset connection",
          recurrence ? `${recurrence} historical memory record${recurrence === 1 ? "" : "s"}` : "no historical memory for this finding",
        ],
      };
    })
    .sort((a, b) => b.score - a.score)
    .slice(0, 8);

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
      ["evidence_change", "finding_state", "response_outcome", "verification"].includes(memory.memory_type)
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
    boundary:
      "Trinorin intelligence is evidence-first. Priority scores organize recorded signals for investigation; they do not prove compromise, attacker intent, causation, or future outcome.",
  };
}
