export type SecurityBrainState = {
  findings: unknown[];
  evidence: unknown[];
  assets: unknown[];
  relationships: unknown[];
  aiSystems: unknown[];
  aiAgents: unknown[];
  signals: Array<{
    kind: "finding" | "evidence" | "relationship" | "ai";
    severity: "critical" | "high" | "medium" | "low" | "unknown";
    title: string;
    detail: string;
    sourceId: string | null;
  }>;
  unknowns: string[];
  boundary: string;
};

type RecordLike = Record<string, unknown>;

const severityRank: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function severity(value: unknown): SecurityBrainState["signals"][number]["severity"] {
  const valueText = text(value).toLowerCase();
  return valueText === "critical" || valueText === "high" || valueText === "medium" || valueText === "low"
    ? valueText
    : "unknown";
}

export function buildSecurityBrain(input: {
  findings: RecordLike[];
  evidence: RecordLike[];
  assets: RecordLike[];
  relationships: RecordLike[];
  aiSystems: RecordLike[];
  aiAgents: RecordLike[];
}): SecurityBrainState {
  const signals: SecurityBrainState["signals"] = [];

  for (const finding of input.findings) {
    signals.push({
      kind: "finding",
      severity: severity(finding.severity),
      title: text(finding.title) || "Security finding",
      detail: text(finding.summary) || "A registered security finding requires analyst review.",
      sourceId: text(finding.id) || null,
    });
  }

  for (const item of input.evidence) {
    const s = severity(item.severity ?? (item.data as RecordLike | null)?.severity);
    if (s === "critical" || s === "high") {
      signals.push({
        kind: "evidence",
        severity: s,
        title: text(item.title) || "High-impact evidence",
        detail: text(item.summary) || "High-impact evidence is available for correlation.",
        sourceId: text(item.id) || null,
      });
    }
  }

  for (const edge of input.relationships) {
    if (text(edge.status).toLowerCase() === "confirmed") {
      signals.push({
        kind: "relationship",
        severity: "unknown",
        title: text(edge.relationship_type) || "Confirmed relationship",
        detail: "A confirmed asset relationship contributes context to attack-path and blast-radius analysis.",
        sourceId: text(edge.id) || null,
      });
    }
  }

  for (const agent of input.aiAgents) {
    if (text(agent.autonomy_level).toLowerCase() === "autonomous") {
      signals.push({
        kind: "ai",
        severity: "medium",
        title: text(agent.name) || "Autonomous AI agent",
        detail: "An autonomous AI agent is registered. Validate its tools, permissions and declared data scope.",
        sourceId: text(agent.id) || null,
      });
    }
  }

  signals.sort((a, b) => (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0));

  const unknowns: string[] = [];
  if (!input.findings.length) unknowns.push("No security findings are currently registered.");
  if (!input.evidence.length) unknowns.push("No security evidence is currently registered.");
  if (!input.assets.length) unknowns.push("No security assets are currently registered.");
  if (!input.relationships.length) unknowns.push("No confirmed asset relationships are available.");
  if (!input.aiSystems.length && !input.aiAgents.length) unknowns.push("No registered AI systems or agents are available.");
  unknowns.push("Missing telemetry is unknown, not safe. Correlation does not establish compromise or attacker intent.");

  return {
    ...input,
    signals: signals.slice(0, 100),
    unknowns,
    boundary: "Security Brain correlates organization-scoped findings, evidence, assets, confirmed relationships and AI security records. It reports observed context and uncertainty; it does not infer compromise from missing data.",
  };
}
