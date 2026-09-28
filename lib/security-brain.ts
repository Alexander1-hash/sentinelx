export type SecurityBrainRecord = Record<string, unknown>;

export type SecurityBrainState = {
  findings: SecurityBrainRecord[];
  evidence: SecurityBrainRecord[];
  assets: SecurityBrainRecord[];
  relationships: SecurityBrainRecord[];
  aiSystems: SecurityBrainRecord[];
  aiAgents: SecurityBrainRecord[];
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

const severityRank: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
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

function recordId(value: unknown): string {
  return text(value);
}

export function buildSecurityBrain(input: {
  findings: SecurityBrainRecord[];
  evidence: SecurityBrainRecord[];
  assets: SecurityBrainRecord[];
  relationships: SecurityBrainRecord[];
  aiSystems: SecurityBrainRecord[];
  aiAgents: SecurityBrainRecord[];
}): SecurityBrainState {
  const signals: SecurityBrainState["signals"] = [];
  const assetById = new Map(input.assets.map((asset) => [recordId(asset.id), asset]));
  const systemById = new Map(input.aiSystems.map((system) => [recordId(system.id), system]));
  const agentsBySystemId = new Map<string, SecurityBrainRecord[]>();

  for (const agent of input.aiAgents) {
    const systemId = recordId(agent.system_id);
    if (!systemId) continue;
    const current = agentsBySystemId.get(systemId) ?? [];
    current.push(agent);
    agentsBySystemId.set(systemId, current);
  }

  for (const finding of input.findings) {
    const findingSeverity = severity(finding.severity);
    const asset = assetById.get(recordId(finding.asset_id));
    const assetName = text(asset?.name);
    const assetType = text(asset?.asset_type);

    signals.push({
      kind: "finding",
      severity: findingSeverity,
      title: text(finding.title) || "Security finding",
      detail: [
        text(finding.summary) || "A registered security finding requires analyst review.",
        assetName ? `Affected asset: ${assetName}${assetType ? ` (${assetType})` : ""}.` : "Affected asset is not linked.",
      ].join(" "),
      sourceId: recordId(finding.id) || null,
    });
  }

  for (const item of input.evidence) {
    const s = severity(item.severity ?? (item.data as SecurityBrainRecord | null)?.severity);
    if (s === "critical" || s === "high") {
      const asset = assetById.get(recordId(item.asset_id));
      signals.push({
        kind: "evidence",
        severity: s,
        title: text(item.title) || "High-impact evidence",
        detail: [
          text(item.summary) || "High-impact evidence is available for correlation.",
          text(asset?.name) ? `Linked asset: ${text(asset?.name)}.` : "Linked asset is not recorded.",
        ].join(" "),
        sourceId: recordId(item.id) || null,
      });
    }
  }

  for (const edge of input.relationships) {
    if (text(edge.status).toLowerCase() !== "confirmed") continue;
    const source = assetById.get(recordId(edge.source_asset_id));
    const target = assetById.get(recordId(edge.target_asset_id));
    const sourceName = text(source?.name) || recordId(edge.source_asset_id) || "source asset";
    const targetName = text(target?.name) || recordId(edge.target_asset_id) || "target asset";

    signals.push({
      kind: "relationship",
      severity: "unknown",
      title: text(edge.relationship_type) || "Confirmed relationship",
      detail: `${sourceName} → ${targetName}. This confirmed relationship contributes context to attack-path and blast-radius analysis; it does not by itself establish a threat.`,
      sourceId: recordId(edge.id) || null,
    });
  }

  for (const agent of input.aiAgents) {
    if (text(agent.autonomy_level).toLowerCase() !== "autonomous") continue;
    const system = systemById.get(recordId(agent.system_id));
    const tools = Array.isArray(agent.tools) ? agent.tools.length : 0;
    const permissions = agent.permissions && typeof agent.permissions === "object" ? Object.keys(agent.permissions).length : 0;

    signals.push({
      kind: "ai",
      severity: "medium",
      title: text(agent.name) || "Autonomous AI agent",
      detail: [
        text(system?.name) ? `System: ${text(system?.name)}.` : "System relationship is not recorded.",
        `${tools} declared tool${tools === 1 ? "" : "s"} and ${permissions} permission field${permissions === 1 ? "" : "s"} are recorded.`,
        "Validate tools, permissions and declared data scope before authorizing sensitive actions.",
      ].join(" "),
      sourceId: recordId(agent.id) || null,
    });
  }

  for (const system of input.aiSystems) {
    const linkedAgents = agentsBySystemId.get(recordId(system.id)) ?? [];
    const asset = assetById.get(recordId(system.asset_id));
    const autonomousCount = linkedAgents.filter((agent) => text(agent.autonomy_level).toLowerCase() === "autonomous").length;
    if (!autonomousCount || !asset) continue;

    signals.push({
      kind: "ai",
      severity: "high",
      title: `${text(system.name) || "AI system"} has autonomous agents and a linked asset`,
      detail: `Linked asset: ${text(asset.name) || "unknown asset"}. ${autonomousCount} autonomous agent${autonomousCount === 1 ? "" : "s"} are registered under this system. Review the asset boundary, permissions and data access together.`,
      sourceId: recordId(system.id) || null,
    });
  }

  signals.sort((a, b) => (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0));

  const unknowns: string[] = [];
  if (!input.findings.length) unknowns.push("No security findings are currently registered.");
  if (!input.evidence.length) unknowns.push("No security evidence is currently registered.");
  if (!input.assets.length) unknowns.push("No security assets are currently registered.");
  if (!input.relationships.some((item) => text(item.status).toLowerCase() === "confirmed")) unknowns.push("No confirmed asset relationships are available.");
  if (!input.aiSystems.length && !input.aiAgents.length) unknowns.push("No registered AI systems or agents are available.");
  if (input.findings.some((finding) => !assetById.has(recordId(finding.asset_id)))) unknowns.push("At least one finding has no resolvable asset link.");
  if (input.aiAgents.some((agent) => text(agent.autonomy_level).toLowerCase() === "autonomous" && !systemById.has(recordId(agent.system_id)))) unknowns.push("At least one autonomous AI agent has no resolvable system link.");
  unknowns.push("Missing telemetry is unknown, not safe. Correlation does not establish compromise or attacker intent.");

  return {
    ...input,
    signals: signals.slice(0, 100),
    unknowns,
    boundary: "Security Brain correlates organization-scoped findings, evidence, assets, confirmed relationships and AI security records. It reports observed context and uncertainty; it does not infer compromise from missing data.",
  };
}
