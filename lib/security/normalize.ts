export type NormalizedSecurityEvent = {
  eventType: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  source: string;
  title: string;
  description: string | null;
  assetId: string | null;
  observedAt: string;
  indicators: string[];
};

const severities = new Set(["info", "low", "medium", "high", "critical"]);

export function normalizeSecurityEvent(input: Record<string, unknown>): NormalizedSecurityEvent {
  const raw = typeof input.severity === "string" ? input.severity.toLowerCase() : "info";
  const severity = severities.has(raw) ? raw as NormalizedSecurityEvent["severity"] : "info";
  return {
    eventType: typeof input.event_type === "string" ? input.event_type : typeof input.eventType === "string" ? input.eventType : "security_event",
    severity,
    source: typeof input.source === "string" ? input.source : "unknown_source",
    title: typeof input.title === "string" ? input.title : "Untitled security event",
    description: typeof input.description === "string" ? input.description : null,
    assetId: typeof input.asset_id === "string" ? input.asset_id : typeof input.assetId === "string" ? input.assetId : null,
    observedAt: typeof input.observed_at === "string" ? input.observed_at : new Date().toISOString(),
    indicators: Array.isArray(input.indicators) ? input.indicators.filter((v): v is string => typeof v === "string").slice(0, 50) : [],
  };
}

export function severityRank(severity: NormalizedSecurityEvent["severity"]) {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[severity];
}
