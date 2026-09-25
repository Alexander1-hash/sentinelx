import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

type Memory = {
  id: string;
  memory_type: "finding_state" | "investigation" | "operator_decision" | "response_outcome" | "evidence_change";
  subject_id: string | null;
  title: string;
  summary: string;
  state: string;
  data: Record<string, unknown>;
  occurred_at: string;
};

type TimelineItem = {
  id: string;
  memoryId: string;
  type: Memory["memory_type"];
  title: string;
  summary: string;
  state: string;
  occurredAt: string;
  subject: {
    kind: "finding" | "asset" | "evidence" | "action" | "unknown";
    id: string | null;
    name: string | null;
  };
  context: {
    findingId: string | null;
    assetId: string | null;
    evidenceId: string | null;
    actionId: string | null;
    changeType: string | null;
    previousState: string | null;
    currentState: string | null;
  };
  historical: boolean;
};

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function subjectFor(
  memory: Memory,
  names: {
    findings: Map<string, string>;
    assets: Map<string, string>;
    evidence: Map<string, string>;
    actions: Map<string, string>;
  }
): TimelineItem["subject"] {
  const findingId = stringValue(memory.data.finding_id) ??
    (memory.memory_type === "finding_state" || memory.memory_type === "investigation" ? memory.subject_id : null);
  const assetId = stringValue(memory.data.asset_id) ?? stringValue(memory.data.affected_asset_id);
  const evidenceId = stringValue(memory.data.evidence_id) ??
    (memory.memory_type === "evidence_change" ? memory.subject_id : null);
  const actionId = stringValue(memory.data.action_id) ??
    (memory.memory_type === "operator_decision" || memory.memory_type === "response_outcome" ? memory.subject_id : null);

  if (findingId && names.findings.has(findingId)) {
    return { kind: "finding", id: findingId, name: names.findings.get(findingId) ?? null };
  }
  if (assetId && names.assets.has(assetId)) {
    return { kind: "asset", id: assetId, name: names.assets.get(assetId) ?? null };
  }
  if (evidenceId && names.evidence.has(evidenceId)) {
    return { kind: "evidence", id: evidenceId, name: names.evidence.get(evidenceId) ?? null };
  }
  if (actionId && names.actions.has(actionId)) {
    return { kind: "action", id: actionId, name: names.actions.get(actionId) ?? null };
  }
  return { kind: "unknown", id: memory.subject_id, name: null };
}

export async function GET(request: Request) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { data: profile } = await supabase
      .from("profiles")
      .select("organization_id")
      .eq("id", user.id)
      .maybeSingle();

    const organizationId = profile?.organization_id;
    if (!organizationId) {
      return NextResponse.json({
        timeline: [],
        summary: { total: 0, findings: 0, investigations: 0, decisions: 0, outcomes: 0, evidenceChanges: 0 },
        boundary: "No organization-scoped security memory is available.",
      });
    }

    const url = new URL(request.url);
    const requestedLimit = Number(url.searchParams.get("limit") ?? "100");
    const limit = Math.min(Math.max(Number.isFinite(requestedLimit) ? requestedLimit : 100, 1), 200);
    const assetIdFilter = url.searchParams.get("assetId");
    const findingIdFilter = url.searchParams.get("findingId");

    const [memoryResult, findingsResult, assetsResult, evidenceResult, actionsResult] = await Promise.all([
      supabase.from("security_memory")
        .select("id,memory_type,subject_id,title,summary,state,data,occurred_at")
        .eq("organization_id", organizationId)
        .order("occurred_at", { ascending: false })
        .limit(200),
      supabase.from("security_findings")
        .select("id,title,asset_id,status,severity")
        .eq("organization_id", organizationId)
        .limit(300),
      supabase.from("security_assets")
        .select("id,name,asset_type,criticality,status")
        .eq("organization_id", organizationId)
        .limit(300),
      supabase.from("security_evidence")
        .select("id,title,asset_id,evidence_type,source,observed_at")
        .eq("organization_id", organizationId)
        .limit(300),
      supabase.from("security_actions")
        .select("id,action_type,finding_id,status,created_at")
        .eq("organization_id", organizationId)
        .limit(300),
    ]);

    const error = memoryResult.error ?? findingsResult.error ?? assetsResult.error ?? evidenceResult.error ?? actionsResult.error;
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    const memories = (memoryResult.data ?? []) as Memory[];
    const findings = findingsResult.data ?? [];
    const assets = assetsResult.data ?? [];
    const evidence = evidenceResult.data ?? [];
    const actions = actionsResult.data ?? [];

    const findingNames = new Map(findings.map((item) => [item.id, item.title]));
    const assetNames = new Map(assets.map((item) => [item.id, item.name]));
    const evidenceNames = new Map(evidence.map((item) => [item.id, item.title]));
    const actionNames = new Map(actions.map((item) => [item.id, item.action_type]));

    const items: TimelineItem[] = memories
      .filter((memory) => {
        if (!assetIdFilter && !findingIdFilter) return true;

        const memoryFindingId = stringValue(memory.data.finding_id) ?? memory.subject_id;
        const memoryAssetId = stringValue(memory.data.asset_id) ?? stringValue(memory.data.affected_asset_id);

        if (findingIdFilter && memoryFindingId === findingIdFilter) return true;
        if (assetIdFilter && memoryAssetId === assetIdFilter) return true;

        const finding = memoryFindingId ? findings.find((item) => item.id === memoryFindingId) : null;
        return Boolean(assetIdFilter && finding?.asset_id === assetIdFilter);
      })
      .slice(0, limit)
      .map((memory) => {
        const changeType = stringValue(memory.data.change_type);
        const previousState = stringValue(memory.data.previous_security_state) ?? stringValue(memory.data.previous_state);
        const currentState = stringValue(memory.data.current_security_state) ?? stringValue(memory.data.current_state);

        return {
          id: `timeline-${memory.id}`,
          memoryId: memory.id,
          type: memory.memory_type,
          title: memory.title,
          summary: memory.summary,
          state: memory.state,
          occurredAt: memory.occurred_at,
          subject: subjectFor(memory, { findings: findingNames, assets: assetNames, evidence: evidenceNames, actions: actionNames }),
          context: {
            findingId: stringValue(memory.data.finding_id),
            assetId: stringValue(memory.data.asset_id) ?? stringValue(memory.data.affected_asset_id),
            evidenceId: stringValue(memory.data.evidence_id),
            actionId: stringValue(memory.data.action_id),
            changeType,
            previousState,
            currentState,
          },
          historical: new Date(memory.occurred_at).getTime() < Date.now() - 24 * 60 * 60 * 1000,
        };
      });

    return NextResponse.json({
      timeline: items,
      summary: {
        total: items.length,
        findings: items.filter((item) => item.type === "finding_state").length,
        investigations: items.filter((item) => item.type === "investigation").length,
        decisions: items.filter((item) => item.type === "operator_decision").length,
        outcomes: items.filter((item) => item.type === "response_outcome").length,
        evidenceChanges: items.filter((item) => item.type === "evidence_change").length,
      },
      boundary:
        "Security History is a record of what SentinelX previously observed, investigated, decided, or recorded as an outcome. Historical memory provides context but does not prove that the same condition exists now. Current evidence and telemetry remain authoritative for present-state claims. Missing telemetry is never treated as resolution.",
    });
  } catch {
    return NextResponse.json({ error: "Security History could not be generated." }, { status: 500 });
  }
}
