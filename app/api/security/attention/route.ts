import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { buildAdaptiveInvestigationContext } from "@/lib/security/adaptive-context";

type AttentionItem = {
  id: string;
  kind: "finding" | "event" | "action";
  priority: "high" | "medium";
  title: string;
  detail: string;
  observedAt: string;
  href: string;
  adaptiveContext?: {
    confidence: "strong" | "moderate" | "limited";
    evidenceFreshnessMinutes: number | null;
    contradictions: string[];
    latestVerification: { state: string; occurredAt: string } | null;
    nextEvidenceNeeded: string[];
  } | null;
};

export async function GET() {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
    const organizationId = profile?.organization_id;
    if (!organizationId) return NextResponse.json({ items: [], summary: { high: 0, medium: 0 } });

    const [findingsResult, eventsResult, actionsResult, evidenceResult, contextEventsResult, relationshipResult, assetResult, memoryResult] = await Promise.all([
      supabase.from("security_findings")
        .select("id,title,finding_type,severity,status,summary,asset_id,detected_at")
        .eq("organization_id", organizationId)
        .in("status", ["open", "acknowledged"])
        .in("severity", ["high", "critical"])
        .order("detected_at", { ascending: false })
        .limit(10),
      supabase.from("security_events")
        .select("id,title,severity,description,observed_at")
        .eq("organization_id", organizationId)
        .in("severity", ["high", "critical"])
        .order("observed_at", { ascending: false })
        .limit(10),
      supabase.from("security_actions")
        .select("id,finding_id,action_type,status,created_at")
        .eq("organization_id", organizationId)
        .eq("status", "pending")
        .order("created_at", { ascending: false })
        .limit(10),
      supabase.from("security_evidence")
        .select("id,asset_id,evidence_type,source,title,summary,observed_at")
        .eq("organization_id", organizationId)
        .order("observed_at", { ascending: false })
        .limit(500),
      supabase.from("security_events")
        .select("id,asset_id,severity,observed_at")
        .eq("organization_id", organizationId)
        .order("observed_at", { ascending: false })
        .limit(500),
      supabase.from("security_asset_relationships")
        .select("source_asset_id,target_asset_id,relationship_type,confidence,status")
        .eq("organization_id", organizationId)
        .limit(500),
      supabase.from("security_assets")
        .select("id,name,asset_type,criticality,status")
        .eq("organization_id", organizationId)
        .limit(500),
      supabase.from("security_memory")
        .select("id,memory_type,subject_id,title,summary,state,data,occurred_at")
        .eq("organization_id", organizationId)
        .order("occurred_at", { ascending: false })
        .limit(500),
    ]);

    const error = findingsResult.error ?? eventsResult.error ?? actionsResult.error ?? evidenceResult.error ?? contextEventsResult.error ?? relationshipResult.error ?? assetResult.error ?? memoryResult.error;
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    const adaptiveContextByFinding = new Map<string, ReturnType<typeof buildAdaptiveInvestigationContext>>();
    for (const finding of findingsResult.data ?? []) {
      adaptiveContextByFinding.set(
        finding.id,
        buildAdaptiveInvestigationContext({
          finding,
          evidence: evidenceResult.data ?? [],
          events: contextEventsResult.data ?? [],
          relationships: relationshipResult.data ?? [],
          assets: assetResult.data ?? [],
          memories: memoryResult.data ?? [],
        }),
      );
    }

    const items: AttentionItem[] = [
      ...(findingsResult.data ?? []).map((item) => ({
        id: item.id,
        kind: "finding" as const,
        priority: "high" as const,
        title: item.title,
        detail: adaptiveContextByFinding.get(item.id)?.contradictions[0]
          ?? adaptiveContextByFinding.get(item.id)?.nextEvidenceNeeded[0]
          ?? item.summary
          ?? "Open high-impact security finding requires review.",
        observedAt: item.detected_at,
        href: `/analyst?findingId=${encodeURIComponent(item.id)}`,
        adaptiveContext: (() => {
          const context = adaptiveContextByFinding.get(item.id);
          return context
            ? {
                confidence: context.confidence,
                evidenceFreshnessMinutes: context.currentState.evidenceFreshnessMinutes,
                contradictions: context.contradictions,
                latestVerification: context.historicalState.latestVerification,
                nextEvidenceNeeded: context.nextEvidenceNeeded.slice(0, 2),
              }
            : null;
        })(),
      })),
      ...(eventsResult.data ?? []).map((item) => ({
        id: item.id,
        kind: "event" as const,
        priority: "high" as const,
        title: item.title,
        detail: item.description ?? "High-impact telemetry event observed.",
        observedAt: item.observed_at,
        href: "/analyst",
      })),
      ...(actionsResult.data ?? []).map((item) => ({
        id: item.id,
        kind: "action" as const,
        priority: "medium" as const,
        title: "Operator review required",
        detail: `${item.action_type.replaceAll("_", " ")} is waiting for an explicit decision.`,
        observedAt: item.created_at,
        href: item.finding_id
          ? `/actions?findingId=${encodeURIComponent(item.finding_id)}`
          : "/actions",
      })),
    ]
      .sort((a, b) => new Date(b.observedAt).getTime() - new Date(a.observedAt).getTime())
      .slice(0, 12);

    return NextResponse.json({
      items,
      summary: {
        high: items.filter((item) => item.priority === "high").length,
        medium: items.filter((item) => item.priority === "medium").length,
      },
      boundary: "Attention items are derived from recorded findings, telemetry, and pending operator actions. They are not proof of compromise.",
    });
  } catch {
    return NextResponse.json({ error: "Security attention data could not be loaded." }, { status: 500 });
  }
}
