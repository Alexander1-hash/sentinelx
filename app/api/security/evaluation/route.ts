import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { buildAdaptiveInvestigationContext } from "@/lib/security/adaptive-context";
import { evaluateIntelligence, summarizeIntelligenceEvaluation } from "@/lib/security/evaluation";

export async function GET() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });

  const { data: profile } = await supabase
    .from("profiles")
    .select("organization_id")
    .eq("id", user.id)
    .single();

  if (!profile?.organization_id) return NextResponse.json({ error: "Organization required." }, { status: 403 });

  const organizationId = profile.organization_id;

  const [findingsResult, evidenceResult, eventsResult, relationshipsResult, assetsResult, memoryResult] =
    await Promise.all([
      supabase.from("security_findings")
        .select("id,asset_id,finding_type,severity,status,summary,detected_at")
        .eq("organization_id", organizationId)
        .order("detected_at", { ascending: false })
        .limit(100),
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

  const error = findingsResult.error ?? evidenceResult.error ?? eventsResult.error ??
    relationshipsResult.error ?? assetsResult.error ?? memoryResult.error;

  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  const contexts: Record<string, ReturnType<typeof buildAdaptiveInvestigationContext>> = {};
  for (const finding of findingsResult.data ?? []) {
    contexts[finding.id] = buildAdaptiveInvestigationContext({
      finding: {
        ...finding,
        finding_type: finding.finding_type ?? "unknown",
        summary: finding.summary ?? null,
      },
      evidence: (evidenceResult.data ?? []).map((item) => ({
        ...item,
        source: item.source ?? "unknown",
        title: item.title ?? "Security evidence",
      })),
      events: eventsResult.data ?? [],
      relationships: relationshipsResult.data ?? [],
      assets: assetsResult.data ?? [],
      memories: memoryResult.data ?? [],
    });
  }

  const results = evaluateIntelligence(findingsResult.data ?? [], contexts);

  return NextResponse.json({
    results,
    summary: summarizeIntelligenceEvaluation(results),
    boundary: "Evaluation measures the quality of recorded intelligence context; it does not establish ground truth or authorize actions.",
  });
}
