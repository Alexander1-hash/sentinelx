import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { synthesizeSecurityIntelligence } from "@/lib/security/intelligence";
import { buildAdaptiveInvestigationContext } from "@/lib/security/adaptive-context";

export async function GET() {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const { data: profile } = await supabase
      .from("profiles")
      .select("organization_id")
      .eq("id", user.id)
      .maybeSingle();

    if (!profile?.organization_id) {
      return NextResponse.json({
        summary: {
          protectedAssets: 0, activeFindings: 0, evidenceRecords: 0,
          securityEvents: 0, confirmedRelationships: 0, memoryRecords: 0,
          intelligenceCoverage: 0,
        },
        priorities: [],
        coverageGaps: ["No organization is connected."],
        lifecycle: { observe: 0, detect: 0, investigate: 0, decide: 0, respond: 0, verify: 0, learn: 0 },
        recentMemory: [],
        boundary: "No organization-scoped inference was made.",
      });
    }

    const org = profile.organization_id;
    const [findings, evidence, events, relationships, memories, assets] = await Promise.all([
      supabase.from("security_findings")
        .select("id,asset_id,title,finding_type,severity,status,summary,detected_at")
        .eq("organization_id", org).order("detected_at", { ascending: false }).limit(500),
      supabase.from("security_evidence")
        .select("id,asset_id,evidence_type,source,title,summary,observed_at")
        .eq("organization_id", org).order("observed_at", { ascending: false }).limit(1000),
      supabase.from("security_events")
        .select("id,asset_id,severity,observed_at")
        .eq("organization_id", org).order("observed_at", { ascending: false }).limit(1000),
      supabase.from("security_asset_relationships")
        .select("source_asset_id,target_asset_id,confidence,status")
        .eq("organization_id", org).limit(1500),
      supabase.from("security_memory")
        .select("id,memory_type,subject_id,title,summary,occurred_at,state,data")
        .eq("organization_id", org).order("occurred_at", { ascending: false }).limit(1000),
      supabase.from("security_assets")
        .select("id,name,asset_type,criticality,status")
        .eq("organization_id", org).limit(1000),
    ]);

    const error = findings.error ?? evidence.error ?? events.error ?? relationships.error ?? memories.error ?? assets.error;
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    const adaptiveContexts: Record<string, ReturnType<typeof buildAdaptiveInvestigationContext>> = {};
    for (const finding of findings.data ?? []) {
      adaptiveContexts[finding.id] = buildAdaptiveInvestigationContext({
        finding: {
          ...finding,
          finding_type: finding.finding_type ?? "unknown",
          summary: finding.summary ?? null,
        },
        evidence: (evidence.data ?? []).map((item) => ({
          ...item,
          source: item.source ?? "unknown",
          title: item.title ?? "Security evidence",
        })),
        events: events.data ?? [],
        relationships: relationships.data ?? [],
        assets: assets.data ?? [],
        memories: memories.data ?? [],
      });
    }

    return NextResponse.json(synthesizeSecurityIntelligence({
      findings: findings.data ?? [],
      evidence: evidence.data ?? [],
      events: events.data ?? [],
      relationships: relationships.data ?? [],
      memories: memories.data ?? [],
      assets: assets.data ?? [],
      adaptiveContexts,
    }));
  } catch {
    return NextResponse.json({ error: "Security intelligence synthesis failed." }, { status: 500 });
  }
}
