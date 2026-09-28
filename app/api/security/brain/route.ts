import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { buildSecurityBrain } from "@/lib/security-brain";

async function context() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return { supabase, organizationId: null, authorized: false };
  const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
  return { supabase, organizationId: profile?.organization_id ?? null, authorized: true };
}

export async function GET() {
  try {
    const { supabase, organizationId, authorized } = await context();
    if (!authorized) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    if (!organizationId) return NextResponse.json({ error: "No organization connected." }, { status: 400 });

    const [findings, evidence, assets, relationships, aiSystems, aiAgents] = await Promise.all([
      supabase.from("security_findings").select("id,asset_id,title,finding_type,severity,status,summary,evidence,remediation,detected_at").eq("organization_id", organizationId).order("detected_at", { ascending: false }).limit(500),
      supabase.from("security_evidence").select("id,asset_id,evidence_type,source,title,summary,data,observed_at").eq("organization_id", organizationId).order("observed_at", { ascending: false }).limit(500),
      supabase.from("security_assets").select("id,name,asset_type,criticality,environment,status").eq("organization_id", organizationId).limit(500),
      supabase.from("security_asset_relationships").select("id,source_asset_id,target_asset_id,relationship_type,confidence,status,evidence_source").eq("organization_id", organizationId).limit(1000),
      supabase.from("ai_security_systems").select("id,asset_id,name,provider,model,system_type,environment,data_classification,status,capabilities,permissions,metadata").eq("organization_id", organizationId).limit(500),
      supabase.from("ai_security_agents").select("id,system_id,name,purpose,autonomy_level,tools,permissions,data_access,status").eq("organization_id", organizationId).limit(500),
    ]);

    const error = findings.error ?? evidence.error ?? assets.error ?? relationships.error ?? aiSystems.error ?? aiAgents.error;
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    const brain = buildSecurityBrain({
      findings: findings.data ?? [],
      evidence: evidence.data ?? [],
      assets: assets.data ?? [],
      relationships: relationships.data ?? [],
      aiSystems: aiSystems.data ?? [],
      aiAgents: aiAgents.data ?? [],
    });

    return NextResponse.json({
      ...brain,
      summary: {
        findings: brain.findings.length,
        evidence: brain.evidence.length,
        assets: brain.assets.length,
        confirmedRelationships: brain.relationships.filter((item) => String(item.status).toLowerCase() === "confirmed").length,
        aiSystems: brain.aiSystems.length,
        aiAgents: brain.aiAgents.length,
        highImpactSignals: brain.signals.filter((item) => item.severity === "critical" || item.severity === "high").length,
      },
    });
  } catch {
    return NextResponse.json({ error: "Unable to load Security Brain." }, { status: 500 });
  }
}
