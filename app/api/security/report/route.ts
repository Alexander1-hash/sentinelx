import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET() {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
    if (!profile?.organization_id) return NextResponse.json({ error: "Organization is required." }, { status: 409 });
    const org = profile.organization_id;
    const [assets, findings, integrations, actions, memory] = await Promise.all([
      supabase.from("security_assets").select("id,name,asset_type,environment,criticality,status,last_seen_at").eq("organization_id", org).order("name"),
      supabase.from("security_findings").select("id,title,finding_type,severity,status,detected_at,resolved_at").eq("organization_id", org).order("detected_at", { ascending: false }).limit(500),
      supabase.from("security_integrations").select("id,provider,integration_type,display_name,status,last_sync_at").eq("organization_id", org).order("display_name"),
      supabase.from("security_actions").select("id,action_type,status,created_at,executed_at").eq("organization_id", org).order("created_at", { ascending: false }).limit(500),
      supabase.from("security_memory").select("id,memory_type,title,summary,occurred_at").eq("organization_id", org).order("occurred_at", { ascending: false }).limit(500),
    ]);
    const error = assets.error ?? findings.error ?? integrations.error ?? actions.error ?? memory.error;
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });
    return NextResponse.json({ generatedAt: new Date().toISOString(), organizationId: org, assets: assets.data ?? [], findings: findings.data ?? [], integrations: integrations.data ?? [], actions: actions.data ?? [], recentMemory: memory.data ?? [], boundary: "Recorded SentinelX data at generation time; not a security certification." });
  } catch { return NextResponse.json({ error: "Security report failed." }, { status: 500 }); }
}
