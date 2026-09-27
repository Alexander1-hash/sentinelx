import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET() {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
    if (!profile?.organization_id) return NextResponse.json({ configured: false, posture: "not_configured" });
    const org = profile.organization_id;
    const [assets, findings, integrations, events, aiSystems, aiAgents, actions] = await Promise.all([
      supabase.from("security_assets").select("id", { count: "exact", head: true }).eq("organization_id", org),
      supabase.from("security_findings").select("id,severity,status").eq("organization_id", org),
      supabase.from("security_integrations").select("id,status").eq("organization_id", org),
      supabase.from("security_events").select("id", { count: "exact", head: true }).eq("organization_id", org),
      supabase.from("ai_security_systems").select("id", { count: "exact", head: true }).eq("organization_id", org),
      supabase.from("ai_security_agents").select("id", { count: "exact", head: true }).eq("organization_id", org),
      supabase.from("security_actions").select("id,status").eq("organization_id", org),
    ]);
    const error = assets.error ?? findings.error ?? integrations.error ?? events.error ?? aiSystems.error ?? aiAgents.error ?? actions.error;
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });
    const rows = findings.data ?? [];
    const open = rows.filter(f => ["open","acknowledged"].includes(f.status)).length;
    const high = rows.filter(f => ["high","critical"].includes(f.severity) && ["open","acknowledged"].includes(f.status)).length;
    return NextResponse.json({
      configured: true,
      posture: high > 0 ? "attention_required" : open > 0 ? "monitor" : "no_recorded_open_findings",
      metrics: { assets: assets.count ?? 0, findings: rows.length, openFindings: open, highImpactOpenFindings: high, events: events.count ?? 0, aiSystems: aiSystems.count ?? 0, aiAgents: aiAgents.count ?? 0, connectedIntegrations: (integrations.data ?? []).filter(i => i.status === "connected").length, pendingActions: (actions.data ?? []).filter(a => a.status === "pending").length },
      boundary: "Deterministic summary of recorded SentinelX data; not a guarantee of security."
    });
  } catch { return NextResponse.json({ error: "Security posture could not be calculated." }, { status: 500 }); }
}
