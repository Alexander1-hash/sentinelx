import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
  if (!profile?.organization_id) return NextResponse.json({ configured: false, coverage: [] });
  const org = profile.organization_id;
  const [systems, agents, events, assets] = await Promise.all([
    supabase.from("ai_security_systems").select("id", { count: "exact", head: true }).eq("organization_id", org),
    supabase.from("ai_security_agents").select("id", { count: "exact", head: true }).eq("organization_id", org),
    supabase.from("ai_security_events").select("id", { count: "exact", head: true }).eq("organization_id", org),
    supabase.from("security_assets").select("id,asset_type", { count: "exact" }).eq("organization_id", org).in("asset_type", ["AI system", "AI agent"]),
  ]);
  const error = systems.error ?? agents.error ?? events.error ?? assets.error;
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({
    configured: true,
    coverage: [
      { surface: "AI systems", registered: systems.count ?? 0, telemetry: events.count ?? 0 },
      { surface: "AI agents", registered: agents.count ?? 0, telemetry: events.count ?? 0 },
      { surface: "AI graph assets", registered: assets.count ?? 0, telemetry: events.count ?? 0 },
    ],
    boundary: "Coverage counts represent recorded inventory and telemetry, not complete visibility."
  });
}
