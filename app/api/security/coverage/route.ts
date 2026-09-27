import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
  if (!profile?.organization_id) return NextResponse.json({ configured: false, surfaces: [] });
  const org = profile.organization_id;
  const types = ["Website","Domain","Cloud","Identity","Business software","Database","AI system","AI agent"];
  const { data, error } = await supabase.from("security_assets").select("asset_type,status,last_seen_at").eq("organization_id", org);
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  const rows = data ?? [];
  const surfaces = types.map(type => {
    const assets = rows.filter(a => a.asset_type === type);
    return { surface: type, registered: assets.length, telemetryConnected: assets.filter(a => a.last_seen_at).length, awaitingTelemetry: assets.filter(a => !a.last_seen_at).length };
  });
  return NextResponse.json({ configured: true, surfaces, boundary: "Coverage measures registered assets and observed telemetry timestamps only." });
}
