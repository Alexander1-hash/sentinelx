import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
  if (!profile?.organization_id) return NextResponse.json({ telemetry: [] });
  const org = profile.organization_id;
  const [integrations, events, evidence] = await Promise.all([
    supabase.from("security_integrations").select("id,provider,integration_type,status,last_sync_at").eq("organization_id", org),
    supabase.from("security_events").select("id,severity,source,observed_at").eq("organization_id", org).order("observed_at", { ascending: false }).limit(200),
    supabase.from("security_evidence").select("id,evidence_type,source,observed_at").eq("organization_id", org).order("observed_at", { ascending: false }).limit(200),
  ]);
  const error = integrations.error ?? events.error ?? evidence.error;
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ telemetry: { integrations: integrations.data ?? [], recentEvents: events.data ?? [], recentEvidence: evidence.data ?? [] }, boundary: "Telemetry inventory reflects only sources connected to SentinelX." });
}
