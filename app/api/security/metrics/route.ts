import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
  if (!profile?.organization_id) return NextResponse.json({ metrics: {} });
  const org = profile.organization_id;
  const [events, evidence, findings, relationships, memory] = await Promise.all([
    supabase.from("security_events").select("id", { count: "exact", head: true }).eq("organization_id", org),
    supabase.from("security_evidence").select("id", { count: "exact", head: true }).eq("organization_id", org),
    supabase.from("security_findings").select("id", { count: "exact", head: true }).eq("organization_id", org),
    supabase.from("security_asset_relationships").select("id", { count: "exact", head: true }).eq("organization_id", org).eq("status", "confirmed"),
    supabase.from("security_memory").select("id", { count: "exact", head: true }).eq("organization_id", org),
  ]);
  const error = events.error ?? evidence.error ?? findings.error ?? relationships.error ?? memory.error;
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ metrics: { events: events.count ?? 0, evidence: evidence.count ?? 0, findings: findings.count ?? 0, confirmedRelationships: relationships.count ?? 0, memoryRecords: memory.count ?? 0 }, generatedAt: new Date().toISOString() });
}
