import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET() {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
    if (!profile?.organization_id) return NextResponse.json({ incidentSignals: [] });
    const org = profile.organization_id;
    const [findings, events, actions] = await Promise.all([
      supabase.from("security_findings").select("id,title,severity,status,summary,asset_id,detected_at").eq("organization_id", org).in("status", ["open","acknowledged"]).order("detected_at", { ascending: false }).limit(100),
      supabase.from("security_events").select("id,title,severity,source,asset_id,observed_at").eq("organization_id", org).in("severity", ["high","critical"]).order("observed_at", { ascending: false }).limit(100),
      supabase.from("security_actions").select("id,action_type,status,finding_id,created_at").eq("organization_id", org).in("status", ["pending","approved"]).order("created_at", { ascending: false }).limit(100),
    ]);
    const error = findings.error ?? events.error ?? actions.error;
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });
    const signals = (findings.data ?? []).map(f => ({ id: "finding:" + f.id, kind: "finding", severity: f.severity, title: f.title, summary: f.summary, assetId: f.asset_id, observedAt: f.detected_at, relatedActionCount: (actions.data ?? []).filter(a => a.finding_id === f.id).length }));
    for (const event of events.data ?? []) signals.push({ id: "event:" + event.id, kind: "event", severity: event.severity, title: event.title, summary: "High-impact event recorded by " + event.source + ".", assetId: event.asset_id, observedAt: event.observed_at, relatedActionCount: 0 });
    signals.sort((a,b) => new Date(b.observedAt).getTime() - new Date(a.observedAt).getTime());
    return NextResponse.json({ incidentSignals: signals.slice(0, 100), pendingResponseActions: (actions.data ?? []).length, boundary: "Incident signals summarize recorded high-impact conditions; they do not confirm an incident." });
  } catch { return NextResponse.json({ error: "Incident summary failed." }, { status: 500 }); }
}
