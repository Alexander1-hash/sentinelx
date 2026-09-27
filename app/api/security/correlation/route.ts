import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { normalizeSecurityEvent, severityRank } from "@/lib/security/normalize";

export async function GET() {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
    if (!profile?.organization_id) return NextResponse.json({ correlations: [] });
    const org = profile.organization_id;
    const [eventsResult, findingsResult, evidenceResult] = await Promise.all([
      supabase.from("security_events").select("id,event_type,severity,source,title,description,observed_at,asset_id").eq("organization_id", org).order("observed_at", { ascending: false }).limit(250),
      supabase.from("security_findings").select("id,asset_id,title,severity,status,detected_at").eq("organization_id", org).order("detected_at", { ascending: false }).limit(250),
      supabase.from("security_evidence").select("id,asset_id,evidence_type,source,title,summary,observed_at").eq("organization_id", org).order("observed_at", { ascending: false }).limit(250),
    ]);
    const error = eventsResult.error ?? findingsResult.error ?? evidenceResult.error;
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });
    const findings = findingsResult.data ?? [];
    const evidence = evidenceResult.data ?? [];
    const correlations: Record<string, unknown>[] = [];
    for (const event of (eventsResult.data ?? []).map(normalizeSecurityEvent)) {
      const candidates = findings.filter(f => f.asset_id && f.asset_id === event.assetId && ["high","critical"].includes(f.severity));
      const supporting = evidence.filter(e => e.asset_id && e.asset_id === event.assetId).slice(0, 5);
      if (!candidates.length || !supporting.length) continue;
      correlations.push({ eventTitle: event.title, eventSeverity: event.severity, eventSource: event.source, observedAt: event.observedAt, findingIds: candidates.map(f => f.id), evidenceIds: supporting.map(e => e.id), confidence: Math.min(0.99, 0.55 + severityRank(event.severity) * 0.08 + Math.min(0.15, supporting.length * 0.03)), boundary: "Correlation is not proof of causation or compromise." });
      if (correlations.length >= 50) break;
    }
    return NextResponse.json({ correlations, count: correlations.length, boundary: "Only recorded events, findings and evidence are correlated." });
  } catch { return NextResponse.json({ error: "Security correlation failed." }, { status: 500 }); }
}
