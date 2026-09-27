import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
  if (!profile?.organization_id) return NextResponse.json({ error: "Organization is required." }, { status: 409 });
  const org = profile.organization_id;
  const [assets, findings, evidence, memory, actions] = await Promise.all([
    supabase.from("security_assets").select("*").eq("organization_id", org),
    supabase.from("security_findings").select("*").eq("organization_id", org),
    supabase.from("security_evidence").select("*").eq("organization_id", org),
    supabase.from("security_memory").select("*").eq("organization_id", org),
    supabase.from("security_actions").select("*").eq("organization_id", org),
  ]);
  const error = assets.error ?? findings.error ?? evidence.error ?? memory.error ?? actions.error;
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return new NextResponse(JSON.stringify({ schemaVersion: "sentinelx-security-export-v1", exportedAt: new Date().toISOString(), organizationId: org, assets: assets.data ?? [], findings: findings.data ?? [], evidence: evidence.data ?? [], memory: memory.data ?? [], actions: actions.data ?? [], boundary: "Exported records are evidence/history, not proof of current state." }, null, 2), { headers: { "Content-Type": "application/json", "Content-Disposition": "attachment; filename=sentinelx-security-export.json" } });
}
