import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET() {
  const startedAt = Date.now();
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ status: "unauthorized" }, { status: 401 });
    const { data: profile, error } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
    if (error) return NextResponse.json({ status: "degraded", checks: { database: "error" } }, { status: 500 });
    if (!profile?.organization_id) return NextResponse.json({ status: "ready", checks: { auth: "ok", organization: "not_configured", database: "ok" }, latencyMs: Date.now() - startedAt });
    const { error: dataError } = await supabase.from("security_assets").select("id", { count: "exact", head: true }).eq("organization_id", profile.organization_id);
    if (dataError) return NextResponse.json({ status: "degraded", checks: { auth: "ok", organization: "ok", database: "error" } }, { status: 500 });
    return NextResponse.json({ status: "healthy", checks: { auth: "ok", organization: "ok", database: "ok", securityData: "reachable" }, latencyMs: Date.now() - startedAt, boundary: "Reachability only; not proof of security." });
  } catch {
    return NextResponse.json({ status: "degraded", checks: { service: "error" } }, { status: 500 });
  }
}
