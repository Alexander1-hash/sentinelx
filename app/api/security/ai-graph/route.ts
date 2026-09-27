import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
  if (!profile?.organization_id) return NextResponse.json({ nodes: [], edges: [] });
  const org = profile.organization_id;
  const [systems, agents, assets, relationships] = await Promise.all([
    supabase.from("ai_security_systems").select("id,name,provider,status").eq("organization_id", org),
    supabase.from("ai_security_agents").select("id,name,system_id,status").eq("organization_id", org),
    supabase.from("security_assets").select("id,name,asset_type").eq("organization_id", org).in("asset_type", ["AI system","AI agent"]),
    supabase.from("security_asset_relationships").select("id,source_asset_id,target_asset_id,relationship_type,confidence,status").eq("organization_id", org).eq("status", "confirmed"),
  ]);
  const error = systems.error ?? agents.error ?? assets.error ?? relationships.error;
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ nodes: [...(systems.data ?? []), ...(agents.data ?? []), ...(assets.data ?? [])], edges: relationships.data ?? [], boundary: "Only confirmed graph relationships are returned; missing edges remain unknown." });
}
