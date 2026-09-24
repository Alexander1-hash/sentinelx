import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

const allowedTypes = [
  "website",
  "domain",
  "cloud",
  "identity",
  "endpoint",
  "email",
  "business_software",
  "database",
  "ai_system",
  "ai_agent",
  "api",
  "other",
] as const;

type AssetType = (typeof allowedTypes)[number];

export async function GET() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { data, error } = await supabase
    .from("security_assets")
    .select("id,name,asset_type,provider,environment,criticality,status,metadata,last_seen_at,created_at")
    .order("created_at", { ascending: false });

  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  return NextResponse.json({ assets: data ?? [] });
}

export async function POST(request: Request) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .select("organization_id")
      .eq("id", user.id)
      .maybeSingle();

    if (profileError) return NextResponse.json({ error: profileError.message }, { status: 500 });
    if (!profile?.organization_id) {
      return NextResponse.json({ error: "Your account is not connected to an organization yet." }, { status: 409 });
    }

    const body = await request.json();
    const name = typeof body.name === "string" ? body.name.trim() : "";
    const assetType = body.assetType as AssetType;
    const provider = typeof body.provider === "string" ? body.provider.trim() : null;
    const environment = typeof body.environment === "string" ? body.environment : "production";
    const criticality = typeof body.criticality === "string" ? body.criticality : "medium";

    if (!name) return NextResponse.json({ error: "Asset name is required." }, { status: 400 });
    if (!allowedTypes.includes(assetType)) return NextResponse.json({ error: "Invalid asset type." }, { status: 400 });
    if (!["development", "staging", "production"].includes(environment)) {
      return NextResponse.json({ error: "Invalid environment." }, { status: 400 });
    }
    if (!["low", "medium", "high", "critical"].includes(criticality)) {
      return NextResponse.json({ error: "Invalid criticality." }, { status: 400 });
    }

    const { data, error } = await supabase
      .from("security_assets")
      .insert({
        organization_id: profile.organization_id,
        name,
        asset_type: assetType,
        provider,
        environment,
        criticality,
        status: "active",
      })
      .select("id,name,asset_type,provider,environment,criticality,status,created_at")
      .single();

    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    return NextResponse.json({ asset: data }, { status: 201 });
  } catch {
    return NextResponse.json({ error: "Invalid request." }, { status: 400 });
  }
}
