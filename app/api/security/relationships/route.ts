import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

const relationshipTypes = [
  "hosts",
  "resolves_to",
  "depends_on",
  "authenticates_to",
  "connects_to",
  "uses",
  "reads_from",
  "writes_to",
  "calls",
  "protects",
  "managed_by",
  "part_of",
] as const;

export async function GET() {
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
    if (!profile?.organization_id) return NextResponse.json({ relationships: [] });

    const { data: relationships, error } = await supabase
      .from("security_asset_relationships")
      .select("id,source_asset_id,target_asset_id,relationship_type,confidence,evidence,created_at")
      .eq("organization_id", profile.organization_id)
      .order("created_at", { ascending: false });

    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    return NextResponse.json({ relationships: relationships ?? [] });
  } catch {
    return NextResponse.json({ error: "Unable to load security relationships." }, { status: 500 });
  }
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
    const sourceAssetId = typeof body.sourceAssetId === "string" ? body.sourceAssetId : "";
    const targetAssetId = typeof body.targetAssetId === "string" ? body.targetAssetId : "";
    const relationshipType = typeof body.relationshipType === "string" ? body.relationshipType : "";
    const confidence = typeof body.confidence === "number" ? body.confidence : null;
    const evidence = body.evidence && typeof body.evidence === "object" ? body.evidence : {};

    if (!sourceAssetId || !targetAssetId) {
      return NextResponse.json({ error: "Source and target assets are required." }, { status: 400 });
    }

    if (sourceAssetId === targetAssetId) {
      return NextResponse.json({ error: "An asset cannot relate to itself." }, { status: 400 });
    }

    if (!relationshipTypes.includes(relationshipType as (typeof relationshipTypes)[number])) {
      return NextResponse.json({ error: "Invalid relationship type." }, { status: 400 });
    }

    if (confidence !== null && (confidence < 0 || confidence > 1)) {
      return NextResponse.json({ error: "Confidence must be between 0 and 1." }, { status: 400 });
    }

    const { data: assets, error: assetsError } = await supabase
      .from("security_assets")
      .select("id")
      .eq("organization_id", profile.organization_id)
      .in("id", [sourceAssetId, targetAssetId]);

    if (assetsError) return NextResponse.json({ error: assetsError.message }, { status: 500 });

    if ((assets ?? []).length !== 2) {
      return NextResponse.json({ error: "Both assets must belong to your organization." }, { status: 403 });
    }

    const { data, error } = await supabase
      .from("security_asset_relationships")
      .upsert({
        organization_id: profile.organization_id,
        source_asset_id: sourceAssetId,
        target_asset_id: targetAssetId,
        relationship_type: relationshipType,
        confidence,
        evidence,
      }, {
        onConflict: "source_asset_id,target_asset_id,relationship_type",
      })
      .select("id,source_asset_id,target_asset_id,relationship_type,confidence,evidence,created_at")
      .single();

    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    return NextResponse.json({ relationship: data }, { status: 201 });
  } catch {
    return NextResponse.json({ error: "Invalid relationship request." }, { status: 400 });
  }
}
