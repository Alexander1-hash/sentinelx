import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

const allowedEvidenceTypes = [
  "asset_observation",
  "telemetry",
  "identity",
  "network",
  "application",
  "ai_system",
  "ai_agent",
  "relationship_observation",
] as const;

type EvidenceType = (typeof allowedEvidenceTypes)[number];

type ObservedRelationship = {
  sourceAssetId: string;
  targetAssetId: string;
  relationshipType: string;
  confidence?: number;
  reason?: string;
};

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

async function getContext() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) return { supabase, user: null, organizationId: null };

  const { data: profile } = await supabase
    .from("profiles")
    .select("organization_id")
    .eq("id", user.id)
    .maybeSingle();

  return {
    supabase,
    user,
    organizationId: profile?.organization_id ?? null,
  };
}

export async function GET() {
  try {
    const { supabase, user, organizationId } = await getContext();

    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    if (!organizationId) return NextResponse.json({ evidence: [] });

    const { data, error } = await supabase
      .from("security_evidence")
      .select("id,asset_id,evidence_type,source,title,summary,data,observed_at,created_at")
      .eq("organization_id", organizationId)
      .order("observed_at", { ascending: false })
      .limit(50);

    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    return NextResponse.json({ evidence: data ?? [] });
  } catch {
    return NextResponse.json({ error: "Unable to load security evidence." }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const { supabase, user, organizationId } = await getContext();

    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    if (!organizationId) {
      return NextResponse.json(
        { error: "Your account is not connected to an organization yet." },
        { status: 409 }
      );
    }

    const body = await request.json();
    const evidenceType = body.evidenceType as EvidenceType;
    const source = typeof body.source === "string" ? body.source.trim() : "";
    const title = typeof body.title === "string" ? body.title.trim() : "";
    const summary = typeof body.summary === "string" ? body.summary.trim() : null;
    const assetId = typeof body.assetId === "string" ? body.assetId : null;
    const data = body.data && typeof body.data === "object" ? body.data : {};
    const observedRelationships = Array.isArray(body.observedRelationships)
      ? body.observedRelationships
      : [];

    if (!allowedEvidenceTypes.includes(evidenceType)) {
      return NextResponse.json({ error: "Invalid evidence type." }, { status: 400 });
    }

    if (!source || !title) {
      return NextResponse.json({ error: "Evidence source and title are required." }, { status: 400 });
    }

    if (assetId) {
      const { data: asset } = await supabase
        .from("security_assets")
        .select("id")
        .eq("id", assetId)
        .eq("organization_id", organizationId)
        .maybeSingle();

      if (!asset) {
        return NextResponse.json({ error: "Asset not found in your organization." }, { status: 403 });
      }
    }

    const { data: evidence, error: evidenceError } = await supabase
      .from("security_evidence")
      .insert({
        organization_id: organizationId,
        asset_id: assetId,
        evidence_type: evidenceType,
        source,
        title,
        summary,
        data,
      })
      .select("id,asset_id,evidence_type,source,title,summary,data,observed_at,created_at")
      .single();

    if (evidenceError) {
      return NextResponse.json({ error: evidenceError.message }, { status: 500 });
    }

    const validRelationships: ObservedRelationship[] = observedRelationships
      .filter((item: unknown): item is Record<string, unknown> => Boolean(item) && typeof item === "object")
      .map((item: Record<string, unknown>) => ({
        sourceAssetId: typeof item.sourceAssetId === "string" ? item.sourceAssetId : "",
        targetAssetId: typeof item.targetAssetId === "string" ? item.targetAssetId : "",
        relationshipType: typeof item.relationshipType === "string" ? item.relationshipType : "",
        confidence: typeof item.confidence === "number" ? item.confidence : 0.5,
        reason: typeof item.reason === "string" ? item.reason : "Observed relationship supplied by an authorized evidence source.",
      }))
      .filter((item) =>
        item.sourceAssetId &&
        item.targetAssetId &&
        item.sourceAssetId !== item.targetAssetId &&
        relationshipTypes.includes(item.relationshipType as (typeof relationshipTypes)[number]) &&
        item.confidence >= 0 &&
        item.confidence <= 1
      );

    let discoveredCount = 0;

    if (validRelationships.length) {
      const assetIds = [...new Set(validRelationships.flatMap((item) => [item.sourceAssetId, item.targetAssetId]))];

      const { data: assets } = await supabase
        .from("security_assets")
        .select("id")
        .eq("organization_id", organizationId)
        .in("id", assetIds);

      const validAssetIds = new Set((assets ?? []).map((asset) => asset.id));

      for (const relationship of validRelationships) {
        if (!validAssetIds.has(relationship.sourceAssetId) || !validAssetIds.has(relationship.targetAssetId)) continue;

        const { error } = await supabase
          .from("security_asset_relationships")
          .upsert({
            organization_id: organizationId,
            source_asset_id: relationship.sourceAssetId,
            target_asset_id: relationship.targetAssetId,
            relationship_type: relationship.relationshipType,
            confidence: relationship.confidence,
            status: "proposed",
            evidence_source: source,
            discovered_at: new Date().toISOString(),
            evidence: {
              source: "evidence_ingestion",
              evidence_id: evidence.id,
              reason: relationship.reason,
            },
          }, {
            onConflict: "source_asset_id,target_asset_id,relationship_type",
            ignoreDuplicates: false,
          });

        if (!error) discoveredCount += 1;
      }
    }

    return NextResponse.json({
      evidence,
      discoveredRelationships: discoveredCount,
      message: discoveredCount
        ? "Evidence recorded and relationship candidates created for review."
        : "Evidence recorded. No relationship candidates were supplied by this evidence source.",
    }, { status: 201 });
  } catch {
    return NextResponse.json({ error: "Invalid evidence request." }, { status: 400 });
  }
}
