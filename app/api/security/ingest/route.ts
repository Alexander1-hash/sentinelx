import { NextResponse } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";

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

const evidenceTypes = [
  "asset_observation",
  "telemetry",
  "identity",
  "network",
  "application",
  "ai_system",
  "ai_agent",
  "relationship_observation",
] as const;

async function hashToken(token: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function POST(request: Request) {
  try {
    const authorization = request.headers.get("authorization");
    const token = authorization?.startsWith("Bearer ")
      ? authorization.slice(7).trim()
      : "";

    if (!token.startsWith("sx_ing_")) {
      return NextResponse.json({ error: "Valid ingestion authorization is required." }, { status: 401 });
    }

    const supabase = createAdminClient();
    const tokenHash = await hashToken(token);

    const { data: verified, error: verifyError } = await supabase.rpc(
      "verify_security_ingestion_token",
      { p_token_hash: tokenHash }
    );

    if (verifyError) {
      return NextResponse.json({ error: "Ingestion authentication is not configured." }, { status: 503 });
    }

    const integration = verified?.[0];
    if (!integration) {
      return NextResponse.json({ error: "Invalid or expired ingestion token." }, { status: 401 });
    }

    const body = await request.json();
    const evidenceType = typeof body.evidenceType === "string" ? body.evidenceType : "";
    const source = typeof body.source === "string" ? body.source.trim() : "";
    const title = typeof body.title === "string" ? body.title.trim() : "";
    const summary = typeof body.summary === "string" ? body.summary.trim() : null;
    const assetId = typeof body.assetId === "string" ? body.assetId : null;
    const observedAt = typeof body.observedAt === "string" ? body.observedAt : null;
    const data = body.data && typeof body.data === "object" ? body.data : {};
    const relationships = Array.isArray(body.observedRelationships) ? body.observedRelationships : [];

    if (!evidenceTypes.includes(evidenceType as (typeof evidenceTypes)[number])) {
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
        .eq("organization_id", integration.organization_id)
        .maybeSingle();

      if (!asset) {
        return NextResponse.json({ error: "Asset is not registered in this organization." }, { status: 403 });
      }
    }

    const { data: evidence, error: evidenceError } = await supabase
      .from("security_evidence")
      .insert({
        organization_id: integration.organization_id,
        asset_id: assetId,
        evidence_type: evidenceType,
        source,
        title,
        summary,
        data,
        ...(observedAt ? { observed_at: observedAt } : {}),
      })
      .select("id,asset_id,evidence_type,source,title,summary,data,observed_at,created_at")
      .single();

    if (evidenceError) {
      return NextResponse.json({ error: evidenceError.message }, { status: 500 });
    }

    let discoveredRelationships = 0;

    for (const item of relationships) {
      if (!item || typeof item !== "object") continue;

      const relationship = item as Record<string, unknown>;
      const sourceAssetId = typeof relationship.sourceAssetId === "string" ? relationship.sourceAssetId : "";
      const targetAssetId = typeof relationship.targetAssetId === "string" ? relationship.targetAssetId : "";
      const relationshipType = typeof relationship.relationshipType === "string" ? relationship.relationshipType : "";
      const confidence = typeof relationship.confidence === "number" ? relationship.confidence : 0.5;
      const reason = typeof relationship.reason === "string"
        ? relationship.reason
        : "Observed relationship supplied by an authorized telemetry source.";

      if (
        !sourceAssetId ||
        !targetAssetId ||
        sourceAssetId === targetAssetId ||
        !relationshipTypes.includes(relationshipType as (typeof relationshipTypes)[number]) ||
        confidence < 0 ||
        confidence > 1
      ) continue;

      const { data: assets } = await supabase
        .from("security_assets")
        .select("id")
        .eq("organization_id", integration.organization_id)
        .in("id", [sourceAssetId, targetAssetId]);

      if ((assets ?? []).length !== 2) continue;

      const { error } = await supabase
        .from("security_asset_relationships")
        .upsert({
          organization_id: integration.organization_id,
          source_asset_id: sourceAssetId,
          target_asset_id: targetAssetId,
          relationship_type: relationshipType,
          confidence,
          status: "proposed",
          evidence_source: source,
          discovered_at: new Date().toISOString(),
          evidence: {
            source: "telemetry_ingestion",
            evidence_id: evidence.id,
            reason,
          },
        }, {
          onConflict: "source_asset_id,target_asset_id,relationship_type",
          ignoreDuplicates: false,
        });

      if (!error) discoveredRelationships += 1;
    }

    if (assetId) {
      await supabase
        .from("security_assets")
        .update({ last_seen_at: observedAt ?? new Date().toISOString() })
        .eq("id", assetId)
        .eq("organization_id", integration.organization_id);
    }

    await supabase
      .from("security_integrations")
      .update({
        status: "connected",
        last_sync_at: new Date().toISOString(),
        ingestion_token_last_used_at: new Date().toISOString(),
      })
      .eq("id", integration.integration_id)
      .eq("organization_id", integration.organization_id);

    return NextResponse.json({
      accepted: true,
      evidenceId: evidence.id,
      discoveredRelationships,
      message: "Telemetry accepted. Relationship candidates remain unconfirmed until reviewed.",
    }, { status: 201 });
  } catch {
    return NextResponse.json({ error: "Invalid ingestion request." }, { status: 400 });
  }
}
