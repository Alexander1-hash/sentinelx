import { NextResponse } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";

const postureStates = ["healthy", "degraded", "at_risk", "unknown"] as const;

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
      return NextResponse.json({ error: "Valid endpoint authorization is required." }, { status: 401 });
    }

    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return NextResponse.json({ error: "A JSON object is required." }, { status: 400 });
    }

    const payload = body as Record<string, unknown>;
    const deviceId = typeof payload.deviceId === "string" ? payload.deviceId.trim() : "";
    const posture = typeof payload.posture === "string" ? payload.posture.trim().toLowerCase() : "unknown";
    const osVersion = typeof payload.osVersion === "string" ? payload.osVersion.trim() : "";
    const agentVersion = typeof payload.agentVersion === "string" ? payload.agentVersion.trim() : "";

    if (!deviceId || deviceId.length > 300) {
      return NextResponse.json({ error: "A stable deviceId is required." }, { status: 400 });
    }

    if (!postureStates.includes(posture as (typeof postureStates)[number])) {
      return NextResponse.json({ error: "Invalid endpoint posture." }, { status: 400 });
    }

    if (osVersion.length > 200 || agentVersion.length > 100) {
      return NextResponse.json({ error: "Endpoint version metadata is too long." }, { status: 400 });
    }

    const supabase = createAdminClient();
    const tokenHash = await hashToken(token);
    const { data: verified, error: verifyError } = await supabase.rpc(
      "verify_security_ingestion_token",
      { p_token_hash: tokenHash }
    );

    if (verifyError) {
      return NextResponse.json({ error: "Endpoint authentication is not configured." }, { status: 503 });
    }

    const integration = verified?.[0];
    if (!integration) {
      return NextResponse.json({ error: "Invalid or expired endpoint token." }, { status: 401 });
    }

    if (integration.integration_type !== "endpoint") {
      return NextResponse.json({ error: "This credential is not bound to an endpoint integration." }, { status: 403 });
    }

    const { data: integrationRecord } = await supabase
      .from("security_integrations")
      .select("id,organization_id,configuration")
      .eq("id", integration.integration_id)
      .eq("organization_id", integration.organization_id)
      .maybeSingle();

    if (!integrationRecord) {
      return NextResponse.json({ error: "Endpoint integration could not be resolved." }, { status: 404 });
    }

    const configuration =
      integrationRecord.configuration &&
      typeof integrationRecord.configuration === "object" &&
      !Array.isArray(integrationRecord.configuration)
        ? integrationRecord.configuration as Record<string, unknown>
        : {};

    const endpointAssetId =
      typeof configuration.endpoint_asset_id === "string"
        ? configuration.endpoint_asset_id
        : "";

    if (!endpointAssetId) {
      return NextResponse.json({ error: "Endpoint integration has no bound security asset." }, { status: 409 });
    }

    const { data: asset, error: assetError } = await supabase
      .from("security_assets")
      .select("id,metadata")
      .eq("id", endpointAssetId)
      .eq("organization_id", integration.organization_id)
      .maybeSingle();

    if (assetError || !asset) {
      return NextResponse.json({ error: "Bound endpoint asset could not be found." }, { status: 404 });
    }

    const metadata =
      asset.metadata &&
      typeof asset.metadata === "object" &&
      !Array.isArray(asset.metadata)
        ? asset.metadata as Record<string, unknown>
        : {};

    const endpoint =
      metadata.endpoint &&
      typeof metadata.endpoint === "object" &&
      !Array.isArray(metadata.endpoint)
        ? metadata.endpoint as Record<string, unknown>
        : {};

    const enrolledDeviceId = typeof endpoint.device_id === "string" ? endpoint.device_id : "";
    if (!enrolledDeviceId || enrolledDeviceId !== deviceId || endpoint.enrollment_state !== "verified") {
      return NextResponse.json({ error: "Endpoint identity is not verified for this device." }, { status: 403 });
    }

    const now = new Date().toISOString();
    const nextMetadata = {
      ...metadata,
      onboarding: {
        ...(metadata.onboarding && typeof metadata.onboarding === "object" && !Array.isArray(metadata.onboarding)
          ? metadata.onboarding as Record<string, unknown>
          : {}),
        state: "enrolled",
        next_step: "Continue sending authorized endpoint telemetry to Trinorin.",
        telemetry: "Endpoint heartbeat received",
      },
      endpoint: {
        ...endpoint,
        os_version: osVersion || endpoint.os_version || null,
        agent_version: agentVersion || endpoint.agent_version || null,
        posture,
        connection_state: "online",
        last_heartbeat_at: now,
      },
    };

    const { data: updatedAsset, error: updateError } = await supabase
      .from("security_assets")
      .update({ metadata: nextMetadata, last_seen_at: now, status: "active" })
      .eq("id", endpointAssetId)
      .eq("organization_id", integration.organization_id)
      .select("id,name,asset_type,status,metadata,last_seen_at")
      .single();

    if (updateError) {
      return NextResponse.json({ error: updateError.message }, { status: 500 });
    }

    await supabase
      .from("security_integrations")
      .update({
        status: "connected",
        last_sync_at: now,
        ingestion_token_last_used_at: now,
      })
      .eq("id", integration.integration_id)
      .eq("organization_id", integration.organization_id);

    return NextResponse.json({
      acknowledged: true,
      heartbeatAt: now,
      endpoint: updatedAsset,
      message: "Endpoint heartbeat accepted and device posture updated.",
    });
  } catch {
    return NextResponse.json({ error: "Invalid endpoint heartbeat request." }, { status: 400 });
  }
}
