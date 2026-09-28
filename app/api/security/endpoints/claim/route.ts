import { NextResponse } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";

const platforms = ["windows", "macos", "linux", "android", "ios"] as const;

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
      return NextResponse.json({ error: "Valid endpoint enrollment authorization is required." }, { status: 401 });
    }

    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return NextResponse.json({ error: "A JSON object is required." }, { status: 400 });
    }

    const payload = body as Record<string, unknown>;
    const deviceId = typeof payload.deviceId === "string" ? payload.deviceId.trim() : "";
    const platform = typeof payload.platform === "string" ? payload.platform.trim().toLowerCase() : "";
    const osVersion = typeof payload.osVersion === "string" ? payload.osVersion.trim() : "";
    const agentVersion = typeof payload.agentVersion === "string" ? payload.agentVersion.trim() : "";

    if (!deviceId || deviceId.length > 300) {
      return NextResponse.json({ error: "A stable deviceId is required." }, { status: 400 });
    }

    if (!platforms.includes(platform as (typeof platforms)[number])) {
      return NextResponse.json({ error: "Unsupported endpoint platform." }, { status: 400 });
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
      return NextResponse.json({ error: "Endpoint enrollment authentication is not configured." }, { status: 503 });
    }

    const integration = verified?.[0];
    if (!integration) {
      return NextResponse.json({ error: "Invalid or expired endpoint enrollment token." }, { status: 401 });
    }

    if (integration.integration_type !== "endpoint") {
      return NextResponse.json({ error: "This credential is not bound to an endpoint integration." }, { status: 403 });
    }

    const { data: integrationRecord, error: integrationError } = await supabase
      .from("security_integrations")
      .select("id,organization_id,configuration,status")
      .eq("id", integration.integration_id)
      .eq("organization_id", integration.organization_id)
      .maybeSingle();

    if (integrationError || !integrationRecord) {
      return NextResponse.json({ error: "Endpoint integration could not be resolved." }, { status: 404 });
    }

    const configuration =
      integrationRecord.configuration &&
      typeof integrationRecord.configuration === "object" &&
      !Array.isArray(integrationRecord.configuration)
        ? integrationRecord.configuration as Record<string, unknown>
        : {};

    const endpointConfiguration =
      configuration.endpoint &&
      typeof configuration.endpoint === "object" &&
      !Array.isArray(configuration.endpoint)
        ? configuration.endpoint as Record<string, unknown>
        : {};

    const endpointAssetId =
      typeof configuration.endpoint_asset_id === "string"
        ? configuration.endpoint_asset_id
        : typeof endpointConfiguration.asset_id === "string"
          ? endpointConfiguration.asset_id
          : "";

    if (!endpointAssetId) {
      return NextResponse.json({ error: "Endpoint integration has no bound security asset." }, { status: 409 });
    }

    const { data: asset, error: assetError } = await supabase
      .from("security_assets")
      .select("id,name,metadata")
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

    const currentDeviceId = typeof endpoint.device_id === "string" ? endpoint.device_id : null;
    if (currentDeviceId && currentDeviceId !== deviceId) {
      return NextResponse.json(
        { error: "This endpoint enrollment is already claimed by another device identity." },
        { status: 409 }
      );
    }

    const now = new Date().toISOString();
    const nextMetadata = {
      ...metadata,
      onboarding: {
        ...(metadata.onboarding && typeof metadata.onboarding === "object" && !Array.isArray(metadata.onboarding)
          ? metadata.onboarding as Record<string, unknown>
          : {}),
        state: "telemetry_connected",
        next_step: "Continue sending authorized endpoint telemetry to Trinorin.",
        telemetry: "Endpoint identity claimed and telemetry channel ready",
      },
      endpoint: {
        ...endpoint,
        enrollment_state: "verified",
        platform,
        device_id: deviceId,
        os_version: osVersion || null,
        agent_version: agentVersion || null,
        posture: "unknown",
        connection_state: "online",
        enrolled_at: typeof endpoint.enrolled_at === "string" ? endpoint.enrolled_at : now,
        last_heartbeat_at: now,
      },
    };

    const { data: updatedAsset, error: updateAssetError } = await supabase
      .from("security_assets")
      .update({
        metadata: nextMetadata,
        last_seen_at: now,
        status: "active",
      })
      .eq("id", endpointAssetId)
      .eq("organization_id", integration.organization_id)
      .select("id,name,asset_type,provider,status,metadata,last_seen_at")
      .single();

    if (updateAssetError) {
      return NextResponse.json({ error: updateAssetError.message }, { status: 500 });
    }

    const nextConfiguration = {
      ...configuration,
      connection_state: "connected",
      endpoint_asset_id: endpointAssetId,
      endpoint: {
        ...endpointConfiguration,
        enrollment_state: "verified",
        asset_id: endpointAssetId,
        platform,
        device_id: deviceId,
      },
    };

    const { error: integrationUpdateError } = await supabase
      .from("security_integrations")
      .update({
        configuration: nextConfiguration,
        status: "connected",
        last_sync_at: now,
        ingestion_token_last_used_at: now,
      })
      .eq("id", integration.integration_id)
      .eq("organization_id", integration.organization_id);

    if (integrationUpdateError) {
      return NextResponse.json({ error: integrationUpdateError.message }, { status: 500 });
    }

    return NextResponse.json({
      enrolled: true,
      endpoint: updatedAsset,
      message: "Endpoint identity verified. Trinorin can now accept authorized telemetry for this device.",
    });
  } catch {
    return NextResponse.json({ error: "Invalid endpoint enrollment request." }, { status: 400 });
  }
}
