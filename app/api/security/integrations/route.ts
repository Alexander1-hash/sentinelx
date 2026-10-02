import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

const allowedStatuses = ["planned", "pending", "connected", "paused", "error"] as const;

async function createIngestionToken() {
  const token = `sx_ing_${crypto.randomUUID().replaceAll("-", "")}${crypto.randomUUID().replaceAll("-", "")}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const hash = Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  return { token, hash, prefix: token.slice(0, 16) };
}

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
    if (!organizationId) return NextResponse.json({ integrations: [] });

    const { data, error } = await supabase
      .from("security_integrations")
      .select("id,provider,integration_type,display_name,status,scopes,configuration,last_sync_at,created_at")
      .eq("organization_id", organizationId)
      .order("created_at", { ascending: false });

    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    const integrations = (data ?? []).map((integration) => {
      const configuration =
        integration.configuration &&
        typeof integration.configuration === "object" &&
        !Array.isArray(integration.configuration)
          ? integration.configuration as Record<string, unknown>
          : {};

      const { authorization: _authorization, ...safeConfiguration } =
        configuration;

      return {
        ...integration,
        configuration: safeConfiguration,
        connection_state:
          typeof configuration.connection_state === "string"
            ? configuration.connection_state
            : "unknown",
      };
    });

    return NextResponse.json({ integrations });
  } catch {
    return NextResponse.json({ error: "Unable to load security integrations." }, { status: 500 });
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

    if (body.action === "configure_execution") {
      const integrationId = typeof body.integrationId === "string" ? body.integrationId.trim() : "";
      const webhookUrl = typeof body.executionWebhookUrl === "string" ? body.executionWebhookUrl.trim() : "";

      if (!integrationId || !webhookUrl) {
        return NextResponse.json(
          { error: "Integration ID and execution webhook URL are required." },
          { status: 400 },
        );
      }

      let parsedUrl: URL;
      try {
        parsedUrl = new URL(webhookUrl);
      } catch {
        return NextResponse.json({ error: "Execution webhook URL is invalid." }, { status: 400 });
      }

      if (parsedUrl.protocol !== "https:") {
        return NextResponse.json({ error: "Execution webhooks must use HTTPS." }, { status: 400 });
      }

      const { data: integration, error: lookupError } = await supabase
        .from("security_integrations")
        .select("id,configuration")
        .eq("id", integrationId)
        .eq("organization_id", organizationId)
        .maybeSingle();

      if (lookupError) return NextResponse.json({ error: lookupError.message }, { status: 500 });
      if (!integration) return NextResponse.json({ error: "Integration not found." }, { status: 404 });

      const current = integration.configuration && typeof integration.configuration === "object" && !Array.isArray(integration.configuration)
        ? integration.configuration as Record<string, unknown>
        : {};

      const execution = current.execution && typeof current.execution === "object" && !Array.isArray(current.execution)
        ? current.execution as Record<string, unknown>
        : {};

      const { error: updateError } = await supabase
        .from("security_integrations")
        .update({
          configuration: {
            ...current,
            execution: {
              ...execution,
              webhook_url: webhookUrl,
              executor_type: "provider_webhook",
              configured_at: new Date().toISOString(),
            },
          },
        })
        .eq("id", integrationId)
        .eq("organization_id", organizationId);

      if (updateError) return NextResponse.json({ error: updateError.message }, { status: 500 });

      return NextResponse.json({
        message: "Provider execution webhook configured.",
        integrationId,
        executorType: "provider_webhook",
        boundary: "The webhook URL is only a routing configuration. Execution still requires a connected permitted integration, explicit operator authorization, target validation, and the deployment execution secret/host allowlist.",
      });
    }

    if (body.action === "rotate_token") {
      const integrationId = typeof body.integrationId === "string" ? body.integrationId : "";

      if (!integrationId) {
        return NextResponse.json({ error: "Integration ID is required." }, { status: 400 });
      }

      const { data: integration } = await supabase
        .from("security_integrations")
        .select("id")
        .eq("id", integrationId)
        .eq("organization_id", organizationId)
        .maybeSingle();

      if (!integration) {
        return NextResponse.json({ error: "Integration not found." }, { status: 404 });
      }

      const generated = await createIngestionToken();

      const { error } = await supabase
        .from("security_integrations")
        .update({
          ingestion_token_hash: generated.hash,
          ingestion_token_prefix: generated.prefix,
          ingestion_token_created_at: new Date().toISOString(),
          ingestion_token_last_used_at: null,
          status: "pending",
        })
        .eq("id", integrationId)
        .eq("organization_id", organizationId);

      if (error) return NextResponse.json({ error: error.message }, { status: 500 });

      return NextResponse.json({
        token: generated.token,
        message: "New ingestion token created. Store it securely; Trinorin will not show it again.",
      });
    }

    const provider = typeof body.provider === "string" ? body.provider.trim() : "";
    const integrationType = typeof body.integrationType === "string" ? body.integrationType.trim() : "";
    const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
    const scopes = Array.isArray(body.scopes)
      ? body.scopes.filter((scope: unknown): scope is string => typeof scope === "string").slice(0, 50)
      : [];

    if (!provider || !integrationType || !displayName) {
      return NextResponse.json(
        { error: "Provider, integration type, and display name are required." },
        { status: 400 }
      );
    }

    const { data: existing } = await supabase
      .from("security_integrations")
      .select("id")
      .eq("organization_id", organizationId)
      .eq("provider", provider)
      .eq("integration_type", integrationType)
      .maybeSingle();

    if (existing) {
      return NextResponse.json(
        { error: "This integration is already registered for your organization." },
        { status: 409 }
      );
    }

    const generated = await createIngestionToken();
    const isEndpoint = integrationType === "endpoint";

    let endpointAssetId: string | null = null;

    if (isEndpoint) {
      const { data: endpointAsset, error: endpointAssetError } = await supabase
        .from("security_assets")
        .insert({
          organization_id: organizationId,
          name: displayName,
          asset_type: "endpoint",
          provider: "Trinorin Endpoint",
          environment: "production",
          criticality: "medium",
          status: "active",
          metadata: {
            onboarding: {
              state: "enrollment_pending",
              next_step: "Install or connect the authorized Trinorin endpoint component.",
              telemetry: "Endpoint enrollment pending",
            },
            endpoint: {
              enrollment_state: "pending",
              platform: "unknown",
              device_id: null,
              os_version: null,
              agent_version: null,
              posture: "unknown",
              connection_state: "offline",
              enrolled_at: null,
              last_heartbeat_at: null,
            },
          },
        })
        .select("id")
        .single();

      if (endpointAssetError) {
        return NextResponse.json({ error: endpointAssetError.message }, { status: 500 });
      }

      endpointAssetId = endpointAsset.id;
    }

    const { data, error } = await supabase
      .from("security_integrations")
      .insert({
        organization_id: organizationId,
        provider,
        integration_type: integrationType,
        display_name: displayName,
        status: "planned",
        scopes,
        configuration: {
          connection_state: isEndpoint ? "enrollment_pending" : "not_connected",
          credential_storage: "hash_only",
          ...(endpointAssetId
            ? {
                endpoint_asset_id: endpointAssetId,
                endpoint: {
                  enrollment_state: "pending",
                  asset_id: endpointAssetId,
                },
              }
            : {}),
        },
        ingestion_token_hash: generated.hash,
        ingestion_token_prefix: generated.prefix,
        ingestion_token_created_at: new Date().toISOString(),
      })
      .select("id,provider,integration_type,display_name,status,scopes,last_sync_at,created_at")
      .single();

    if (error) {
      if (endpointAssetId) {
        await supabase
          .from("security_assets")
          .delete()
          .eq("id", endpointAssetId)
          .eq("organization_id", organizationId);
      }
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    return NextResponse.json({
      integration: data,
      token: generated.token,
      message: "Integration registered. A one-time ingestion token was created. Store it securely; Trinorin will not show it again.",
    }, { status: 201 });
  } catch {
    return NextResponse.json({ error: "Invalid integration request." }, { status: 400 });
  }
}
