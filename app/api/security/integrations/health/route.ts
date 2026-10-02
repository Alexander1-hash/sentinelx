import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { createAdminClient } from "@/lib/supabase/admin";

type HealthStage = "registered" | "authorized" | "asset_verified" | "webhook_subscribed" | "ingestion_active";

function deriveStage(integration: Record<string, unknown>): HealthStage {
  const configuration = integration.configuration && typeof integration.configuration === "object" && !Array.isArray(integration.configuration)
    ? integration.configuration as Record<string, unknown> : {};
  const state = typeof configuration.connection_state === "string" ? configuration.connection_state : "";
  if (state === "ingestion_active") return "ingestion_active";
  if (state === "webhook_subscribed") return "webhook_subscribed";
  if (state === "asset_verified") return "asset_verified";
  if (state === "authorized") return "authorized";
  return "registered";
}

export async function GET(request: Request) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
    if (!profile?.organization_id) return NextResponse.json({ health: [] });

    const integrationId = new URL(request.url).searchParams.get("integrationId")?.trim() ?? "";
    let query = supabase.from("security_integrations")
      .select("id,provider,integration_type,display_name,status,configuration,last_sync_at,created_at")
      .eq("organization_id", profile.organization_id);
    if (integrationId) query = query.eq("id", integrationId);

    const { data: integrations, error } = await query.order("created_at", { ascending: false });
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    const admin = createAdminClient();
    const ids = (integrations ?? []).map((item) => item.id);
    const { data: secrets } = ids.length
      ? await admin.from("security_integration_secrets").select("integration_id,expires_at,authorized_at,updated_at").eq("organization_id", profile.organization_id).in("integration_id", ids)
      : { data: [] as Array<{ integration_id: string; expires_at: string | null; authorized_at: string; updated_at: string }> };

    const secretById = new Map((secrets ?? []).map((secret) => [secret.integration_id, secret]));
    const health = (integrations ?? []).map((integration) => {
      const stage = deriveStage(integration as Record<string, unknown>);
      const secret = secretById.get(integration.id);
      const authorized = Boolean(secret);
      const expired = Boolean(secret?.expires_at && new Date(secret.expires_at).getTime() <= Date.now());
      const hasTelemetry = Boolean(integration.last_sync_at);
      const configuration = integration.configuration && typeof integration.configuration === "object" && !Array.isArray(integration.configuration)
        ? integration.configuration as Record<string, unknown> : {};
      const authorization = configuration.authorization && typeof configuration.authorization === "object" && !Array.isArray(configuration.authorization)
        ? configuration.authorization as Record<string, unknown> : {};
      const asset = authorization.asset_selection && typeof authorization.asset_selection === "object" && !Array.isArray(authorization.asset_selection)
        ? authorization.asset_selection as Record<string, unknown> : {};
      const webhook = authorization.webhook_subscription && typeof authorization.webhook_subscription === "object" && !Array.isArray(authorization.webhook_subscription)
        ? authorization.webhook_subscription as Record<string, unknown> : {};
      const assetVerified = asset.verified === true;
      const webhookSubscribed = webhook.subscribed === true;
      return {
        integrationId: integration.id,
        displayName: integration.display_name,
        provider: integration.provider,
        status: integration.status,
        stage,
        checks: {
          registered: true,
          authorized,
          credentialExpired: expired,
          assetVerified,
          webhookSubscribed,
          firstEventReceived: hasTelemetry,
          analysisReady: hasTelemetry,
        },
        lastTelemetryAt: integration.last_sync_at,
        nextAction: expired ? "Reauthorize the provider credential."
          : !authorized && ["x", "meta", "whatsapp", "discord", "slack"].includes(integration.integration_type) ? "Authorize the provider."
          : !assetVerified && ["meta", "whatsapp"].includes(integration.integration_type) ? "Select and verify the intended provider asset."
          : !webhookSubscribed && integration.integration_type === "whatsapp" ? "Subscribe the verified WhatsApp Business Account webhook."
          : !hasTelemetry ? "Send or wait for the first signed provider event."
          : "Integration is receiving telemetry; Trinorin can analyze the evidence.",
      };
    });

    return NextResponse.json({ health });
  } catch {
    return NextResponse.json({ error: "Unable to evaluate integration health." }, { status: 500 });
  }
}
