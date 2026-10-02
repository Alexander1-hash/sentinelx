import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { decryptIntegrationSecret } from "@/lib/security/integration-secrets";

async function readJson(response: Response) {
  return response.json().catch(() => ({})) as Promise<Record<string, unknown>>;
}

export async function POST(request: Request) {
  try {
    const body = await request.json() as Record<string, unknown>;
    const integrationId = typeof body.integrationId === "string" ? body.integrationId.trim() : "";
    const wabaId = typeof body.wabaId === "string" ? body.wabaId.trim() : "";
    if (!integrationId || !wabaId) return NextResponse.json({ error: "Integration ID and WABA ID are required." }, { status: 400 });

    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
    if (!profile?.organization_id) return NextResponse.json({ error: "No organization is attached to this account." }, { status: 409 });

    const { data: integration } = await supabase.from("security_integrations").select("id,provider,integration_type,configuration").eq("id", integrationId).eq("organization_id", profile.organization_id).maybeSingle();
    if (!integration || integration.provider !== "WhatsApp Business" || integration.integration_type !== "whatsapp") return NextResponse.json({ error: "WhatsApp integration not found." }, { status: 404 });

    const config = integration.configuration && typeof integration.configuration === "object" && !Array.isArray(integration.configuration) ? integration.configuration as Record<string, unknown> : {};
    const authorization = config.authorization && typeof config.authorization === "object" && !Array.isArray(config.authorization) ? config.authorization as Record<string, unknown> : {};
    const selection = authorization.asset_selection && typeof authorization.asset_selection === "object" && !Array.isArray(authorization.asset_selection) ? authorization.asset_selection as Record<string, unknown> : {};
    if (selection.waba_id !== wabaId || selection.verified !== true) return NextResponse.json({ error: "Select and validate this WABA and its phone number before subscribing the webhook." }, { status: 409 });

    const admin = createAdminClient();
    const { data: secret } = await admin.from("security_integration_secrets").select("access_token_encrypted,expires_at").eq("integration_id", integrationId).eq("organization_id", profile.organization_id).maybeSingle();
    if (!secret?.access_token_encrypted) return NextResponse.json({ error: "No authorized WhatsApp credential is stored." }, { status: 409 });
    if (secret.expires_at && new Date(secret.expires_at).getTime() <= Date.now()) return NextResponse.json({ error: "The provider credential has expired. Reauthorize the integration." }, { status: 409 });
    const accessToken = await decryptIntegrationSecret(secret.access_token_encrypted);
    if (!accessToken) return NextResponse.json({ error: "The stored provider credential could not be decrypted." }, { status: 500 });

    const response = await fetch("https://graph.facebook.com/v24.0/" + encodeURIComponent(wabaId) + "/subscribed_apps", {
      method: "POST",
      headers: { Authorization: "Bearer " + accessToken },
      cache: "no-store",
    });
    const result = await readJson(response);
    if (!response.ok || result.error || result.success !== true) {
      const error = result.error && typeof result.error === "object" && !Array.isArray(result.error) ? result.error as Record<string, unknown> : {};
      return NextResponse.json({ error: typeof error.message === "string" ? error.message : "Meta did not confirm the WhatsApp webhook subscription." }, { status: 502 });
    }

    const webhookUrl = new URL(request.url).origin + "/api/security/webhooks/whatsapp";
    const nextAuthorization = { ...authorization, webhook_subscription: { waba_id: wabaId, subscribed: true, subscribed_at: new Date().toISOString(), callback_url: webhookUrl, verification: "Meta subscription confirmed; delivery still requires a valid webhook verification token and app signature." } };
    const { error: updateError } = await supabase.from("security_integrations").update({ configuration: { ...config, connection_state: "webhook_subscribed", authorization: nextAuthorization } }).eq("id", integrationId).eq("organization_id", profile.organization_id);
    if (updateError) return NextResponse.json({ error: updateError.message }, { status: 500 });

    return NextResponse.json({ subscribed: true, connectionState: "webhook_subscribed", wabaId, webhookUrl, boundary: "Subscription confirmation proves Meta accepted the WABA subscription. It does not prove that a webhook event has been delivered or analyzed yet." });
  } catch {
    return NextResponse.json({ error: "Unable to subscribe the WhatsApp webhook." }, { status: 400 });
  }
}
