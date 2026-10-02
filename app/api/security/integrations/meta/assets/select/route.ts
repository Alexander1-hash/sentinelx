import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { decryptIntegrationSecret } from "@/lib/security/integration-secrets";

type Provider = "meta" | "whatsapp";

async function readJson(response: Response) {
  return response.json().catch(() => ({})) as Promise<Record<string, unknown>>;
}

async function graphGet(path: string, token: string, fields?: string) {
  const url = new URL(`https://graph.facebook.com/v24.0/${path.replace(/^\//, "")}`);
  url.searchParams.set("access_token", token);
  if (fields) url.searchParams.set("fields", fields);
  const response = await fetch(url, { cache: "no-store" });
  const body = await readJson(response);
  if (!response.ok || body.error) throw new Error("Meta asset validation failed.");
  return body;
}

function rows(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  const data = (value as Record<string, unknown>).data;
  return Array.isArray(data) ? data.filter((x): x is Record<string, unknown> => Boolean(x && typeof x === "object" && !Array.isArray(x))) : [];
}

export async function POST(request: Request) {
  try {
    const body = await request.json() as Record<string, unknown>;
    const integrationId = typeof body.integrationId === "string" ? body.integrationId : "";
    const provider = body.provider as Provider;
    const businessId = typeof body.businessId === "string" ? body.businessId : null;
    const wabaId = typeof body.wabaId === "string" ? body.wabaId : null;
    const phoneNumberId = typeof body.phoneNumberId === "string" ? body.phoneNumberId : null;
    if (!integrationId || !["meta", "whatsapp"].includes(provider)) return NextResponse.json({ error: "Invalid integration selection." }, { status: 400 });
    if (provider === "whatsapp" && (!wabaId || !phoneNumberId)) return NextResponse.json({ error: "WhatsApp requires a WABA and phone number selection." }, { status: 400 });

    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
    if (!profile?.organization_id) return NextResponse.json({ error: "No organization is attached to this account." }, { status: 409 });

    const { data: integration } = await supabase.from("security_integrations").select("id,provider,integration_type,configuration").eq("id", integrationId).eq("organization_id", profile.organization_id).maybeSingle();
    if (!integration || integration.integration_type !== provider) return NextResponse.json({ error: "Integration not found." }, { status: 404 });

    const admin = createAdminClient();
    const { data: secret } = await admin.from("security_integration_secrets").select("access_token_encrypted").eq("integration_id", integrationId).eq("organization_id", profile.organization_id).maybeSingle();
    if (!secret?.access_token_encrypted) return NextResponse.json({ error: "No authorized provider credential is stored." }, { status: 409 });
    const token = await decryptIntegrationSecret(secret.access_token_encrypted);
    if (!token) return NextResponse.json({ error: "Stored provider credential could not be decrypted." }, { status: 500 });

    if (provider === "whatsapp") {
      const response = await graphGet(`${wabaId}/phone_numbers`, token, "id,display_phone_number,verified_name,quality_rating,code_verification_status");
      if (!rows(response).some(row => row.id === phoneNumberId)) return NextResponse.json({ error: "The selected phone number is not attached to the selected WABA." }, { status: 400 });
      const config = integration.configuration && typeof integration.configuration === "object" && !Array.isArray(integration.configuration) ? integration.configuration as Record<string, unknown> : {};
      const authorization = config.authorization && typeof config.authorization === "object" && !Array.isArray(config.authorization) ? config.authorization as Record<string, unknown> : {};
      const nextAuthorization = { ...authorization, asset_selection: { waba_id: wabaId, phone_number_id: phoneNumberId, selected_at: new Date().toISOString(), verified: true } };
      await supabase.from("security_integrations").update({ configuration: { ...config, connection_state: "asset_verified", authorization: nextAuthorization } }).eq("id", integrationId).eq("organization_id", profile.organization_id);
      return NextResponse.json({ verified: true, connectionState: "asset_verified", wabaId, phoneNumberId });
    }

    if (!businessId) return NextResponse.json({ error: "Meta business selection is required." }, { status: 400 });
    const businessResponse = await graphGet("me/businesses", token, "id,name");
    if (!rows(businessResponse).some(row => row.id === businessId)) return NextResponse.json({ error: "The selected business is not authorized for this Meta token." }, { status: 400 });
    const config = integration.configuration && typeof integration.configuration === "object" && !Array.isArray(integration.configuration) ? integration.configuration as Record<string, unknown> : {};
    const authorization = config.authorization && typeof config.authorization === "object" && !Array.isArray(config.authorization) ? config.authorization as Record<string, unknown> : {};
    await supabase.from("security_integrations").update({ configuration: { ...config, connection_state: "asset_verified", authorization: { ...authorization, asset_selection: { business_id: businessId, selected_at: new Date().toISOString(), verified: true } } } }).eq("id", integrationId).eq("organization_id", profile.organization_id);
    return NextResponse.json({ verified: true, connectionState: "asset_verified", businessId });
  } catch {
    return NextResponse.json({ error: "Unable to validate the selected Meta asset." }, { status: 502 });
  }
}
