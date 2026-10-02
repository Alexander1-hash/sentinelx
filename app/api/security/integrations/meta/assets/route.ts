import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { decryptIntegrationSecret } from "@/lib/security/integration-secrets";

type Provider = "meta" | "whatsapp";

async function readJson(response: Response) {
  return response.json().catch(() => ({})) as Promise<Record<string, unknown>>;
}

async function graphGet(
  path: string,
  accessToken: string,
  fields?: string,
) {
  const url = new URL(`https://graph.facebook.com/v24.0/${path.replace(/^\//, "")}`);
  url.searchParams.set("access_token", accessToken);
  if (fields) url.searchParams.set("fields", fields);

  const response = await fetch(url, { cache: "no-store" });
  const body = await readJson(response);

  if (!response.ok || body.error) {
    const error =
      body.error && typeof body.error === "object" && !Array.isArray(body.error)
        ? body.error as Record<string, unknown>
        : {};
    throw new Error(
      typeof error.message === "string"
        ? error.message
        : "Meta Graph API request failed.",
    );
  }

  return body;
}

function asRows(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  const data = (value as Record<string, unknown>).data;
  return Array.isArray(data)
    ? data.filter((row): row is Record<string, unknown> =>
        Boolean(row && typeof row === "object" && !Array.isArray(row)),
      )
    : [];
}

export async function GET(request: Request) {
  try {
    const url = new URL(request.url);
    const integrationId = url.searchParams.get("integrationId")?.trim() ?? "";
    const provider = url.searchParams.get("provider")?.trim() as Provider;

    if (!integrationId || !["meta", "whatsapp"].includes(provider)) {
      return NextResponse.json(
        { error: "A Meta or WhatsApp integrationId and provider are required." },
        { status: 400 },
      );
    }

    const supabase = await createClient();
    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const { data: profile } = await supabase
      .from("profiles")
      .select("organization_id")
      .eq("id", user.id)
      .maybeSingle();

    if (!profile?.organization_id) {
      return NextResponse.json(
        { error: "No organization is attached to this account." },
        { status: 409 },
      );
    }

    const { data: integration } = await supabase
      .from("security_integrations")
      .select("id,provider,integration_type,configuration")
      .eq("id", integrationId)
      .eq("organization_id", profile.organization_id)
      .maybeSingle();

    if (
      !integration ||
      integration.integration_type !== provider ||
      (provider === "meta" && integration.provider !== "Meta") ||
      (provider === "whatsapp" && integration.provider !== "WhatsApp Business")
    ) {
      return NextResponse.json({ error: "Integration not found." }, { status: 404 });
    }

    const admin = createAdminClient();
    const { data: secret } = await admin
      .from("security_integration_secrets")
      .select("access_token_encrypted,expires_at,scopes")
      .eq("integration_id", integrationId)
      .eq("organization_id", profile.organization_id)
      .maybeSingle();

    if (!secret?.access_token_encrypted) {
      return NextResponse.json(
        { error: "No authorized Meta credential is stored for this integration." },
        { status: 409 },
      );
    }

    if (secret.expires_at && new Date(secret.expires_at).getTime() <= Date.now()) {
      return NextResponse.json(
        { error: "The Meta access token has expired. Reauthorize the integration." },
        { status: 409 },
      );
    }

    const accessToken = await decryptIntegrationSecret(secret.access_token_encrypted);
    if (!accessToken) {
      return NextResponse.json(
        { error: "The stored Meta credential could not be decrypted." },
        { status: 500 },
      );
    }

    const businessResponse = await graphGet("me/businesses", accessToken, "id,name");
    const businessRows = asRows(businessResponse);

    if (provider === "meta") {
      return NextResponse.json({
        provider,
        integrationId,
        businesses: businessRows.map((business) => ({
          id: business.id ?? null,
          name: business.name ?? null,
        })),
        selectionRequired: true,
        boundary:
          "Meta token validity does not by itself select a Page, Instagram business account, or other business asset. Trinorin will not claim telemetry until an asset is explicitly selected and validated.",
      });
    }

    const wabaRows: Record<string, unknown>[] = [];
    for (const business of businessRows) {
      if (typeof business.id !== "string") continue;
      const response = await graphGet(
        `${business.id}/owned_whatsapp_business_accounts`,
        accessToken,
        "id,name",
      );
      for (const waba of asRows(response)) {
        wabaRows.push({
          ...waba,
          business_id: business.id,
          business_name: business.name ?? null,
        });
      }
    }

    const wabas = [];
    for (const waba of wabaRows) {
      if (typeof waba.id !== "string") continue;
      const phoneResponse = await graphGet(
        `${waba.id}/phone_numbers`,
        accessToken,
        "id,display_phone_number,verified_name,quality_rating,code_verification_status",
      );
      wabas.push({
        id: waba.id,
        name: waba.name ?? null,
        business_id: waba.business_id,
        business_name: waba.business_name,
        phoneNumbers: asRows(phoneResponse).map((phone) => ({
          id: phone.id ?? null,
          display_phone_number: phone.display_phone_number ?? null,
          verified_name: phone.verified_name ?? null,
          quality_rating: phone.quality_rating ?? null,
          code_verification_status: phone.code_verification_status ?? null,
        })),
      });
    }

    return NextResponse.json({
      provider,
      integrationId,
      businesses: businessRows.map((business) => ({
        id: business.id ?? null,
        name: business.name ?? null,
      })),
      whatsappBusinessAccounts: wabas,
      selectionRequired: true,
      boundary:
        "WhatsApp Business Account and phone-number discovery is separate from OAuth token validation. Trinorin will not mark WhatsApp telemetry ready until an authorized WABA and phone number are explicitly selected and validated.",
    });
  } catch (error) {
    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : "Unable to discover Meta business assets.",
      },
      { status: 502 },
    );
  }
}
