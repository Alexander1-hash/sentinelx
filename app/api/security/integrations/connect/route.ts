import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { encryptIntegrationState } from "@/lib/security/integration-secrets";

const providers = {
  x: {
    clientId: () => process.env.X_CLIENT_ID,
    authorizeUrl: "https://twitter.com/i/oauth2/authorize",
    scopes: ["tweet.read", "users.read", "offline.access"],
    pkce: true,
  },
  meta: {
    clientId: () => process.env.META_CLIENT_ID,
    authorizeUrl: "https://www.facebook.com/v24.0/dialog/oauth",
    scopes: ["business_management"],
    pkce: false,
  },
  whatsapp: {
    clientId: () => process.env.META_CLIENT_ID,
    authorizeUrl: "https://www.facebook.com/v24.0/dialog/oauth",
    scopes: ["business_management", "whatsapp_business_management"],
    pkce: false,
  },
  discord: {
    clientId: () => process.env.DISCORD_CLIENT_ID,
    authorizeUrl: "https://discord.com/oauth2/authorize",
    scopes: ["identify", "guilds"],
    pkce: false,
  },
  slack: {
    clientId: () => process.env.SLACK_CLIENT_ID,
    authorizeUrl: "https://slack.com/oauth/v2/authorize",
    scopes: ["channels:read", "channels:history", "groups:read", "groups:history", "im:history", "mpim:history", "users:read"],
    pkce: false,
  },
} as const;

type Provider = keyof typeof providers;

function randomVerifier() {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function sha256Base64Url(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export async function GET(request: Request) {
  try {
    const url = new URL(request.url);
    const integrationId = url.searchParams.get("integrationId")?.trim() ?? "";
    const provider = url.searchParams.get("provider")?.trim() as Provider;

    if (!integrationId || !provider || !(provider in providers)) {
      return NextResponse.json({ error: "A supported integrationId and provider are required." }, { status: 400 });
    }

    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
    if (!profile?.organization_id) return NextResponse.json({ error: "No organization is attached to this account." }, { status: 409 });

    const { data: integration } = await supabase
      .from("security_integrations")
      .select("id,provider,integration_type,configuration")
      .eq("id", integrationId)
      .eq("organization_id", profile.organization_id)
      .maybeSingle();

    if (!integration) return NextResponse.json({ error: "Integration not found." }, { status: 404 });
    if (integration.integration_type !== provider) return NextResponse.json({ error: "Provider does not match the registered integration." }, { status: 409 });

    const definition = providers[provider];
    const clientId = definition.clientId();
    if (!clientId) {
      return NextResponse.json({ error: `${provider} OAuth is not configured on this deployment yet.` }, { status: 503 });
    }

    const redirectUri = `${url.origin}/api/security/integrations/callback`;
    const verifier = definition.pkce ? randomVerifier() : null;
    const state = await encryptIntegrationState({
      integrationId,
      organizationId: profile.organization_id,
      provider,
      userId: user.id,
      redirectUri,
      verifier,
      expiresAt: Date.now() + 10 * 60 * 1000,
    });

    const authorize = new URL(definition.authorizeUrl);
    authorize.searchParams.set("client_id", clientId);
    authorize.searchParams.set("redirect_uri", redirectUri);
    authorize.searchParams.set("response_type", "code");
    authorize.searchParams.set("state", state);
    authorize.searchParams.set("scope", definition.scopes.join(" "));
    if (provider === "x" && verifier) {
      authorize.searchParams.set("code_challenge", await sha256Base64Url(verifier));
      authorize.searchParams.set("code_challenge_method", "S256");
    }

    return NextResponse.json({
      authorizationUrl: authorize.toString(),
      provider,
      integrationId,
      boundary: "Authorization happens on the provider. Trinorin does not collect provider passwords.",
    });
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "Unable to start integration authorization." }, { status: 500 });
  }
}
