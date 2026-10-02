import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  decryptIntegrationSecret,
  encryptIntegrationSecret,
} from "@/lib/security/integration-secrets";

type Provider = "x" | "discord" | "slack";

function providerConfig(provider: Provider) {
  const map = {
    x: {
      clientId: process.env.X_CLIENT_ID,
      clientSecret: process.env.X_CLIENT_SECRET,
      tokenUrl: "https://api.x.com/2/oauth2/token",
    },
    discord: {
      clientId: process.env.DISCORD_CLIENT_ID,
      clientSecret: process.env.DISCORD_CLIENT_SECRET,
      tokenUrl: "https://discord.com/api/oauth2/token",
    },
    slack: {
      clientId: process.env.SLACK_CLIENT_ID,
      clientSecret: process.env.SLACK_CLIENT_SECRET,
      tokenUrl: "https://slack.com/api/oauth.v2.access",
    },
  } as const;

  return map[provider];
}

async function readJson(response: Response) {
  return response.json().catch(() => ({})) as Promise<Record<string, unknown>>;
}

export async function POST(request: Request) {
  try {
    const supabase = await createClient();
    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { data: profile } = await supabase
      .from("profiles")
      .select("organization_id")
      .eq("id", user.id)
      .maybeSingle();

    const organizationId = profile?.organization_id ?? null;

    if (!organizationId) {
      return NextResponse.json(
        { error: "Your account is not connected to an organization." },
        { status: 409 },
      );
    }

    const body = await request.json().catch(() => ({}));
    const integrationId =
      typeof body.integrationId === "string"
        ? body.integrationId.trim()
        : "";

    if (!integrationId) {
      return NextResponse.json(
        { error: "Integration ID is required." },
        { status: 400 },
      );
    }

    const { data: integration } = await supabase
      .from("security_integrations")
      .select("id,provider,configuration")
      .eq("id", integrationId)
      .eq("organization_id", organizationId)
      .maybeSingle();

    if (!integration) {
      return NextResponse.json(
        { error: "Integration not found." },
        { status: 404 },
      );
    }

    const provider = integration.provider as Provider;

    if (!["x", "discord", "slack"].includes(provider)) {
      return NextResponse.json(
        {
          error:
            "This provider does not use the Trinorin refresh-token flow. Reauthorization or provider-specific token renewal is required.",
        },
        { status: 409 },
      );
    }

    const oauth = providerConfig(provider);

    if (!oauth.clientId || !oauth.clientSecret) {
      return NextResponse.json(
        { error: `${provider} OAuth is not configured on this deployment.` },
        { status: 503 },
      );
    }

    const admin = createAdminClient();
    const { data: secret, error: secretLookupError } = await admin
      .from("security_integration_secrets")
      .select(
        "access_token_encrypted,refresh_token_encrypted,token_type,scopes,expires_at",
      )
      .eq("integration_id", integrationId)
      .eq("organization_id", organizationId)
      .maybeSingle();

    if (secretLookupError) {
      return NextResponse.json(
        { error: "Unable to access the provider credential record." },
        { status: 500 },
      );
    }

    if (!secret?.refresh_token_encrypted) {
      return NextResponse.json(
        {
          error:
            "No refresh token is stored for this integration. Reconnect the provider to establish renewable credentials.",
        },
        { status: 409 },
      );
    }

    const refreshToken = await decryptIntegrationSecret(
      secret.refresh_token_encrypted,
    );

    if (!refreshToken) {
      return NextResponse.json(
        { error: "The stored refresh credential could not be decrypted." },
        { status: 500 },
      );
    }

    const form = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    });

    if (provider === "x" || provider === "slack") {
      form.set("client_id", oauth.clientId);
      form.set("client_secret", oauth.clientSecret);
    }

    const headers: HeadersInit = {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    };

    if (provider === "discord") {
      headers.authorization =
        "Basic " +
        btoa(
          `${oauth.clientId}:${oauth.clientSecret}`,
        );
    }

    const response = await fetch(oauth.tokenUrl, {
      method: "POST",
      headers,
      body: form,
      cache: "no-store",
    });

    const tokenBody = await readJson(response);

    if (!response.ok) {
      return NextResponse.json(
        {
          error:
            "The provider rejected the refresh request. Reauthorization may be required.",
        },
        { status: 502 },
      );
    }

    if (provider === "slack" && tokenBody.ok === false) {
      return NextResponse.json(
        {
          error:
            typeof tokenBody.error === "string"
              ? `Slack rejected the refresh request: ${tokenBody.error}`
              : "Slack rejected the refresh request.",
        },
        { status: 502 },
      );
    }

    const accessToken =
      typeof tokenBody.access_token === "string"
        ? tokenBody.access_token
        : "";

    if (!accessToken) {
      return NextResponse.json(
        { error: "The provider did not return a refreshed access token." },
        { status: 502 },
      );
    }

    const nextRefreshToken =
      typeof tokenBody.refresh_token === "string"
        ? tokenBody.refresh_token
        : refreshToken;

    const expiresIn =
      typeof tokenBody.expires_in === "number"
        ? tokenBody.expires_in
        : null;

    const now = new Date().toISOString();
    const expiresAt = expiresIn
      ? new Date(Date.now() + expiresIn * 1000).toISOString()
      : null;

    const encryptedAccessToken =
      await encryptIntegrationSecret(accessToken);
    const encryptedRefreshToken =
      await encryptIntegrationSecret(nextRefreshToken);

    const scopes =
      typeof tokenBody.scope === "string"
        ? tokenBody.scope.split(/\s+/).filter(Boolean)
        : Array.isArray(secret.scopes)
          ? secret.scopes
          : [];

    const tokenType =
      typeof tokenBody.token_type === "string"
        ? tokenBody.token_type
        : secret.token_type ?? "Bearer";

    const { error: updateSecretError } = await admin
      .from("security_integration_secrets")
      .update({
        access_token_encrypted: encryptedAccessToken,
        refresh_token_encrypted: encryptedRefreshToken,
        token_type: tokenType,
        scopes,
        expires_at: expiresAt,
        updated_at: now,
      })
      .eq("integration_id", integrationId)
      .eq("organization_id", organizationId);

    if (updateSecretError) {
      return NextResponse.json(
        {
          error:
            "The provider token was refreshed but Trinorin could not persist the new credential securely.",
        },
        { status: 500 },
      );
    }

    const configuration =
      integration.configuration &&
      typeof integration.configuration === "object" &&
      !Array.isArray(integration.configuration)
        ? (integration.configuration as Record<string, unknown>)
        : {};

    const authorization =
      configuration.authorization &&
      typeof configuration.authorization === "object" &&
      !Array.isArray(configuration.authorization)
        ? (configuration.authorization as Record<string, unknown>)
        : {};

    const { error: updateIntegrationError } = await supabase
      .from("security_integrations")
      .update({
        status: "connected",
        configuration: {
          ...configuration,
          connection_state: "verified",
          authorization: {
            ...authorization,
            refreshed_at: now,
            expires_at: expiresAt,
            validation_state: "verified",
            verified: true,
          },
        },
      })
      .eq("id", integrationId)
      .eq("organization_id", organizationId);

    if (updateIntegrationError) {
      return NextResponse.json(
        {
          error:
            "The provider credential was refreshed, but Trinorin could not update the integration state.",
        },
        { status: 500 },
      );
    }

    return NextResponse.json({
      refreshed: true,
      provider,
      expiresAt,
      message: "Provider credentials refreshed and stored securely.",
    });
  } catch {
    return NextResponse.json(
      { error: "Unable to refresh the provider credential." },
      { status: 500 },
    );
  }
}
