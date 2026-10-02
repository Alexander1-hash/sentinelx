import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  decryptIntegrationState,
  encryptIntegrationSecret,
} from "@/lib/security/integration-secrets";

type OAuthState = {
  integrationId: string;
  organizationId: string;
  provider: "x" | "meta" | "whatsapp" | "discord" | "slack";
  userId: string;
  redirectUri: string;
  verifier: string | null;
  expiresAt: number;
};

type ValidationResult = {
  verified: boolean;
  state: "verified" | "token_valid";
  identity: Record<string, unknown>;
};

function config(provider: OAuthState["provider"]) {
  const map = {
    x: {
      clientId: process.env.X_CLIENT_ID,
      clientSecret: process.env.X_CLIENT_SECRET,
      tokenUrl: "https://api.x.com/2/oauth2/token",
    },
    meta: {
      clientId: process.env.META_CLIENT_ID,
      clientSecret: process.env.META_CLIENT_SECRET,
      tokenUrl: "https://graph.facebook.com/v24.0/oauth/access_token",
    },
    whatsapp: {
      clientId: process.env.META_CLIENT_ID,
      clientSecret: process.env.META_CLIENT_SECRET,
      tokenUrl: "https://graph.facebook.com/v24.0/oauth/access_token",
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

function errorRedirect(origin: string, message: string) {
  return NextResponse.redirect(
    new URL(
      `/integrations?connection_error=${encodeURIComponent(message)}`,
      origin,
    ),
  );
}

async function readJson(response: Response) {
  return response.json().catch(() => ({})) as Promise<Record<string, unknown>>;
}

async function validateProviderToken(
  provider: OAuthState["provider"],
  accessToken: string,
  clientId: string,
  clientSecret: string,
): Promise<ValidationResult | null> {
  if (provider === "x") {
    const response = await fetch("https://api.x.com/2/users/me", {
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/json",
      },
      cache: "no-store",
    });

    if (!response.ok) return null;

    const body = await readJson(response);
    const data =
      body.data &&
      typeof body.data === "object" &&
      !Array.isArray(body.data)
        ? (body.data as Record<string, unknown>)
        : null;

    if (!data?.id) return null;

    return {
      verified: true,
      state: "verified",
      identity: {
        id: data.id,
        username: data.username ?? null,
        name: data.name ?? null,
      },
    };
  }

  if (provider === "slack") {
    const response = await fetch("https://slack.com/api/auth.test", {
      method: "POST",
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/json",
      },
      cache: "no-store",
    });

    if (!response.ok) return null;

    const body = await readJson(response);
    if (body.ok !== true) return null;

    return {
      verified: true,
      state: "verified",
      identity: {
        team_id: body.team_id ?? null,
        team: body.team ?? null,
        user_id: body.user_id ?? null,
        user: body.user ?? null,
        bot_id: body.bot_id ?? null,
      },
    };
  }

  if (provider === "discord") {
    const response = await fetch("https://discord.com/api/users/@me", {
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/json",
      },
      cache: "no-store",
    });

    if (!response.ok) return null;

    const body = await readJson(response);
    if (typeof body.id !== "string") return null;

    return {
      verified: true,
      state: "verified",
      identity: {
        id: body.id,
        username: body.username ?? null,
        global_name: body.global_name ?? null,
      },
    };
  }

  // Meta and WhatsApp use a Meta-issued access token. Validate the token
  // against Meta's token-debug endpoint, but do not claim that a WhatsApp
  // Business Account or business asset has been selected yet.
  const appAccessToken = `${clientId}|${clientSecret}`;
  const debugUrl = new URL(
    "https://graph.facebook.com/v24.0/debug_token",
  );
  debugUrl.searchParams.set("input_token", accessToken);
  debugUrl.searchParams.set("access_token", appAccessToken);

  const debugResponse = await fetch(debugUrl, {
    headers: { accept: "application/json" },
    cache: "no-store",
  });

  if (!debugResponse.ok) return null;

  const debugBody = await readJson(debugResponse);
  const data =
    debugBody.data &&
    typeof debugBody.data === "object" &&
    !Array.isArray(debugBody.data)
      ? (debugBody.data as Record<string, unknown>)
      : null;

  if (data?.is_valid !== true) return null;

  return {
    verified: false,
    state: "token_valid",
    identity: {
      app_id: data.app_id ?? null,
      user_id: data.user_id ?? null,
      scopes: Array.isArray(data.scopes) ? data.scopes : [],
      expires_at: data.expires_at ?? null,
      data_access_expiration_time:
        data.data_access_expiration_time ?? null,
      asset_selection_required: provider === "whatsapp",
    },
  };
}

export async function GET(request: Request) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const stateToken = url.searchParams.get("state");
  const oauthError = url.searchParams.get("error");

  if (oauthError) {
    return errorRedirect(
      url.origin,
      `Provider authorization was not completed: ${oauthError}`,
    );
  }

  if (!code || !stateToken) {
    return errorRedirect(
      url.origin,
      "The provider authorization response was incomplete.",
    );
  }

  const state = await decryptIntegrationState<OAuthState>(stateToken);

  if (!state || state.expiresAt < Date.now()) {
    return errorRedirect(
      url.origin,
      "The authorization session expired. Start the connection again.",
    );
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user || user.id !== state.userId) {
    return errorRedirect(
      url.origin,
      "The authorization session does not belong to the current user.",
    );
  }

  const oauth = config(state.provider);

  if (!oauth.clientId || !oauth.clientSecret) {
    return errorRedirect(
      url.origin,
      `${state.provider} OAuth is not configured on this deployment.`,
    );
  }

  const form = new URLSearchParams({
    code,
    client_id: oauth.clientId,
    client_secret: oauth.clientSecret,
    redirect_uri: state.redirectUri,
    grant_type: "authorization_code",
  });

  if (state.verifier) {
    form.set("code_verifier", state.verifier);
  }

  const tokenResponse = await fetch(oauth.tokenUrl, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: form,
    cache: "no-store",
  });

  const tokenBody = await readJson(tokenResponse);

  if (!tokenResponse.ok) {
    return errorRedirect(
      url.origin,
      "The provider rejected the authorization code.",
    );
  }

  const accessToken =
    typeof tokenBody.access_token === "string" ? tokenBody.access_token : "";

  if (!accessToken) {
    return errorRedirect(
      url.origin,
      "The provider did not return an access token.",
    );
  }

  const refreshToken =
    typeof tokenBody.refresh_token === "string"
      ? tokenBody.refresh_token
      : null;

  const currentResult = await supabase
    .from("security_integrations")
    .select("configuration")
    .eq("id", state.integrationId)
    .eq("organization_id", state.organizationId)
    .maybeSingle();

  if (!currentResult.data) {
    return errorRedirect(
      url.origin,
      "The registered integration no longer exists.",
    );
  }

  const current =
    currentResult.data.configuration &&
    typeof currentResult.data.configuration === "object" &&
    !Array.isArray(currentResult.data.configuration)
      ? (currentResult.data.configuration as Record<string, unknown>)
      : {};

  const validation = await validateProviderToken(
    state.provider,
    accessToken,
    oauth.clientId,
    oauth.clientSecret,
  );

  if (!validation) {
    return errorRedirect(
      url.origin,
      "Trinorin received the provider token but could not validate it with the provider.",
    );
  }

  const encryptedAccessToken = await encryptIntegrationSecret(accessToken);
  const encryptedRefreshToken = refreshToken
    ? await encryptIntegrationSecret(refreshToken)
    : null;

  const tokenType =
    typeof tokenBody.token_type === "string"
      ? tokenBody.token_type
      : "Bearer";

  const scopes =
    typeof tokenBody.scope === "string"
      ? tokenBody.scope.split(/\s+/).filter(Boolean)
      : [];

  const expiresIn =
    typeof tokenBody.expires_in === "number" ? tokenBody.expires_in : null;

  const authorizedAt = new Date().toISOString();
  const expiresAt = expiresIn
    ? new Date(Date.now() + expiresIn * 1000).toISOString()
    : null;

  const admin = createAdminClient();

  const { error: secretError } = await admin
    .from("security_integration_secrets")
    .upsert(
      {
        organization_id: state.organizationId,
        integration_id: state.integrationId,
        provider: state.provider,
        access_token_encrypted: encryptedAccessToken,
        refresh_token_encrypted: encryptedRefreshToken,
        token_type: tokenType,
        scopes,
        expires_at: expiresAt,
        authorized_at: authorizedAt,
        updated_at: authorizedAt,
      },
      { onConflict: "integration_id" },
    );

  if (secretError) {
    return errorRedirect(
      url.origin,
      "Authorization succeeded but Trinorin could not persist the provider credentials securely.",
    );
  }

  const { authorization: _oldAuthorization, ...safeConfiguration } = current;

  const { error } = await supabase
    .from("security_integrations")
    .update({
      status: "connected",
      configuration: {
        ...safeConfiguration,
        connection_state: validation.state,
        authorization: {
          method: "oauth2",
          provider: state.provider,
          authorized_at: authorizedAt,
          token_type: tokenType,
          expires_in: expiresIn,
          expires_at: expiresAt,
          scopes,
          validation_state: validation.state,
          verified: validation.verified,
          identity: validation.identity,
          boundary:
            state.provider === "whatsapp"
              ? "Meta access token validated. WhatsApp Business Account and business-asset selection remain to be verified before Trinorin claims WhatsApp telemetry access."
              : state.provider === "meta"
                ? "Meta access token validated. Specific business assets and granted capabilities remain bounded by the permissions returned by Meta."
                : "Provider token validated against the provider identity endpoint.",
        },
      },
    })
    .eq("id", state.integrationId)
    .eq("organization_id", state.organizationId);

  if (error) {
    return errorRedirect(
      url.origin,
      "Authorization succeeded but Trinorin could not finalize the connection state.",
    );
  }

  return NextResponse.redirect(
    new URL(
      `/integrations?connected=${encodeURIComponent(state.provider)}`,
      url.origin,
    ),
  );
}
