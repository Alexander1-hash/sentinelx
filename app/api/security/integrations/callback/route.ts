import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { decryptIntegrationState, encryptIntegrationSecret } from "@/lib/security/integration-secrets";

type OAuthState = {
  integrationId: string;
  organizationId: string;
  provider: "x" | "meta" | "whatsapp" | "discord" | "slack";
  userId: string;
  redirectUri: string;
  verifier: string | null;
  expiresAt: number;
};

function config(provider: OAuthState["provider"]) {
  const map = {
    x: { clientId: process.env.X_CLIENT_ID, clientSecret: process.env.X_CLIENT_SECRET, tokenUrl: "https://api.x.com/2/oauth2/token" },
    meta: { clientId: process.env.META_CLIENT_ID, clientSecret: process.env.META_CLIENT_SECRET, tokenUrl: "https://graph.facebook.com/v24.0/oauth/access_token" },
    whatsapp: { clientId: process.env.META_CLIENT_ID, clientSecret: process.env.META_CLIENT_SECRET, tokenUrl: "https://graph.facebook.com/v24.0/oauth/access_token" },
    discord: { clientId: process.env.DISCORD_CLIENT_ID, clientSecret: process.env.DISCORD_CLIENT_SECRET, tokenUrl: "https://discord.com/api/oauth2/token" },
    slack: { clientId: process.env.SLACK_CLIENT_ID, clientSecret: process.env.SLACK_CLIENT_SECRET, tokenUrl: "https://slack.com/api/oauth.v2.access" },
  } as const;
  return map[provider];
}

function errorRedirect(origin: string, message: string) {
  return NextResponse.redirect(new URL(`/integrations?connection_error=${encodeURIComponent(message)}`, origin));
}

export async function GET(request: Request) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const stateToken = url.searchParams.get("state");
  const oauthError = url.searchParams.get("error");

  if (oauthError) return errorRedirect(url.origin, `Provider authorization was not completed: ${oauthError}`);
  if (!code || !stateToken) return errorRedirect(url.origin, "The provider authorization response was incomplete.");

  const state = await decryptIntegrationState<OAuthState>(stateToken);
  if (!state || state.expiresAt < Date.now()) return errorRedirect(url.origin, "The authorization session expired. Start the connection again.");

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user || user.id !== state.userId) return errorRedirect(url.origin, "The authorization session does not belong to the current user.");

  const oauth = config(state.provider);
  if (!oauth.clientId || !oauth.clientSecret) return errorRedirect(url.origin, `${state.provider} OAuth is not configured on this deployment.`);

  const form = new URLSearchParams({
    code,
    client_id: oauth.clientId,
    client_secret: oauth.clientSecret,
    redirect_uri: state.redirectUri,
    grant_type: "authorization_code",
  });
  if (state.verifier) form.set("code_verifier", state.verifier);

  const tokenResponse = await fetch(oauth.tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: form,
    cache: "no-store",
  });

  const tokenBody = await tokenResponse.json().catch(() => ({}));
  if (!tokenResponse.ok) return errorRedirect(url.origin, "The provider rejected the authorization code.");

  const accessToken = typeof tokenBody.access_token === "string" ? tokenBody.access_token : "";
  if (!accessToken) return errorRedirect(url.origin, "The provider did not return an access token.");

  const refreshToken = typeof tokenBody.refresh_token === "string" ? tokenBody.refresh_token : null;
  const currentResult = await supabase
    .from("security_integrations")
    .select("configuration")
    .eq("id", state.integrationId)
    .eq("organization_id", state.organizationId)
    .maybeSingle();

  if (!currentResult.data) return errorRedirect(url.origin, "The registered integration no longer exists.");

  const current = currentResult.data.configuration && typeof currentResult.data.configuration === "object" && !Array.isArray(currentResult.data.configuration)
    ? currentResult.data.configuration as Record<string, unknown>
    : {};

  const encryptedAccessToken = await encryptIntegrationSecret(accessToken);
  const encryptedRefreshToken = refreshToken ? await encryptIntegrationSecret(refreshToken) : null;
  const tokenType = typeof tokenBody.token_type === "string" ? tokenBody.token_type : "Bearer";
  const scopes = typeof tokenBody.scope === "string"
    ? tokenBody.scope.split(/\s+/).filter(Boolean)
    : [];
  const expiresIn = typeof tokenBody.expires_in === "number" ? tokenBody.expires_in : null;
  const authorizedAt = new Date().toISOString();

  const admin = createAdminClient();
  const { error: secretError } = await admin
    .from("security_integration_secrets")
    .upsert({
      organization_id: state.organizationId,
      integration_id: state.integrationId,
      provider: state.provider,
      access_token_encrypted: encryptedAccessToken,
      refresh_token_encrypted: encryptedRefreshToken,
      token_type: tokenType,
      scopes,
      expires_at: expiresIn ? new Date(Date.now() + expiresIn * 1000).toISOString() : null,
      authorized_at: authorizedAt,
      updated_at: authorizedAt,
    }, { onConflict: "integration_id" });

  if (secretError) {
    return errorRedirect(url.origin, "Authorization succeeded but Trinorin could not persist the provider credentials securely.");
  }

  const { authorization: _oldAuthorization, ...safeConfiguration } = current;
  const { error } = await supabase
    .from("security_integrations")
    .update({
      status: "connected",
      configuration: {
        ...safeConfiguration,
        connection_state: "authorized",
        authorization: {
          method: "oauth2",
          provider: state.provider,
          authorized_at: authorizedAt,
          token_type: tokenType,
          expires_in: expiresIn,
          scopes,
        },
      },
    })
    .eq("id", state.integrationId)
    .eq("organization_id", state.organizationId);

  if (error) return errorRedirect(url.origin, "Authorization succeeded but Trinorin could not finalize the connection state.");

  return NextResponse.redirect(new URL(`/integrations?connected=${encodeURIComponent(state.provider)}`, url.origin));
}
