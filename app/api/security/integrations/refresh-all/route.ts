import { NextResponse } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  decryptIntegrationSecret,
  encryptIntegrationSecret,
} from "@/lib/security/integration-secrets";

type Provider = "x" | "discord" | "slack";

const providerConfig = {
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

async function readJson(response: Response) {
  return response.json().catch(() => ({})) as Promise<Record<string, unknown>>;
}

function authorized(request: Request) {
  const secret = process.env.CRON_SECRET;
  if (!secret) return false;
  const authorization = request.headers.get("authorization");
  return authorization === `Bearer ${secret}`;
}

export async function GET(request: Request) {
  if (!authorized(request)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const admin = createAdminClient();
    const threshold = Date.now() + 15 * 60 * 1000;

    const { data: rows, error } = await admin
      .from("security_integration_secrets")
      .select(
        "integration_id,organization_id,provider,access_token_encrypted,refresh_token_encrypted,token_type,scopes,expires_at",
      )
      .in("provider", ["x", "discord", "slack"]);

    if (error) {
      return NextResponse.json({ error: "Unable to load renewable integration credentials." }, { status: 500 });
    }

    let checked = 0;
    let refreshed = 0;
    let skipped = 0;
    const failures: Array<{ integrationId: string; provider: string; error: string }> = [];

    for (const row of rows ?? []) {
      checked += 1;

      if (!row.refresh_token_encrypted) {
        skipped += 1;
        continue;
      }

      const expiresAt = row.expires_at ? new Date(row.expires_at).getTime() : null;
      if (expiresAt !== null && expiresAt > threshold) {
        skipped += 1;
        continue;
      }

      const provider = row.provider as Provider;
      const config = providerConfig[provider];

      if (!config.clientId || !config.clientSecret) {
        failures.push({
          integrationId: row.integration_id,
          provider,
          error: "Provider OAuth credentials are not configured.",
        });
        continue;
      }

      const refreshToken = await decryptIntegrationSecret(row.refresh_token_encrypted);
      if (!refreshToken) {
        failures.push({
          integrationId: row.integration_id,
          provider,
          error: "Stored refresh credential could not be decrypted.",
        });
        continue;
      }

      const form = new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      });

      const headers: HeadersInit = {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      };

      if (provider === "discord") {
        headers.authorization =
          "Basic " + btoa(`${config.clientId}:${config.clientSecret}`);
      } else {
        form.set("client_id", config.clientId);
        form.set("client_secret", config.clientSecret);
      }

      const response = await fetch(config.tokenUrl, {
        method: "POST",
        headers,
        body: form,
        cache: "no-store",
      });

      const tokenBody = await readJson(response);

      if (!response.ok || (provider === "slack" && tokenBody.ok === false)) {
        failures.push({
          integrationId: row.integration_id,
          provider,
          error: "Provider rejected the scheduled token refresh.",
        });
        continue;
      }

      const accessToken =
        typeof tokenBody.access_token === "string" ? tokenBody.access_token : "";

      if (!accessToken) {
        failures.push({
          integrationId: row.integration_id,
          provider,
          error: "Provider returned no access token.",
        });
        continue;
      }

      const nextRefreshToken =
        typeof tokenBody.refresh_token === "string"
          ? tokenBody.refresh_token
          : refreshToken;

      const expiresIn =
        typeof tokenBody.expires_in === "number" ? tokenBody.expires_in : null;

      const now = new Date().toISOString();
      const nextExpiresAt = expiresIn
        ? new Date(Date.now() + expiresIn * 1000).toISOString()
        : null;

      const scopes =
        typeof tokenBody.scope === "string"
          ? tokenBody.scope.split(/\s+/).filter(Boolean)
          : Array.isArray(row.scopes)
            ? row.scopes
            : [];

      const tokenType =
        typeof tokenBody.token_type === "string"
          ? tokenBody.token_type
          : row.token_type ?? "Bearer";

      const { error: secretUpdateError } = await admin
        .from("security_integration_secrets")
        .update({
          access_token_encrypted: await encryptIntegrationSecret(accessToken),
          refresh_token_encrypted: await encryptIntegrationSecret(nextRefreshToken),
          token_type: tokenType,
          scopes,
          expires_at: nextExpiresAt,
          updated_at: now,
        })
        .eq("integration_id", row.integration_id)
        .eq("organization_id", row.organization_id);

      if (secretUpdateError) {
        failures.push({
          integrationId: row.integration_id,
          provider,
          error: "Refreshed credential could not be persisted securely.",
        });
        continue;
      }

      const { data: integration } = await admin
        .from("security_integrations")
        .select("configuration")
        .eq("id", row.integration_id)
        .eq("organization_id", row.organization_id)
        .maybeSingle();

      const configuration =
        integration?.configuration &&
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

      await admin
        .from("security_integrations")
        .update({
          status: "connected",
          configuration: {
            ...configuration,
            connection_state: "verified",
            authorization: {
              ...authorization,
              refreshed_at: now,
              expires_at: nextExpiresAt,
              validation_state: "verified",
              verified: true,
            },
          },
          updated_at: now,
        })
        .eq("id", row.integration_id)
        .eq("organization_id", row.organization_id);

      refreshed += 1;
    }

    return NextResponse.json({
      ok: failures.length === 0,
      checked,
      refreshed,
      skipped,
      failures,
      ranAt: new Date().toISOString(),
    });
  } catch {
    return NextResponse.json(
      { error: "Scheduled integration credential refresh failed." },
      { status: 500 },
    );
  }
}
