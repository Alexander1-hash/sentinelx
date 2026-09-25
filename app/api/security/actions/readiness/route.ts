import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import {
  getExecutorRequirement,
  getExecutorRequirements,
  getExecutorAdapters,
} from "@/lib/security/executors";
import { buildExecutorPreview } from "@/lib/security/executor-registry";

async function getContext() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

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

export async function GET(request: Request) {
  try {
    const { supabase, user, organizationId } = await getContext();

    if (!user || !organizationId) {
      return NextResponse.json(
        { error: "Authentication and organization are required." },
        { status: 401 },
      );
    }

    const url = new URL(request.url);
    const actionType = url.searchParams.get("actionType")?.trim();

    const { data: integrations, error } = await supabase
      .from("security_integrations")
      .select("id,provider,integration_type,display_name,status,scopes,last_sync_at")
      .eq("organization_id", organizationId);

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    const connected = (integrations ?? []).filter(
      (integration) => integration.status === "connected",
    );

    if (actionType) {
      const requirement = getExecutorRequirement(actionType);

      if (!requirement) {
        return NextResponse.json(
          { error: "Unsupported security action." },
          { status: 400 },
        );
      }

      const preview = buildExecutorPreview(actionType);
      const matchingIntegrations = connected.filter((integration) =>
        requirement.requiredIntegrationTypes.includes(integration.integration_type),
      );

      return NextResponse.json({
        actionType,
        requirement,
        connectedIntegrations: matchingIntegrations.map((integration) => ({
          id: integration.id,
          provider: integration.provider,
          integrationType: integration.integration_type,
          displayName: integration.display_name,
          status: integration.status,
          lastSyncAt: integration.last_sync_at,
        })),
        executorReady: false,
        boundary:
          requirement.readiness === "not_required"
            ? requirement.boundary
            : "Connectivity alone does not authorize or execute a provider action. A provider-specific executor adapter must be configured.",
      });
    }

    return NextResponse.json({
      executors: getExecutorAdapters().map((adapter) => ({
        id: adapter.id,
        displayName: adapter.displayName,
        executorType: adapter.executorType,
        mode: adapter.mode,
        enabled: adapter.enabled,
        supportedActions: adapter.supportedActions,
        boundary: adapter.boundary,
      })),
      requirements: getExecutorRequirements().map((requirement) => ({
        ...requirement,
        connectedIntegrationCount: connected.filter((integration) =>
          requirement.requiredIntegrationTypes.includes(integration.integration_type),
        ).length,
        executorReady: requirement.readiness === "not_required",
      })),
      connectedIntegrations: connected.map((integration) => ({
        id: integration.id,
        provider: integration.provider,
        integrationType: integration.integration_type,
        displayName: integration.display_name,
        status: integration.status,
        lastSyncAt: integration.last_sync_at,
      })),
      boundary:
        "SentinelX reports executor readiness separately from operator authorization and integration connectivity.",
    });
  } catch {
    return NextResponse.json(
      { error: "Security executor readiness could not be loaded." },
      { status: 500 },
    );
  }
}
