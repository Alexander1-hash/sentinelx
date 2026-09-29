import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import {
  getExecutorRequirement,
  getExecutorRequirements,
  getExecutorAdapters,
} from "@/lib/security/executors";
import { buildExecutorPreview } from "@/lib/security/executor-registry";
import { buildAdaptiveInvestigationContext } from "@/lib/security/adaptive-context";

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
    const findingId = url.searchParams.get("findingId")?.trim();

    const { data: integrations, error } = await supabase
      .from("security_integrations")
      .select("id,provider,integration_type,display_name,status,scopes,last_sync_at,configuration")
      .eq("organization_id", organizationId);

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    const connected = (integrations ?? []).filter(
      (integration) => integration.status === "connected",
    );

    let adaptiveInvestigationContext = null;

    if (findingId) {
      const [findingResult, evidenceResult, eventsResult, relationshipResult, assetsResult, memoryResult] = await Promise.all([
        supabase.from("security_findings").select("id,asset_id,title,finding_type,severity,status,detected_at,summary").eq("organization_id", organizationId).eq("id", findingId).maybeSingle(),
        supabase.from("security_evidence").select("id,asset_id,evidence_type,source,title,summary,observed_at,data").eq("organization_id", organizationId).order("observed_at", { ascending: false }).limit(300),
        supabase.from("security_events").select("id,asset_id,severity,observed_at").eq("organization_id", organizationId).order("observed_at", { ascending: false }).limit(300),
        supabase.from("security_relationships").select("source_asset_id,target_asset_id,relationship_type,confidence,status").eq("organization_id", organizationId).limit(500),
        supabase.from("security_assets").select("id,name,asset_type,criticality,status").eq("organization_id", organizationId).limit(500),
        supabase.from("security_memory").select("id,memory_type,subject_id,title,summary,state,data,occurred_at").eq("organization_id", organizationId).order("occurred_at", { ascending: false }).limit(500),
      ]);

      if (findingResult.error || evidenceResult.error || eventsResult.error || relationshipResult.error || assetsResult.error || memoryResult.error) {
        return NextResponse.json({ error: "Investigation context could not be loaded." }, { status: 500 });
      }

      if (findingResult.data) {
        adaptiveInvestigationContext = buildAdaptiveInvestigationContext({
          finding: findingResult.data,
          evidence: evidenceResult.data ?? [],
          events: eventsResult.data ?? [],
          relationships: relationshipResult.data ?? [],
          assets: assetsResult.data ?? [],
          memories: memoryResult.data ?? [],
        });
      }
    }

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
        findingId: findingId ?? null,
        requirement,
        adaptiveInvestigationContext,
        connectedIntegrations: matchingIntegrations.map((integration) => {
          const configuration = (integration as { configuration?: unknown }).configuration;
          const execution =
            configuration && typeof configuration === "object" && !Array.isArray(configuration)
              ? (configuration as Record<string, unknown>).execution
              : null;
          const webhookUrl =
            execution && typeof execution === "object" && !Array.isArray(execution)
              ? (execution as Record<string, unknown>).webhook_url
              : null;
          return {
            id: integration.id,
            provider: integration.provider,
            integrationType: integration.integration_type,
            displayName: integration.display_name,
            status: integration.status,
            lastSyncAt: integration.last_sync_at,
            providerExecutionReady: Boolean(
              typeof webhookUrl === "string" && webhookUrl.trim(),
            ),
          };
        }),
        executorReady:
          requirement.readiness === "not_required"
            ? true
            : matchingIntegrations.some((integration) => {
                const configuration = (integration as { configuration?: unknown }).configuration;
                const execution =
                  configuration && typeof configuration === "object" && !Array.isArray(configuration)
                    ? (configuration as Record<string, unknown>).execution
                    : null;
                const webhookUrl =
                  execution && typeof execution === "object" && !Array.isArray(execution)
                    ? (execution as Record<string, unknown>).webhook_url
                    : null;
                return Boolean(typeof webhookUrl === "string" && webhookUrl.trim());
              }),
        boundary:
          requirement.readiness === "not_required"
            ? requirement.boundary
            : "Provider execution is available only when a connected, permitted integration has an explicit execution webhook and the deployment execution allowlist is configured. Connectivity never grants authorization.",
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
        executorReady:
          requirement.readiness === "not_required" ||
          connected.some((integration) => {
            if (!requirement.requiredIntegrationTypes.includes(integration.integration_type)) return false;
            const configuration = (integration as { configuration?: unknown }).configuration;
            const execution =
              configuration && typeof configuration === "object" && !Array.isArray(configuration)
                ? (configuration as Record<string, unknown>).execution
                : null;
            const webhookUrl =
              execution && typeof execution === "object" && !Array.isArray(execution)
                ? (execution as Record<string, unknown>).webhook_url
                : null;
            return Boolean(typeof webhookUrl === "string" && webhookUrl.trim());
          }),
      })),
      connectedIntegrations: connected.map((integration) => ({
        id: integration.id,
        provider: integration.provider,
        integrationType: integration.integration_type,
        displayName: integration.display_name,
        status: integration.status,
        lastSyncAt: integration.last_sync_at,
      })),
      adaptiveInvestigationContext,
      boundary:
        "Trinorin reports executor readiness separately from operator authorization and integration connectivity. Investigation context informs readiness but never grants authorization.",
    });
  } catch {
    return NextResponse.json(
      { error: "Security executor readiness could not be loaded." },
      { status: 500 },
    );
  }
}
