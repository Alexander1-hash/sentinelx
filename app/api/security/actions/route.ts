import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { buildSecurityPatterns, type SecurityPatternMemory } from "@/lib/security/patterns";
import { validateExecutionTarget, isMutatingSecurityAction } from "@/lib/security/executors";

const ACTION_TYPES = [
  "investigate_asset",
  "review_finding",
  "contain_asset",
  "disable_integration",
  "revoke_access",
  "isolate_endpoint",
  "block_indicator",
] as const;

const MUTATING_ACTIONS = new Set([
  "contain_asset",
  "disable_integration",
  "revoke_access",
  "isolate_endpoint",
  "block_indicator",
]);

type ActionStatus =
  | "pending"
  | "approved"
  | "executing"
  | "completed"
  | "failed"
  | "cancelled";

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

export async function GET() {
  try {
    const { supabase, organizationId } = await getContext();

    if (!organizationId) return NextResponse.json({ actions: [] });

    const { data, error } = await supabase
      .from("security_actions")
      .select("id,finding_id,requested_by,action_type,status,target,authorization,result,created_at,executed_at")
      .eq("organization_id", organizationId)
      .order("created_at", { ascending: false })
      .limit(100);

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    const actions = data ?? [];
    const assetIds = [...new Set(actions
      .map((action) => {
        const target = action.target as Record<string, unknown>;
        const value = target.assetId ?? (target.resourceType === "asset" ? target.resourceId : null);
        return typeof value === "string" ? value : null;
      })
      .filter((value): value is string => Boolean(value)))];

    const findingIds = [...new Set(actions
      .map((action) => {
        const target = action.target as Record<string, unknown>;
        const value = target.resourceType === "finding" ? target.resourceId : action.finding_id;
        return typeof value === "string" ? value : null;
      })
      .filter((value): value is string => Boolean(value)))];

    const integrationIds = [...new Set(actions
      .map((action) => {
        const target = action.target as Record<string, unknown>;
        const value = target.integrationId ?? (target.resourceType === "integration" ? target.resourceId : null);
        return typeof value === "string" ? value : null;
      })
      .filter((value): value is string => Boolean(value)))];

    const [assetsResult, findingsResult, integrationsResult] = await Promise.all([
      assetIds.length
        ? supabase.from("security_assets").select("id,name,asset_type").in("id", assetIds)
        : Promise.resolve({ data: [], error: null }),
      findingIds.length
        ? supabase.from("security_findings").select("id,title,finding_type").in("id", findingIds)
        : Promise.resolve({ data: [], error: null }),
      integrationIds.length
        ? supabase.from("security_integrations").select("id,display_name,provider,integration_type").in("id", integrationIds)
        : Promise.resolve({ data: [], error: null }),
    ]);

    if (assetsResult.error || findingsResult.error || integrationsResult.error) {
      return NextResponse.json({ error: "Security action target context could not be resolved." }, { status: 500 });
    }

    const assets = new Map((assetsResult.data ?? []).map((item) => [item.id, item]));
    const findings = new Map((findingsResult.data ?? []).map((item) => [item.id, item]));
    const integrations = new Map((integrationsResult.data ?? []).map((item) => [item.id, item]));

    const enrichedActions = actions.map((action) => {
      const target = action.target as Record<string, unknown>;
      const assetId = typeof target.assetId === "string"
        ? target.assetId
        : target.resourceType === "asset" && typeof target.resourceId === "string"
          ? target.resourceId
          : null;
      const findingId = target.resourceType === "finding" && typeof target.resourceId === "string"
        ? target.resourceId
        : action.finding_id;
      const integrationId = typeof target.integrationId === "string"
        ? target.integrationId
        : target.resourceType === "integration" && typeof target.resourceId === "string"
          ? target.resourceId
          : null;

      const asset = assetId ? assets.get(assetId) : null;
      const finding = findingId ? findings.get(findingId) : null;
      const integration = integrationId ? integrations.get(integrationId) : null;

      const targetContext = asset
        ? {
            resourceName: asset.name,
            resourceType: asset.asset_type,
            source: target.assetId ? "Security Brain asset" : "verified asset resource",
            evidence: finding
              ? `The action is linked to finding “${finding.title}” and targets its recorded affected asset.`
              : "The target is a recorded organization-owned Security Brain asset.",
            boundary: "Target identity is resolved from SentinelX records. This does not prove the external provider will execute the action.",
          }
        : finding
          ? {
              resourceName: finding.title,
              resourceType: "finding",
              source: "Security finding",
              evidence: `The action targets the organization-owned finding “${finding.title}”.`,
              boundary: "Finding identity is verified in SentinelX. A finding is not proof that an external action has occurred.",
            }
          : integration
            ? {
                resourceName: integration.display_name,
                resourceType: integration.integration_type,
                source: "Security integration",
                evidence: `The action references the organization-owned ${integration.provider} integration.`,
                boundary: "Integration identity is verified separately from provider execution capability.",
              }
            : {
                source: "operator supplied",
                boundary: "Target identity is not resolved to a known SentinelX resource. External execution must remain blocked.",
              };

      return { ...action, target_context: targetContext };
    });

    return NextResponse.json({ actions: enrichedActions });
  } catch {
    return NextResponse.json({ error: "Security actions could not be loaded." }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const { supabase, user, organizationId } = await getContext();

    if (!user || !organizationId) {
      return NextResponse.json({ error: "Authentication and organization are required." }, { status: 401 });
    }

    const body = (await request.json()) as {
      actionType?: string;
      findingId?: string | null;
      target?: Record<string, unknown>;
      reason?: string;
    };

    const actionType = body.actionType?.trim();

    if (!actionType || !ACTION_TYPES.includes(actionType as (typeof ACTION_TYPES)[number])) {
      return NextResponse.json({ error: "Unsupported security action." }, { status: 400 });
    }

    let target: Record<string, unknown> = body.target ?? {};

    // Deterministically derive targets from organization-owned SentinelX records
    // when the operator supplied a finding but did not provide a target.
    // We never invent provider resource IDs or infer targets from free-form text.
    if (body.findingId && Object.keys(target).length === 0) {
      const { data: finding, error: findingError } = await supabase
        .from("security_findings")
        .select("id,asset_id")
        .eq("id", body.findingId)
        .eq("organization_id", organizationId)
        .maybeSingle();

      if (findingError) {
        return NextResponse.json({ error: findingError.message }, { status: 500 });
      }

      if (!finding) {
        return NextResponse.json({ error: "The selected finding was not found in this organization." }, { status: 404 });
      }

      if (actionType === "review_finding") {
        target = {
          resourceId: finding.id,
          resourceType: "finding",
        };
      } else if (
        ["investigate_asset", "contain_asset", "revoke_access", "isolate_endpoint"].includes(actionType) &&
        finding.asset_id
      ) {
        target = {
          assetId: finding.asset_id,
          resourceId: finding.asset_id,
          resourceType: "asset",
        };
      }
    }

    const targetValidation = validateExecutionTarget(actionType, target);
    if (isMutatingSecurityAction(actionType) && !targetValidation.valid) {
      return NextResponse.json(
        {
          error: targetValidation.error,
          targetResolution: body.findingId
            ? "The finding was verified, but no deterministic executable target could be derived for this action."
            : "Provide an explicit authorized target for this action.",
        },
        { status: 400 },
      );
    }
    const reason = body.reason?.trim() || "Operator-requested security action.";

    let historicalPatternContext: Array<Record<string, unknown>> = [];
    if (body.findingId) {
      const { data: memories } = await supabase
        .from("security_memory")
        .select("id,memory_type,subject_id,title,summary,state,data,occurred_at")
        .eq("organization_id", organizationId)
        .order("occurred_at", { ascending: false })
        .limit(300);

      const typedMemories = (memories ?? []) as SecurityPatternMemory[];
      const patterns = buildSecurityPatterns(typedMemories);
      historicalPatternContext = patterns
        .filter((pattern) =>
          pattern.memoryIds.some((memoryId) => {
            const memory = typedMemories.find((item) => item.id === memoryId);
            if (!memory) return false;
            const findingId =
              typeof memory.data.finding_id === "string"
                ? memory.data.finding_id
                : memory.memory_type === "finding_state"
                  ? memory.subject_id
                  : null;
            return findingId === body.findingId;
          })
        )
        .slice(0, 8)
        .map((pattern) => ({
          id: pattern.id,
          pattern: pattern.pattern,
          title: pattern.title,
          detail: pattern.detail,
          confidence: pattern.confidence,
          firstObserved: pattern.firstObserved,
          lastObserved: pattern.lastObserved,
          memoryIds: pattern.memoryIds,
          sequence: pattern.sequence ?? null,
          boundary: pattern.boundary,
        }));
    }

    const authorization = {
      required: MUTATING_ACTIONS.has(actionType),
      state: "pending_operator_authorization",
      requested_at: new Date().toISOString(),
      requested_by: user.id,
      reason,
      execution_boundary: "No external or destructive action is executed by this endpoint.",
    };

    const { data, error } = await supabase
      .from("security_actions")
      .insert({
        organization_id: organizationId,
        finding_id: body.findingId ?? null,
        requested_by: user.id,
        action_type: actionType,
        status: "pending",
        target,
        authorization,
        result: {
          state: "recommendation_created",
          message: "Action is queued for explicit operator review.",
          historical_pattern_context: historicalPatternContext,
        },
      })
      .select("id,finding_id,action_type,status,target,authorization,result,created_at,executed_at")
      .single();

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    return NextResponse.json({
      action: data,
      message: "Security action created. Review and authorize it before execution.",
    }, { status: 201 });
  } catch {
    return NextResponse.json({ error: "Security action could not be created." }, { status: 500 });
  }
}

export async function PATCH(request: Request) {
  try {
    const { supabase, user, organizationId } = await getContext();

    if (!user || !organizationId) {
      return NextResponse.json({ error: "Authentication and organization are required." }, { status: 401 });
    }

    const body = (await request.json()) as {
      id?: string;
      status?: ActionStatus;
    };

    if (!body.id || !body.status) {
      return NextResponse.json({ error: "Action id and status are required." }, { status: 400 });
    }

    if (!["approved", "cancelled"].includes(body.status)) {
      return NextResponse.json({
        error: "Only explicit approval or cancellation is available through this control.",
      }, { status: 400 });
    }

    const { data: existing, error: lookupError } = await supabase
      .from("security_actions")
      .select("id,finding_id,action_type,status,target,authorization,result")
      .eq("id", body.id)
      .eq("organization_id", organizationId)
      .maybeSingle();

    if (lookupError) {
      return NextResponse.json({ error: lookupError.message }, { status: 500 });
    }

    if (!existing) {
      return NextResponse.json({ error: "Security action not found." }, { status: 404 });
    }

    if (existing.status !== "pending") {
      return NextResponse.json({ error: "Only pending actions can be approved or cancelled." }, { status: 409 });
    }

    // Revalidate the reviewed target at approval time. A pending action may have
    // been created earlier, so the current organization-owned records must still
    // agree with the target the operator is approving.
    if (body.status === "approved") {
      const target = (existing.target ?? {}) as Record<string, unknown>;

      if (existing.finding_id) {
        const { data: finding, error: findingError } = await supabase
          .from("security_findings")
          .select("id,asset_id,title")
          .eq("id", existing.finding_id)
          .eq("organization_id", organizationId)
          .maybeSingle();

        if (findingError) {
          return NextResponse.json({ error: findingError.message }, { status: 500 });
        }

        if (!finding) {
          return NextResponse.json({
            error: "Approval blocked: the linked finding is no longer available in this organization.",
          }, { status: 409 });
        }

        if (existing.action_type === "review_finding") {
          if (target.resourceType !== "finding" || target.resourceId !== finding.id) {
            return NextResponse.json({
              error: "Approval blocked: the finding target changed since this action was created.",
            }, { status: 409 });
          }
        }

        if (["investigate_asset", "contain_asset", "revoke_access", "isolate_endpoint"].includes(existing.action_type)) {
          if (!finding.asset_id) {
            return NextResponse.json({
              error: "Approval blocked: the finding no longer has a deterministic affected asset.",
            }, { status: 409 });
          }

          const targetAssetId =
            typeof target.assetId === "string"
              ? target.assetId
              : target.resourceType === "asset" && typeof target.resourceId === "string"
                ? target.resourceId
                : null;

          if (targetAssetId !== finding.asset_id) {
            return NextResponse.json({
              error: "Approval blocked: the affected asset changed since this action was created.",
            }, { status: 409 });
          }
        }
      }

      const targetAssetId =
        typeof target.assetId === "string"
          ? target.assetId
          : target.resourceType === "asset" && typeof target.resourceId === "string"
            ? target.resourceId
            : null;

      if (targetAssetId) {
        const { data: asset, error: assetError } = await supabase
          .from("security_assets")
          .select("id,status")
          .eq("id", targetAssetId)
          .eq("organization_id", organizationId)
          .maybeSingle();

        if (assetError) {
          return NextResponse.json({ error: assetError.message }, { status: 500 });
        }

        if (!asset) {
          return NextResponse.json({
            error: "Approval blocked: the target asset is no longer available in this organization.",
          }, { status: 409 });
        }
      }
    }

    const authorization = {
      ...(existing.authorization ?? {}),
      state: body.status === "approved" ? "operator_authorized" : "operator_cancelled",
      authorized_at: new Date().toISOString(),
      revalidated_at: new Date().toISOString(),
      revalidation: body.status === "approved"
        ? "Target and organization ownership revalidated immediately before authorization."
        : "No target revalidation was required for cancellation.",
      authorized_by: user.id,
    };

    const result = {
      ...(existing.result ?? {}),
      state: body.status === "approved" ? "approved_for_execution" : "cancelled_by_operator",
      message: body.status === "approved"
        ? "Action is authorized. External execution remains disabled until a provider-specific executor is configured."
        : "Action was cancelled by the operator.",
    };

    const { data, error } = await supabase
      .from("security_actions")
      .update({
        status: body.status,
        authorization,
        result,
      })
      .eq("id", body.id)
      .eq("organization_id", organizationId)
      .select("id,finding_id,action_type,status,target,authorization,result,created_at,executed_at")
      .single();

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    await supabase.from("security_memory").insert({
      organization_id: organizationId,
      memory_type: "operator_decision",
      subject_id: data.id,
      title: body.status === "approved" ? "Operator authorized a security action" : "Operator cancelled a security action",
      summary: body.status === "approved"
        ? `The operator authorized ${data.action_type}. No external action was executed by SentinelX.`
        : `The operator cancelled ${data.action_type}. No external action was executed by SentinelX.`,
      data: {
        action_id: data.id,
        finding_id: data.finding_id,
        action_type: data.action_type,
        status: data.status,
        authorization: data.authorization,
        historical_pattern_context: Array.isArray((data.result as Record<string, unknown> | null)?.historical_pattern_context)
          ? (data.result as Record<string, unknown>).historical_pattern_context
          : [],
      },
    });

    return NextResponse.json({
      action: data,
      message: body.status === "approved"
        ? "Action authorized. No external action has been executed."
        : "Action cancelled.",
    });
  } catch {
    return NextResponse.json({ error: "Security action could not be updated." }, { status: 500 });
  }
}
