import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { getExecutorAdapter, getExecutorRequirement, validateExecutionTarget } from "@/lib/security/executors";

const OUTCOME_STATUSES = ["completed", "failed"] as const;
type OutcomeStatus = (typeof OUTCOME_STATUSES)[number];

type OutcomeBody = {
  actionId?: string;
  status?: OutcomeStatus;
  executorType?: string;
  executionReference?: string;
  evidence?: Array<{
    type?: string;
    source?: string;
    summary?: string;
    reference?: string;
  }>;
  result?: Record<string, unknown>;
};

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

export async function POST(request: Request) {
  try {
    const { supabase, user, organizationId } = await getContext();

    if (!user || !organizationId) {
      return NextResponse.json(
        { error: "Authentication and organization are required." },
        { status: 401 },
      );
    }

    const body = (await request.json()) as OutcomeBody;
    const actionId = body.actionId?.trim();
    const executorType = body.executorType?.trim();
    const executionReference = body.executionReference?.trim();
    const status = body.status;

    if (!actionId || !status || !OUTCOME_STATUSES.includes(status)) {
      return NextResponse.json(
        { error: "actionId and a valid completed/failed status are required." },
        { status: 400 },
      );
    }

    if (!executorType || !executionReference) {
      return NextResponse.json(
        {
          error:
            "executorType and executionReference are required to record an execution outcome.",
        },
        { status: 400 },
      );
    }

    const evidence = Array.isArray(body.evidence)
      ? body.evidence
          .slice(0, 50)
          .map((item) => ({
            type: item?.type?.trim() || "executor_result",
            source: item?.source?.trim() || executorType,
            summary: item?.summary?.trim() || "",
            reference: item?.reference?.trim() || executionReference,
          }))
          .filter((item) => item.summary || item.reference)
      : [];

    if (evidence.length === 0) {
      return NextResponse.json(
        { error: "At least one explicit evidence record is required." },
        { status: 400 },
      );
    }

    const { data: action, error: actionLookupError } = await supabase
      .from("security_actions")
      .select("id,action_type,status,target,authorization")
      .eq("id", actionId)
      .eq("organization_id", organizationId)
      .maybeSingle();

    if (actionLookupError) {
      return NextResponse.json({ error: actionLookupError.message }, { status: 500 });
    }

    if (!action) {
      return NextResponse.json({ error: "Security action not found." }, { status: 404 });
    }

    if (action.status !== "approved" || action.authorization?.state !== "operator_authorized") {
      return NextResponse.json(
        { error: "Execution is blocked until the action is explicitly authorized." },
        { status: 409 },
      );
    }

    const targetValidation = validateExecutionTarget(action.action_type, action.target);
    if (!targetValidation.valid) {
      return NextResponse.json({ error: targetValidation.error }, { status: 409 });
    }

    const authorizedAdapter = getExecutorAdapter(executorType, action.action_type);
    if (!authorizedAdapter) {
      return NextResponse.json(
        { error: "The requested executor is not enabled for this action type." },
        { status: 400 },
      );
    }

    const requirement = getExecutorRequirement(action.action_type);
    const target = targetValidation.target;

    // Resource-level authorization: the outcome endpoint trusts only the target
    // stored on the already-authorized action, then proves known SentinelX
    // resources belong to the current organization before recording an outcome.
    if (target.assetId) {
      const { data: asset, error: assetError } = await supabase
        .from("security_assets")
        .select("id")
        .eq("id", target.assetId)
        .eq("organization_id", organizationId)
        .maybeSingle();

      if (assetError) {
        return NextResponse.json({ error: assetError.message }, { status: 500 });
      }

      if (!asset) {
        return NextResponse.json(
          { error: "The authorized asset target was not found in this organization." },
          { status: 409 },
        );
      }
    }

    if (target.resourceId) {
      const resourceType = target.resourceType?.trim().toLowerCase();

      if (resourceType === "asset") {
        const { data: asset, error: assetError } = await supabase
          .from("security_assets")
          .select("id")
          .eq("id", target.resourceId)
          .eq("organization_id", organizationId)
          .maybeSingle();

        if (assetError) {
          return NextResponse.json({ error: assetError.message }, { status: 500 });
        }

        if (!asset) {
          return NextResponse.json(
            { error: "The authorized resource target was not found in this organization." },
            { status: 409 },
          );
        }
      } else if (resourceType === "finding") {
        const { data: finding, error: findingError } = await supabase
          .from("security_findings")
          .select("id")
          .eq("id", target.resourceId)
          .eq("organization_id", organizationId)
          .maybeSingle();

        if (findingError) {
          return NextResponse.json({ error: findingError.message }, { status: 500 });
        }

        if (!finding) {
          return NextResponse.json(
            { error: "The authorized finding target was not found in this organization." },
            { status: 409 },
          );
        }
      } else if (resourceType === "integration") {
        const { data: integration, error: integrationError } = await supabase
          .from("security_integrations")
          .select("id")
          .eq("id", target.resourceId)
          .eq("organization_id", organizationId)
          .maybeSingle();

        if (integrationError) {
          return NextResponse.json({ error: integrationError.message }, { status: 500 });
        }

        if (!integration) {
          return NextResponse.json(
            { error: "The authorized integration resource was not found in this organization." },
            { status: 409 },
          );
        }
      } else {
        return NextResponse.json(
          { error: "The authorized resource target type cannot be verified by SentinelX." },
          { status: 409 },
        );
      }
    }

    if (target.integrationId) {
      const { data: integration, error: integrationError } = await supabase
        .from("security_integrations")
        .select("id,integration_type,provider,status")
        .eq("id", target.integrationId)
        .eq("organization_id", organizationId)
        .maybeSingle();

      if (integrationError) {
        return NextResponse.json({ error: integrationError.message }, { status: 500 });
      }

      if (!integration) {
        return NextResponse.json({ error: "The authorized integration target was not found in this organization." }, { status: 409 });
      }

      if (integration.status !== "connected") {
        return NextResponse.json({ error: "The authorized integration target is not currently connected." }, { status: 409 });
      }

      if (requirement && !requirement.requiredIntegrationTypes.includes(integration.integration_type)) {
        return NextResponse.json({ error: "The authorized integration type is not permitted for this action." }, { status: 409 });
      }
    }

    const { data, error } = await supabase.rpc(
      "record_security_action_outcome",
      {
        p_action_id: actionId,
        p_status: status,
        p_executor_type: executorType,
        p_execution_reference: executionReference,
        p_evidence: evidence,
        p_result: {
          ...(body.result ?? {}),
          execution_target: targetValidation.target,
          target_scope_verified: true,
          target_scope_source: "authorized_security_action",
        },
      },
    );

    if (error) {
      if (error.code === "42501") {
        return NextResponse.json({ error: error.message }, { status: 401 });
      }

      if (error.code === "P0002") {
        return NextResponse.json({ error: error.message }, { status: 404 });
      }

      if (error.code === "55000") {
        return NextResponse.json({ error: error.message }, { status: 409 });
      }

      if (error.code === "22023") {
        return NextResponse.json({ error: error.message }, { status: 400 });
      }

      return NextResponse.json(
        { error: "Security action outcome could not be recorded.", details: error.message },
        { status: 500 },
      );
    }

    const result = data as {
      action?: Record<string, unknown>;
      memory?: Record<string, unknown>;
    };

    return NextResponse.json({
      action: result.action,
      memory: result.memory,
      message:
        status === "completed"
          ? "Verified response outcome recorded as completed."
          : "Verified response outcome recorded as failed.",
    });
  } catch {
    return NextResponse.json(
      { error: "Security action outcome could not be recorded." },
      { status: 500 },
    );
  }
}
