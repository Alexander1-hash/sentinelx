import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

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

    return NextResponse.json({ actions: data ?? [] });
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

    const target = body.target ?? {};
    const reason = body.reason?.trim() || "Operator-requested security action.";

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
      .select("id,action_type,status,authorization,result")
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

    const authorization = {
      ...(existing.authorization ?? {}),
      state: body.status === "approved" ? "operator_authorized" : "operator_cancelled",
      authorized_at: new Date().toISOString(),
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
