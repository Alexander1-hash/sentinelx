import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

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

  return { supabase, user, organizationId: profile?.organization_id ?? null };
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
        { error: "executorType and executionReference are required to record an execution outcome." },
        { status: 400 },
      );
    }

    const evidence = Array.isArray(body.evidence)
      ? body.evidence.slice(0, 50).map((item) => ({
          type: item?.type?.trim() || "executor_result",
          source: item?.source?.trim() || executorType,
          summary: item?.summary?.trim() || "",
          reference: item?.reference?.trim() || executionReference,
        }))
      : [];

    if (evidence.length === 0) {
      return NextResponse.json(
        { error: "At least one explicit evidence record is required." },
        { status: 400 },
      );
    }

    const { data: action, error: actionError } = await supabase
      .from("security_actions")
      .select("id,finding_id,action_type,status,target,authorization,result,created_at,executed_at")
      .eq("id", actionId)
      .eq("organization_id", organizationId)
      .maybeSingle();

    if (actionError) {
      return NextResponse.json({ error: actionError.message }, { status: 500 });
    }

    if (!action) {
      return NextResponse.json({ error: "Security action not found." }, { status: 404 });
    }

    if (action.status !== "approved") {
      return NextResponse.json(
        { error: "Only explicitly approved actions can receive an execution outcome." },
        { status: 409 },
      );
    }

    const existingResult =
      action.result && typeof action.result === "object"
        ? (action.result as Record<string, unknown>)
        : {};

    const outcome = {
      state: status,
      executor_type: executorType,
      execution_reference: executionReference,
      evidence,
      supplied_at: new Date().toISOString(),
      supplied_by: user.id,
      boundary:
        "This outcome is recorded from an explicit executor result. SentinelX does not infer execution from approval alone.",
      ...(body.result ?? {}),
    };

    const { data: updatedAction, error: updateError } = await supabase
      .from("security_actions")
      .update({
        status,
        result: {
          ...existingResult,
          state: status,
          response_outcome: outcome,
        },
        executed_at: new Date().toISOString(),
      })
      .eq("id", actionId)
      .eq("organization_id", organizationId)
      .eq("status", "approved")
      .select("id,finding_id,action_type,status,target,authorization,result,created_at,executed_at")
      .single();

    if (updateError) {
      return NextResponse.json({ error: updateError.message }, { status: 500 });
    }

    const { data: memory, error: memoryError } = await supabase
      .from("security_memory")
      .insert({
        organization_id: organizationId,
        memory_type: "response_outcome",
        subject_id: updatedAction.id,
        title:
          status === "completed"
            ? "Security action execution completed"
            : "Security action execution failed",
        summary:
          status === "completed"
            ? updatedAction.action_type + " received a completed result from " + executorType + "."
            : updatedAction.action_type + " received a failed result from " + executorType + ".",
        state: status,
        data: {
          action_id: updatedAction.id,
          finding_id: updatedAction.finding_id,
          action_type: updatedAction.action_type,
          status,
          executor_type: executorType,
          execution_reference: executionReference,
          evidence,
          response_outcome: outcome,
          memory_reason:
            "Created only from an explicit authorized executor result; approval alone is not execution.",
        },
      })
      .select("id,memory_type,subject_id,title,summary,state,data,occurred_at,created_at")
      .single();

    if (memoryError) {
      return NextResponse.json(
        {
          error: "Action outcome was recorded, but the response outcome memory could not be created.",
          action: updatedAction,
          details: memoryError.message,
        },
        { status: 500 },
      );
    }

    return NextResponse.json({
      action: updatedAction,
      memory,
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
