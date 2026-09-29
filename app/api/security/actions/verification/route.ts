import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

const VERIFICATION_STATES = ["resolved", "persisting", "returned", "unknown"] as const;
type VerificationState = (typeof VERIFICATION_STATES)[number];

type VerificationBody = {
  actionId?: string;
  state?: VerificationState;
  summary?: string;
  evidence?: Array<{
    type?: string;
    source?: string;
    summary?: string;
    reference?: string;
  }>;
  currentSecurityState?: string;
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

    const body = (await request.json()) as VerificationBody;
    const actionId = body.actionId?.trim();
    const state = body.state;
    const summary = body.summary?.trim();

    if (!actionId || !state || !VERIFICATION_STATES.includes(state)) {
      return NextResponse.json(
        {
          error:
            "actionId and a valid resolved/persisting/returned/unknown state are required.",
        },
        { status: 400 },
      );
    }

    if (!summary) {
      return NextResponse.json(
        { error: "A verification summary is required." },
        { status: 400 },
      );
    }

    const evidence = Array.isArray(body.evidence)
      ? body.evidence
          .slice(0, 50)
          .map((item) => ({
            type: item?.type?.trim() || "verification",
            source: item?.source?.trim() || "operator_verification",
            summary: item?.summary?.trim() || "",
            reference: item?.reference?.trim() || "",
          }))
          .filter((item) => item.summary || item.reference)
      : [];

    if (evidence.length === 0) {
      return NextResponse.json(
        { error: "At least one explicit verification evidence record is required." },
        { status: 400 },
      );
    }

    const { data: action, error: actionError } = await supabase
      .from("security_actions")
      .select("id,finding_id,action_type,status,result,target")
      .eq("id", actionId)
      .eq("organization_id", organizationId)
      .maybeSingle();

    if (actionError) {
      return NextResponse.json({ error: actionError.message }, { status: 500 });
    }

    if (!action) {
      return NextResponse.json({ error: "Security action not found." }, { status: 404 });
    }

    if (!["completed", "failed"].includes(action.status)) {
      return NextResponse.json(
        {
          error:
            "Verification is available only after an explicit completed or failed execution outcome.",
        },
        { status: 409 },
      );
    }

    const findingSnapshot = action.finding_id
      ? await supabase
          .from("security_findings")
          .select("id,asset_id,title,severity,status")
          .eq("id", action.finding_id)
          .eq("organization_id", organizationId)
          .maybeSingle()
      : { data: null, error: null };

    if (findingSnapshot.error) {
      return NextResponse.json(
        { error: findingSnapshot.error.message },
        { status: 500 },
      );
    }

    if (action.finding_id && !findingSnapshot.data) {
      return NextResponse.json(
        { error: "The linked finding is no longer available in this organization." },
        { status: 409 },
      );
    }

    const verification = {
      state,
      summary,
      current_security_state: body.currentSecurityState?.trim() || null,
      evidence,
      finding_snapshot: findingSnapshot.data
        ? {
            id: findingSnapshot.data.id,
            asset_id: findingSnapshot.data.asset_id,
            title: findingSnapshot.data.title,
            severity: findingSnapshot.data.severity,
            status: findingSnapshot.data.status,
          }
        : null,
      ...(body.result ?? {}),
    };

    const { data, error } = await supabase.rpc(
      "record_security_action_verification",
      {
        p_action_id: action.id,
        p_state: state,
        p_summary: summary,
        p_evidence: evidence,
        p_verification: verification,
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
        { error: "Security response verification could not be recorded.", details: error.message },
        { status: 500 },
      );
    }

    const result = data as {
      verification?: Record<string, unknown>;
      action?: Record<string, unknown>;
      memory?: Record<string, unknown>;
    };

    return NextResponse.json({ error: updateError.message }, { status: 500 });
    }

    const { data: memory, error: memoryError } = await supabase
      .from("security_memory")
      .insert({
        organization_id: organizationId,
        memory_type: "verification",
        subject_id: action.id,
        title:
          state === "resolved"
            ? "Security response verified as resolved"
            : state === "persisting"
              ? "Security condition verified as persisting"
              : state === "returned"
                ? "Security condition verified as returned"
                : "Security response verification recorded",
        summary,
        state,
        data: {
          action_id: action.id,
          finding_id: action.finding_id,
          action_type: action.action_type,
          verification,
          memory_reason:
            "Created from explicit post-response verification evidence; it is part of the existing security_memory timeline.",
        },
        occurred_at: new Date().toISOString(),
      })
      .select("id,memory_type,subject_id,title,summary,state,data,occurred_at")
      .single();

    if (memoryError) {
      return NextResponse.json({ error: memoryError.message }, { status: 500 });
    }

    return NextResponse.json({
      verification,
      memory,
      message:
        "Post-response verification recorded in the existing Trinorin security memory.",
    });
  } catch {
    return NextResponse.json(
      { error: "Security response verification could not be recorded." },
      { status: 500 },
    );
  }
}
