import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import {
  getExecutorAdapter,
  getExecutorRequirement,
  validateExecutionTarget,
  isMutatingSecurityAction,
} from "@/lib/security/executors";

const EXECUTOR_TYPE = "provider_webhook";
const TIMEOUT_MS = 15000;

function hostAllowed(hostname: string) {
  const configured = process.env.TRINORIN_EXECUTOR_WEBHOOK_HOSTS
    ?.split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);

  return Boolean(configured?.length && configured.includes(hostname.toLowerCase()));
}

async function hmacSha256(secret: string, body: string) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  return Array.from(new Uint8Array(signature))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function getContext() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

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
      return NextResponse.json({ error: "Authentication and organization are required." }, { status: 401 });
    }

    const body = await request.json();
    const actionId = typeof body.actionId === "string" ? body.actionId.trim() : "";

    if (!actionId) {
      return NextResponse.json({ error: "actionId is required." }, { status: 400 });
    }

    const { data: action, error: actionError } = await supabase
      .from("security_actions")
      .select("id,organization_id,finding_id,action_type,status,target,authorization,result")
      .eq("id", actionId)
      .eq("organization_id", organizationId)
      .maybeSingle();

    if (actionError) return NextResponse.json({ error: actionError.message }, { status: 500 });
    if (!action) return NextResponse.json({ error: "Security action not found." }, { status: 404 });

    if (action.status !== "approved" || action.authorization?.state !== "operator_authorized") {
      return NextResponse.json(
        { error: "Automated execution is blocked until the action is explicitly authorized." },
        { status: 409 },
      );
    }

    if (!isMutatingSecurityAction(action.action_type)) {
      return NextResponse.json(
        { error: "This action type does not require automated provider execution." },
        { status: 400 },
      );
    }

    const adapter = getExecutorAdapter(EXECUTOR_TYPE, action.action_type);
    if (!adapter || adapter.mode !== "provider") {
      return NextResponse.json({ error: "Provider executor is not enabled for this action." }, { status: 409 });
    }

    const requirement = getExecutorRequirement(action.action_type);
    const targetValidation = validateExecutionTarget(action.action_type, action.target);

    if (!targetValidation.valid) {
      return NextResponse.json({ error: targetValidation.error }, { status: 409 });
    }

    const target = targetValidation.target;
    if (!target.integrationId) {
      return NextResponse.json(
        { error: "Automated execution requires an explicitly selected provider integration target." },
        { status: 409 },
      );
    }

    const { data: integration, error: integrationError } = await supabase
      .from("security_integrations")
      .select("id,provider,integration_type,status,configuration")
      .eq("id", target.integrationId)
      .eq("organization_id", organizationId)
      .maybeSingle();

    if (integrationError) return NextResponse.json({ error: integrationError.message }, { status: 500 });
    if (!integration) return NextResponse.json({ error: "The provider integration target was not found." }, { status: 409 });
    if (integration.status !== "connected") {
      return NextResponse.json({ error: "The provider integration target is not connected." }, { status: 409 });
    }
    if (requirement && !requirement.requiredIntegrationTypes.includes(integration.integration_type)) {
      return NextResponse.json({ error: "The provider integration type is not permitted for this action." }, { status: 409 });
    }

    const configuration = (integration.configuration ?? {}) as Record<string, unknown>;
    const execution = configuration.execution as Record<string, unknown> | undefined;
    const webhookUrl = typeof execution?.webhook_url === "string" ? execution.webhook_url.trim() : "";

    if (!webhookUrl) {
      return NextResponse.json(
        { error: "This connected integration has no configured provider execution webhook." },
        { status: 409 },
      );
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(webhookUrl);
    } catch {
      return NextResponse.json({ error: "The provider execution webhook URL is invalid." }, { status: 409 });
    }

    if (parsedUrl.protocol !== "https:") {
      return NextResponse.json({ error: "Provider execution webhooks must use HTTPS." }, { status: 409 });
    }

    if (!hostAllowed(parsedUrl.hostname)) {
      return NextResponse.json(
        { error: "The provider webhook host is not on the Trinorin execution allowlist." },
        { status: 409 },
      );
    }

    const secret = process.env.TRINORIN_EXECUTOR_WEBHOOK_SECRET;
    if (!secret) {
      return NextResponse.json(
        { error: "The provider executor secret is not configured in the deployment environment." },
        { status: 503 },
      );
    }

    const requestedAt = new Date().toISOString();
    const payload = {
      version: 1,
      event: "security_action.execute",
      actionId: action.id,
      organizationId,
      findingId: action.finding_id,
      actionType: action.action_type,
      target,
      provider: integration.provider,
      integrationId: integration.id,
      requestedAt,
      boundary:
        "Provider execution was explicitly authorized by an operator and is limited to the validated target. The provider response is the source of execution outcome.",
    };
    const serialized = JSON.stringify(payload);
    const signature = await hmacSha256(secret, serialized);

    let providerResponse: Response;
    try {
      providerResponse = await fetch(webhookUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-trinorin-executor": EXECUTOR_TYPE,
          "x-trinorin-action-id": action.id,
          "x-trinorin-signature": signature,
        },
        body: serialized,
        signal: AbortSignal.timeout(TIMEOUT_MS),
        cache: "no-store",
      });
    } catch {
      return NextResponse.json(
        { error: "The provider executor could not reach the configured webhook. No execution outcome was recorded." },
        { status: 504 },
      );
    }

    const responseText = await providerResponse.text();
    let providerBody: Record<string, unknown> = {};
    try {
      const parsed = JSON.parse(responseText);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) providerBody = parsed;
    } catch {
      providerBody = { response: responseText.slice(0, 4000) };
    }

    if (!providerResponse.ok) {
      return NextResponse.json(
        {
          error: "The provider rejected the automated execution request.",
          providerStatus: providerResponse.status,
          providerResponse: providerBody,
        },
        { status: 502 },
      );
    }

    const executionReference =
      typeof providerBody.executionReference === "string" && providerBody.executionReference.trim()
        ? providerBody.executionReference.trim()
        : `provider:${integration.provider}:${action.id}:${Date.now()}`;

    const evidence = [{
      type: "provider_execution",
      source: integration.provider,
      summary:
        typeof providerBody.summary === "string" && providerBody.summary.trim()
          ? providerBody.summary.trim()
          : `Provider accepted automated ${action.action_type} execution for the authorized target.`,
      reference: executionReference,
    }];

    const resultPayload = {
      provider_response: providerBody,
      provider_http_status: providerResponse.status,
      execution_target: target,
      target_scope_verified: true,
      target_scope_source: "authorized_security_action",
      executor_mode: "provider",
      executor_type: EXECUTOR_TYPE,
    };

    const { data, error: outcomeError } = await supabase.rpc(
      "record_security_action_outcome",
      {
        p_action_id: action.id,
        p_status: "completed",
        p_executor_type: EXECUTOR_TYPE,
        p_execution_reference: executionReference,
        p_evidence: evidence,
        p_result: resultPayload,
      },
    );

    if (outcomeError) {
      return NextResponse.json(
        { error: "Provider execution completed, but Trinorin could not record the outcome.", details: outcomeError.message },
        { status: 500 },
      );
    }

    return NextResponse.json({
      ok: true,
      status: "completed",
      executorType: EXECUTOR_TYPE,
      executionReference,
      provider: integration.provider,
      action: data,
      boundary:
        "The provider accepted the authorized execution request. Trinorin records the provider response as evidence; post-response verification is still required.",
    });
  } catch {
    return NextResponse.json({ error: "Automated provider execution could not be completed." }, { status: 500 });
  }
}
