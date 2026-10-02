import { NextResponse } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { normalizeSecurityEvent } from "@/lib/security/normalize";
import { runSecurityAnalysis } from "@/lib/security/analysis";

const MAX_BODY_BYTES = 1_000_000;
async function hmacSha256(secret: string, value: string) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return Array.from(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)))).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function safeEqual(left: string, right: string) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i += 1) difference |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return difference === 0;
}
export async function POST(request: Request) {
  try {
    const contentLength = Number(request.headers.get("content-length") ?? "0");
    if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) return NextResponse.json({ error: "Webhook payload is too large." }, { status: 413 });
    const signingSecret = process.env.SLACK_SIGNING_SECRET;
    if (!signingSecret) return NextResponse.json({ error: "Slack webhook verification is not configured." }, { status: 503 });
    const timestamp = request.headers.get("x-slack-request-timestamp") ?? "";
    const signature = request.headers.get("x-slack-signature") ?? "";
    const timestampSeconds = Number(timestamp);
    if (!/^v0=[0-9a-f]{64}$/i.test(signature) || !/^\d+$/.test(timestamp)) return NextResponse.json({ error: "Invalid Slack request signature." }, { status: 401 });
    if (!Number.isFinite(timestampSeconds) || Math.abs(Date.now() / 1000 - timestampSeconds) > 300) return NextResponse.json({ error: "Expired Slack webhook request." }, { status: 401 });
    const rawBody = await request.text();
    const expected = "v0=" + await hmacSha256(signingSecret, "v0:" + timestamp + ":" + rawBody);
    if (!safeEqual(signature, expected)) return NextResponse.json({ error: "Invalid Slack request signature." }, { status: 401 });
    const body = JSON.parse(rawBody) as Record<string, unknown>;
    if (body.type === "url_verification" && typeof body.challenge === "string") return NextResponse.json({ challenge: body.challenge });
    if (body.type !== "event_callback") return NextResponse.json({ accepted: true, ignored: true });
    const integrationId = new URL(request.url).searchParams.get("integrationId")?.trim() ?? "";
    const teamId = typeof body.team_id === "string" ? body.team_id : "";
    const eventId = typeof body.event_id === "string" ? body.event_id : "";
    const event = body.event && typeof body.event === "object" && !Array.isArray(body.event) ? body.event as Record<string, unknown> : {};
    if (!integrationId || !eventId || !teamId) return NextResponse.json({ error: "Slack webhook identity is incomplete." }, { status: 400 });
    const admin = createAdminClient();
    const { data: integration } = await admin.from("security_integrations").select("id,organization_id,provider,integration_type,configuration").eq("id", integrationId).maybeSingle();
    if (!integration || integration.provider !== "Slack" || integration.integration_type !== "slack") return NextResponse.json({ error: "Slack integration was not found." }, { status: 404 });
    const configuration = integration.configuration && typeof integration.configuration === "object" && !Array.isArray(integration.configuration) ? integration.configuration as Record<string, unknown> : {};
    const authorization = configuration.authorization && typeof configuration.authorization === "object" && !Array.isArray(configuration.authorization) ? configuration.authorization as Record<string, unknown> : {};
    const identity = authorization.identity && typeof authorization.identity === "object" && !Array.isArray(authorization.identity) ? authorization.identity as Record<string, unknown> : {};
    if (typeof identity.team_id === "string" && identity.team_id && identity.team_id !== teamId) return NextResponse.json({ error: "Slack workspace does not match the authorized integration." }, { status: 403 });
    const { data: duplicate } = await admin.from("security_evidence").select("id").eq("organization_id", integration.organization_id).eq("source", "slack_events").contains("data", { slack_event_id: eventId }).limit(1).maybeSingle();
    if (duplicate) return NextResponse.json({ accepted: true, duplicate: true, evidenceId: duplicate.id });
    const eventType = typeof event.type === "string" ? event.type : "unknown";
    const eventText = typeof event.text === "string" ? event.text : "";
    const channelId = typeof event.channel === "string" ? event.channel : null;
    const userId = typeof event.user === "string" ? event.user : null;
    const observedAt = typeof event.event_ts === "string" && /^\d+(\.\d+)?$/.test(event.event_ts) ? new Date(Number(event.event_ts) * 1000).toISOString() : new Date().toISOString();
    const title = "Slack event: " + eventType;
    const summary = eventText ? eventText.slice(0, 5000) : "Authorized Slack " + eventType + " event received from workspace " + teamId + ".";
    const normalized = normalizeSecurityEvent({ event_type: "slack." + eventType, severity: "info", source: "slack_events", title, description: summary, observed_at: observedAt, indicators: [] });
    const { data: evidence, error: evidenceError } = await admin.from("security_evidence").insert({ organization_id: integration.organization_id, evidence_type: "application", source: "slack_events", title, summary, data: { slack_event_id: eventId, slack_event_type: eventType, workspace_id: teamId, channel_id: channelId, user_id: userId, text: eventText || null, event }, observed_at: observedAt }).select("id,observed_at").single();
    if (evidenceError || !evidence) return NextResponse.json({ error: "Slack evidence could not be recorded." }, { status: 500 });
    const { data: securityEvent, error: eventError } = await admin.from("security_events").insert({ organization_id: integration.organization_id, event_type: normalized.eventType, severity: normalized.severity, source: normalized.source, title: normalized.title, description: normalized.description, observed_at: normalized.observedAt, evidence: { evidence_id: evidence.id, provider: "slack", slack_event_id: eventId, slack_event_type: eventType, workspace_id: teamId, channel_id: channelId, user_id: userId }, raw_reference: evidence.id }).select("id").single();
    if (eventError || !securityEvent) return NextResponse.json({ error: "Slack evidence was recorded but the security event could not be created." }, { status: 500 });
    await admin.from("security_integrations").update({ status: "connected", last_sync_at: observedAt, configuration: { ...configuration, connection_state: "ingestion_active", last_ingestion_at: new Date().toISOString() } }).eq("id", integration.id).eq("organization_id", integration.organization_id);
    let analysisTriggered = false;
    let analysisError: string | null = null;
    try { await runSecurityAnalysis(admin, integration.organization_id); analysisTriggered = true; } catch (error) { analysisError = error instanceof Error ? error.message : "Security analysis could not be completed."; }
    return NextResponse.json({ accepted: true, eventId: securityEvent.id, evidenceId: evidence.id, analysisTriggered, ...(analysisError ? { analysisError } : {}) });
  } catch {
    return NextResponse.json({ error: "Invalid Slack webhook request." }, { status: 400 });
  }
}