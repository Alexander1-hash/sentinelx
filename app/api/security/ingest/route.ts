import { NextResponse } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { normalizeSecurityEvent } from "@/lib/security/normalize";
import { runSecurityAnalysis } from "@/lib/security/analysis";

const relationshipTypes = [
  "hosts",
  "resolves_to",
  "depends_on",
  "authenticates_to",
  "connects_to",
  "uses",
  "reads_from",
  "writes_to",
  "calls",
  "protects",
  "managed_by",
  "part_of",
] as const;

const evidenceTypes = [
  "asset_observation",
  "telemetry",
  "identity",
  "network",
  "application",
  "ai_system",
  "ai_agent",
  "relationship_observation",
] as const;

const MAX_BODY_BYTES = 1_000_000;

async function hashToken(token: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function POST(request: Request) {
  try {
    const contentLength = Number(request.headers.get("content-length") ?? "0");
    if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
      return NextResponse.json({ error: "Ingestion payload is too large." }, { status: 413 });
    }

    const authorization = request.headers.get("authorization");
    const token = authorization?.startsWith("Bearer ")
      ? authorization.slice(7).trim()
      : "";

    if (!token.startsWith("sx_ing_")) {
      return NextResponse.json({ error: "Valid ingestion authorization is required." }, { status: 401 });
    }

    const supabase = createAdminClient();
    const tokenHash = await hashToken(token);

    const { data: verified, error: verifyError } = await supabase.rpc(
      "verify_security_ingestion_token",
      { p_token_hash: tokenHash }
    );

    if (verifyError) {
      return NextResponse.json({ error: "Ingestion authentication is not configured." }, { status: 503 });
    }

    const integration = verified?.[0];
    if (!integration) {
      return NextResponse.json({ error: "Invalid or expired ingestion token." }, { status: 401 });
    }

    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return NextResponse.json({ error: "A JSON object is required." }, { status: 400 });
    }

    const payload = body as Record<string, unknown>;
    const evidenceType = typeof payload.evidenceType === "string" ? payload.evidenceType : "";
    const source = typeof payload.source === "string" ? payload.source.trim() : "";
    const title = typeof payload.title === "string" ? payload.title.trim() : "";
    const summary = typeof payload.summary === "string" ? payload.summary.trim() : null;
    const assetId = typeof payload.assetId === "string" ? payload.assetId : null;
    const rawObservedAt = typeof payload.observedAt === "string" ? payload.observedAt.trim() : null;
    const parsedObservedAt = rawObservedAt ? new Date(rawObservedAt) : null;
    if (rawObservedAt && Number.isNaN(parsedObservedAt?.getTime())) {
      return NextResponse.json({ error: "observedAt must be a valid ISO-8601 timestamp." }, { status: 400 });
    }
    const observedAt = parsedObservedAt ? parsedObservedAt.toISOString() : null;
    const data =
      payload.data && typeof payload.data === "object" && !Array.isArray(payload.data)
        ? payload.data
        : {};
    const securityState =
      payload.securityState === "active" ||
      payload.securityState === "degraded" ||
      payload.securityState === "cleared" ||
      payload.securityState === "resolved" ||
      payload.securityState === "healthy"
        ? payload.securityState
        : null;
    const relationships = Array.isArray(payload.observedRelationships)
      ? payload.observedRelationships
      : [];

    if (!evidenceTypes.includes(evidenceType as (typeof evidenceTypes)[number])) {
      return NextResponse.json({ error: "Invalid evidence type." }, { status: 400 });
    }

    if (!source || !title) {
      return NextResponse.json({ error: "Evidence source and title are required." }, { status: 400 });
    }

    if (source.length > 200 || title.length > 300 || (summary && summary.length > 5000)) {
      return NextResponse.json(
        { error: "Evidence source, title, or summary exceeds the allowed length." },
        { status: 400 }
      );
    }

    if (Array.isArray(payload.indicators) && payload.indicators.length > 100) {
      return NextResponse.json({ error: "A maximum of 100 indicators is allowed." }, { status: 400 });
    }

    if (assetId) {
      const { data: asset } = await supabase
        .from("security_assets")
        .select("id")
        .eq("id", assetId)
        .eq("organization_id", integration.organization_id)
        .maybeSingle();

      if (!asset) {
        return NextResponse.json({ error: "Asset is not registered in this organization." }, { status: 403 });
      }
    }

    const previousQuery = supabase
      .from("security_evidence")
      .select("id,asset_id,evidence_type,source,title,summary,data,observed_at,created_at")
      .eq("organization_id", integration.organization_id)
      .eq("evidence_type", evidenceType)
      .eq("source", source)
      .eq("title", title)
      .order("observed_at", { ascending: false })
      .limit(1);

    const { data: previousEvidence } = assetId
      ? await previousQuery.eq("asset_id", assetId)
      : await previousQuery.is("asset_id", null);

    function normalizeValue(value: unknown): unknown {
      if (Array.isArray(value)) return value.map(normalizeValue);
      if (value && typeof value === "object") {
        return Object.fromEntries(
          Object.entries(value as Record<string, unknown>)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([key, entry]) => [key, normalizeValue(entry)])
        );
      }
      return value;
    }

    async function fingerprintEvidence(value: {
      asset_id: string | null;
      evidence_type: string;
      source: string;
      title: string;
      summary: string | null;
      data: unknown;
    }) {
      const canonical = JSON.stringify(normalizeValue(value));
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
      return Array.from(new Uint8Array(digest))
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
    }

    const fingerprintData = {
      ...(data as Record<string, unknown>),
      ...(securityState ? { security_state: securityState } : {}),
    };

    const currentFingerprint = await fingerprintEvidence({
      asset_id: assetId,
      evidence_type: evidenceType,
      source,
      title,
      summary,
      data: fingerprintData,
    });

    const previous = previousEvidence?.[0] ?? null;
    const previousFingerprint = previous
      ? await fingerprintEvidence({
          asset_id: previous.asset_id,
          evidence_type: previous.evidence_type,
          source: previous.source,
          title: previous.title,
          summary: previous.summary,
          data: previous.data,
        })
      : null;

    const previousSecurityState =
      previous?.data &&
      typeof previous.data === "object" &&
      !Array.isArray(previous.data) &&
      "security_state" in previous.data
        ? typeof (previous.data as Record<string, unknown>).security_state === "string"
          ? (previous.data as Record<string, unknown>).security_state as string
          : null
        : null;

    const isExplicitResolution =
      securityState !== null &&
      ["cleared", "resolved", "healthy"].includes(securityState) &&
      ["active", "degraded"].includes(previousSecurityState ?? "");

    const changeType = !previous
      ? "new"
      : isExplicitResolution
        ? "resolved"
        : previousFingerprint === currentFingerprint
          ? "unchanged"
          : "changed";

    if (changeType === "unchanged" && previous?.id) {
      let unchangedEventQuery = supabase
        .from("security_events")
        .select("id,event_type,severity,source,title,description,asset_id,observed_at,created_at")
        .eq("organization_id", integration.organization_id)
        .eq("source", source)
        .eq("title", title)
        .contains("evidence", { evidence_id: previous.id })
        .order("observed_at", { ascending: false })
        .limit(1);

      unchangedEventQuery = assetId
        ? unchangedEventQuery.eq("asset_id", assetId)
        : unchangedEventQuery.is("asset_id", null);

      const { data: unchangedEvents } = await unchangedEventQuery;
      const unchangedEvent = unchangedEvents?.[0];

      if (unchangedEvent) {
        const syncTimestamp = new Date().toISOString();

        await supabase
          .from("security_integrations")
          .update({
            status: "connected",
            last_sync_at: syncTimestamp,
            ingestion_token_last_used_at: syncTimestamp,
          })
          .eq("id", integration.integration_id)
          .eq("organization_id", integration.organization_id);

        if (assetId) {
          await supabase
            .from("security_assets")
            .update({ last_seen_at: observedAt ?? syncTimestamp })
            .eq("id", assetId)
            .eq("organization_id", integration.organization_id);
        }

        return NextResponse.json(
          {
            accepted: true,
            eventId: unchangedEvent.id,
            evidenceId: previous.id,
            event: unchangedEvent,
            discoveredRelationships: 0,
            analysisTriggered: false,
            findingsCreated: 0,
            findings: [],
            message:
              "Telemetry matched the previously recorded evidence state. SentinelX kept the existing event identity and did not create duplicate analysis activity.",
          },
          { status: 200 }
        );
      }
    }

    const normalizedEvent = normalizeSecurityEvent({
      event_type:
        typeof payload.eventType === "string"
          ? payload.eventType
          : typeof payload.event_type === "string"
            ? payload.event_type
            : evidenceType,
      severity:
        typeof payload.severity === "string"
          ? payload.severity
          : typeof (data as Record<string, unknown>).severity === "string"
            ? (data as Record<string, unknown>).severity
            : "info",
      source,
      title,
      description: summary,
      asset_id: assetId,
      observed_at: observedAt ?? undefined,
      indicators: Array.isArray(payload.indicators) ? payload.indicators : [],
    });

    const { data: evidence, error: evidenceError } = await supabase
      .from("security_evidence")
      .insert({
        organization_id: integration.organization_id,
        asset_id: assetId,
        evidence_type: evidenceType,
        source,
        title,
        summary,
        data: {
          ...(data as Record<string, unknown>),
          ...(securityState ? { security_state: securityState } : {}),
          normalized_event: normalizedEvent,
        },
        ...(observedAt ? { observed_at: observedAt } : {}),
      })
      .select("id,asset_id,evidence_type,source,title,summary,data,observed_at,created_at")
      .single();

    if (evidenceError) {
      return NextResponse.json({ error: evidenceError.message }, { status: 500 });
    }

    const { data: securityEvent, error: eventError } = await supabase
      .from("security_events")
      .insert({
        organization_id: integration.organization_id,
        asset_id: normalizedEvent.assetId,
        event_type: normalizedEvent.eventType,
        severity: normalizedEvent.severity,
        source: normalizedEvent.source,
        title: normalizedEvent.title,
        description: normalizedEvent.description,
        observed_at: normalizedEvent.observedAt,
        evidence: {
          evidence_id: evidence.id,
          evidence_type: evidenceType,
          indicators: normalizedEvent.indicators,
          change_type: changeType,
          integration_id: integration.integration_id,
        },
        raw_reference:
          typeof payload.rawReference === "string" ? payload.rawReference : evidence.id,
      })
      .select("id,event_type,severity,source,title,description,asset_id,observed_at,created_at")
      .single();

    if (eventError) {
      return NextResponse.json(
        { error: "Evidence was recorded, but the security event could not be registered." },
        { status: 500 }
      );
    }

    let discoveredRelationships = 0;

    for (const item of relationships) {
      if (!item || typeof item !== "object") continue;

      const relationship = item as Record<string, unknown>;
      const sourceAssetId =
        typeof relationship.sourceAssetId === "string" ? relationship.sourceAssetId : "";
      const targetAssetId =
        typeof relationship.targetAssetId === "string" ? relationship.targetAssetId : "";
      const relationshipType =
        typeof relationship.relationshipType === "string" ? relationship.relationshipType : "";
      const confidence =
        typeof relationship.confidence === "number" ? relationship.confidence : 0.5;
      const reason =
        typeof relationship.reason === "string"
          ? relationship.reason
          : "Observed relationship supplied by an authorized telemetry source.";

      if (
        !sourceAssetId ||
        !targetAssetId ||
        sourceAssetId === targetAssetId ||
        !relationshipTypes.includes(relationshipType as (typeof relationshipTypes)[number]) ||
        confidence < 0 ||
        confidence > 1
      ) {
        continue;
      }

      const { data: assets } = await supabase
        .from("security_assets")
        .select("id")
        .eq("organization_id", integration.organization_id)
        .in("id", [sourceAssetId, targetAssetId]);

      if ((assets ?? []).length !== 2) continue;

      const { error } = await supabase
        .from("security_asset_relationships")
        .upsert(
          {
            organization_id: integration.organization_id,
            source_asset_id: sourceAssetId,
            target_asset_id: targetAssetId,
            relationship_type: relationshipType,
            confidence,
            status: "proposed",
            evidence_source: source,
            discovered_at: new Date().toISOString(),
            evidence: {
              source: "telemetry_ingestion",
              evidence_id: evidence.id,
              reason,
            },
          },
          {
            onConflict: "source_asset_id,target_asset_id,relationship_type",
            ignoreDuplicates: false,
          }
        );

      if (!error) discoveredRelationships += 1;
    }

    if (changeType !== "unchanged") {
      const isChanged = changeType === "changed";
      const isResolved = changeType === "resolved";

      await supabase.from("security_memory").insert({
        organization_id: integration.organization_id,
        memory_type: "evidence_change",
        subject_id: evidence.id,
        title: isResolved
          ? `Evidence resolved: ${title}`
          : isChanged
            ? `Evidence changed: ${title}`
            : `New evidence: ${title}`,
        summary: isResolved
          ? "The authorized source explicitly reported a resolved or cleared state for this evidence pattern."
          : isChanged
            ? `Recorded evidence changed from the previous observed state for ${source}.`
            : (summary ?? `New ${evidenceType} evidence was received from ${source}.`),
        state: "active",
        data: {
          evidence_id: evidence.id,
          security_event_id: securityEvent.id,
          previous_evidence_id: previous?.id ?? null,
          asset_id: assetId,
          evidence_type: evidenceType,
          source,
          title,
          observed_at: evidence.observed_at,
          discovered_relationships: discoveredRelationships,
          change_type: changeType,
          fingerprint: currentFingerprint,
          previous_fingerprint: previousFingerprint,
          memory_reason: isResolved
            ? "explicit_evidence_resolution"
            : isChanged
              ? "evidence_state_changed"
              : "new_evidence_observed",
          security_state: securityState,
          severity: normalizedEvent.severity,
          event_type: normalizedEvent.eventType,
        },
        occurred_at: evidence.observed_at ?? normalizedEvent.observedAt,
      });
    }

    if (assetId) {
      await supabase
        .from("security_assets")
        .update({ last_seen_at: normalizedEvent.observedAt })
        .eq("id", assetId)
        .eq("organization_id", integration.organization_id);
    }

    await supabase
      .from("security_integrations")
      .update({
        status: "connected",
        last_sync_at: new Date().toISOString(),
        ingestion_token_last_used_at: new Date().toISOString(),
      })
      .eq("id", integration.integration_id)
      .eq("organization_id", integration.organization_id);

    let analysisTriggered = false;
    let analysisError: string | null = null;
    let findingsCreated = 0;
    let findings: Array<{ id: string; title: string; severity: string }> = [];

    try {
      const analysisResult = await runSecurityAnalysis(supabase, integration.organization_id);
      analysisTriggered = true;
      findingsCreated = analysisResult.findingsCreated;
      findings = analysisResult.findings;
    } catch (error) {
      analysisError = error instanceof Error ? error.message : "Security analysis could not be completed.";
    }

    return NextResponse.json(
      {
        accepted: true,
        eventId: securityEvent.id,
        evidenceId: evidence.id,
        event: securityEvent,
        discoveredRelationships,
        analysisTriggered,
        findingsCreated,
        findings,
        ...(analysisError ? { analysisError } : {}),
        message:
          "Telemetry accepted. The normalized event is now available to SentinelX security intelligence; relationship candidates remain unconfirmed until reviewed.",
      },
      { status: 201 }
    );
  } catch {
    return NextResponse.json({ error: "Invalid ingestion request." }, { status: 400 });
  }
}
