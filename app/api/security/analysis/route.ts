import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

type SecurityEvent = {
  id: string;
  asset_id: string | null;
  event_type: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  source: string;
  title: string;
  description: string | null;
  observed_at: string;
  evidence: Record<string, unknown>;
};

type AiSecurityEvent = {
  id: string;
  system_id: string | null;
  agent_id: string | null;
  event_type: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  title: string;
  description: string | null;
  observed_at: string;
  evidence: Record<string, unknown>;
};

type EvidenceRecord = {
  id: string;
  asset_id: string | null;
  evidence_type: string;
  source: string;
  title: string;
  summary: string | null;
  data: Record<string, unknown>;
  observed_at: string;
};

const severeLevels = new Set(["high", "critical"]);

async function getContext() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

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

async function collectAnalysisContext(supabase: Awaited<ReturnType<typeof createClient>>, organizationId: string) {
  const [eventsResult, aiEventsResult, evidenceResult, relationshipsResult, findingsResult] = await Promise.all([
    supabase
      .from("security_events")
      .select("id,asset_id,event_type,severity,source,title,description,observed_at,evidence")
      .eq("organization_id", organizationId)
      .order("observed_at", { ascending: false })
      .limit(200),
    supabase
      .from("ai_security_events")
      .select("id,system_id,agent_id,event_type,severity,title,description,observed_at,evidence")
      .eq("organization_id", organizationId)
      .order("observed_at", { ascending: false })
      .limit(200),
    supabase
      .from("security_evidence")
      .select("id,asset_id,evidence_type,source,title,summary,data,observed_at")
      .eq("organization_id", organizationId)
      .order("observed_at", { ascending: false })
      .limit(200),
    supabase
      .from("security_asset_relationships")
      .select("id,source_asset_id,target_asset_id,relationship_type,confidence,status,evidence,evidence_source")
      .eq("organization_id", organizationId)
      .eq("status", "confirmed")
      .limit(500),
    supabase
      .from("security_findings")
      .select("id,title,finding_type,severity,status,evidence")
      .eq("organization_id", organizationId)
      .in("status", ["open", "acknowledged"])
      .limit(500),
  ]);

  const error = eventsResult.error ?? aiEventsResult.error ?? evidenceResult.error ?? relationshipsResult.error ?? findingsResult.error;
  if (error) throw new Error(error.message);

  return {
    events: (eventsResult.data ?? []) as SecurityEvent[],
    aiEvents: (aiEventsResult.data ?? []) as AiSecurityEvent[],
    evidence: (evidenceResult.data ?? []) as EvidenceRecord[],
    relationships: relationshipsResult.data ?? [],
    openFindings: findingsResult.data ?? [],
  };
}

export async function GET() {
  try {
    const { supabase, user, organizationId } = await getContext();

    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    if (!organizationId) return NextResponse.json({ findings: [], analysis: null });

    const { data, error } = await supabase
      .from("security_findings")
      .select("id,asset_id,title,finding_type,severity,status,summary,evidence,remediation,detected_at,resolved_at,created_at,updated_at")
      .eq("organization_id", organizationId)
      .order("detected_at", { ascending: false })
      .limit(100);

    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    return NextResponse.json({ findings: data ?? [] });
  } catch {
    return NextResponse.json({ error: "Unable to load Security Brain findings." }, { status: 500 });
  }
}

export async function POST() {
  try {
    const { supabase, user, organizationId } = await getContext();

    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    if (!organizationId) {
      return NextResponse.json({
        findingsCreated: 0,
        analyzed: false,
        message: "No organization is connected, so there is no security evidence to analyze.",
      });
    }

    const context = await collectAnalysisContext(supabase, organizationId);

    const severeEvents = context.events.filter((event) => severeLevels.has(event.severity));
    const severeAiEvents = context.aiEvents.filter((event) => severeLevels.has(event.severity));

    const existingKeys = new Set(
      context.openFindings.map((finding) => {
        const evidence = finding.evidence as Record<string, unknown> | null;
        return typeof evidence?.source_event_id === "string"
          ? evidence.source_event_id
          : "";
      }).filter(Boolean)
    );

    const candidates = [
      ...severeEvents.map((event) => ({
        sourceEventId: event.id,
        assetId: event.asset_id,
        title: event.title,
        findingType: `security_event:${event.event_type}`,
        severity: event.severity,
        summary: event.description ?? "A high-impact security event was observed and requires investigation.",
        remediation: "Review the source evidence, validate the affected asset, and apply an authorized remediation appropriate to the event.",
        evidence: {
          source: "security_event",
          source_event_id: event.id,
          event_type: event.event_type,
          event_source: event.source,
          observed_at: event.observed_at,
          evidence: event.evidence,
          analysis_boundary: "observed_event",
        },
      })),
      ...severeAiEvents.map((event) => ({
        sourceEventId: event.id,
        assetId: null,
        title: event.title,
        findingType: `ai_security_event:${event.event_type}`,
        severity: event.severity,
        summary: event.description ?? "A high-impact AI security event was observed and requires investigation.",
        remediation: "Review the AI system or agent evidence, validate the behavior, and apply an authorized remediation appropriate to the event.",
        evidence: {
          source: "ai_security_event",
          source_event_id: event.id,
          system_id: event.system_id,
          agent_id: event.agent_id,
          event_type: event.event_type,
          observed_at: event.observed_at,
          evidence: event.evidence,
          analysis_boundary: "observed_ai_event",
        },
      })),
    ].filter((candidate) => !existingKeys.has(candidate.sourceEventId));

    let findingsCreated = 0;

    for (const candidate of candidates) {
      const { error } = await supabase
        .from("security_findings")
        .insert({
          organization_id: organizationId,
          asset_id: candidate.assetId,
          title: candidate.title,
          finding_type: candidate.findingType,
          severity: candidate.severity,
          status: "open",
          summary: candidate.summary,
          evidence: candidate.evidence,
          remediation: candidate.remediation,
          detected_at: new Date().toISOString(),
        });

      if (error) {
        return NextResponse.json({ error: error.message }, { status: 500 });
      }

      findingsCreated += 1;
    }

    const highImpactEvidence = context.evidence.filter((item) => item.data?.severity === "high" || item.data?.severity === "critical").length;

    return NextResponse.json({
      analyzed: true,
      findingsCreated,
      context: {
        securityEvents: context.events.length,
        highImpactSecurityEvents: severeEvents.length,
        aiSecurityEvents: context.aiEvents.length,
        highImpactAiSecurityEvents: severeAiEvents.length,
        evidenceRecords: context.evidence.length,
        highImpactEvidenceRecords: highImpactEvidence,
        confirmedRelationships: context.relationships.length,
      },
      message: findingsCreated
        ? `${findingsCreated} evidence-backed finding${findingsCreated === 1 ? "" : "s"} created. No finding was created from an unverified relationship or missing telemetry.`
        : "Analysis completed. No new evidence-backed high-impact findings were created.",
    });
  } catch {
    return NextResponse.json({ error: "Security Brain analysis could not be completed." }, { status: 500 });
  }
}
