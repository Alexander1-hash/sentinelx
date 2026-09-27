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

type AssetRecord = {
  id: string;
  name: string;
  asset_type: string;
};

type AiAgentRecord = {
  id: string;
  system_id: string | null;
  name: string;
};

type AiSystemRecord = {
  id: string;
  asset_id: string | null;
  name: string;
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
  const [eventsResult, aiEventsResult, evidenceResult, relationshipsResult, findingsResult, assetsResult, agentsResult, systemsResult] = await Promise.all([
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
      .limit(500),
    supabase
      .from("security_assets")
      .select("id,name,asset_type")
      .eq("organization_id", organizationId)
      .limit(500),
    supabase
      .from("ai_security_agents")
      .select("id,system_id,name")
      .eq("organization_id", organizationId)
      .limit(500),
    supabase
      .from("ai_security_systems")
      .select("id,asset_id,name")
      .eq("organization_id", organizationId)
      .limit(500),
  ]);

  const error = eventsResult.error ?? aiEventsResult.error ?? evidenceResult.error ?? relationshipsResult.error ?? findingsResult.error ?? assetsResult.error ?? agentsResult.error ?? systemsResult.error;
  if (error) throw new Error(error.message);

  const allFindings = findingsResult.data ?? [];
  const openFindings = allFindings.filter((finding) => finding.status === "open" || finding.status === "acknowledged");

  return {
    events: (eventsResult.data ?? []) as SecurityEvent[],
    aiEvents: (aiEventsResult.data ?? []) as AiSecurityEvent[],
    evidence: (evidenceResult.data ?? []) as EvidenceRecord[],
    relationships: relationshipsResult.data ?? [],
    openFindings,
    allFindings,
    assets: (assetsResult.data ?? []) as AssetRecord[],
    agents: (agentsResult.data ?? []) as AiAgentRecord[],
    systems: (systemsResult.data ?? []) as AiSystemRecord[],
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
    if (!organizationId) return NextResponse.json({ findingsCreated: 0, analyzed: false, message: "No organization is connected, so there is no security evidence to analyze." });
    const { runSecurityAnalysis } = await import("@/lib/security/analysis");
    return NextResponse.json(await runSecurityAnalysis(supabase, organizationId));
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "Security Brain analysis could not be completed." }, { status: 500 });
  }
}
