import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { buildAdaptiveInvestigationContext } from "@/lib/security/adaptive-context";
import { buildIntelligenceCore } from "@/lib/security/intelligence-core";

async function getOrganization(supabase: Awaited<ReturnType<typeof createClient>>) {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return { user: null, organizationId: null };

  const { data: profile } = await supabase
    .from("profiles")
    .select("organization_id")
    .eq("id", user.id)
    .maybeSingle();

  return { user, organizationId: profile?.organization_id ?? null };
}

async function buildCoreForOrganization(
  supabase: Awaited<ReturnType<typeof createClient>>,
  organizationId: string,
  findingId?: string,
) {
  const [findingsResult, evidenceResult, eventsResult, relationshipsResult, assetsResult, memoryResult] =
    await Promise.all([
      supabase.from("security_findings")
        .select("id,asset_id,title,finding_type,severity,status,summary,detected_at")
        .eq("organization_id", organizationId)
        .order("detected_at", { ascending: false })
        .limit(100),
      supabase.from("security_evidence")
        .select("id,asset_id,evidence_type,source,title,summary,observed_at")
        .eq("organization_id", organizationId)
        .order("observed_at", { ascending: false })
        .limit(500),
      supabase.from("security_events")
        .select("id,asset_id,severity,observed_at")
        .eq("organization_id", organizationId)
        .order("observed_at", { ascending: false })
        .limit(500),
      supabase.from("security_asset_relationships")
        .select("source_asset_id,target_asset_id,relationship_type,confidence,status")
        .eq("organization_id", organizationId)
        .limit(500),
      supabase.from("security_assets")
        .select("id,name,asset_type,criticality,status")
        .eq("organization_id", organizationId)
        .limit(500),
      supabase.from("security_memory")
        .select("id,memory_type,subject_id,title,summary,state,data,occurred_at")
        .eq("organization_id", organizationId)
        .order("occurred_at", { ascending: false })
        .limit(500),
    ]);

  const error = findingsResult.error ?? evidenceResult.error ?? eventsResult.error ??
    relationshipsResult.error ?? assetsResult.error ?? memoryResult.error;
  if (error) throw new Error(error.message);

  const findings = findingId
    ? (findingsResult.data ?? []).filter((finding) => finding.id === findingId)
    : (findingsResult.data ?? []).slice(0, 10);

  const traces = findings.map((finding) => {
    const context = buildAdaptiveInvestigationContext({
      finding: {
        ...finding,
        finding_type: finding.finding_type ?? "unknown",
        summary: finding.summary ?? null,
      },
      evidence: (evidenceResult.data ?? []).map((item) => ({
        ...item,
        source: item.source ?? "unknown",
        title: item.title ?? "Security evidence",
      })),
      events: eventsResult.data ?? [],
      relationships: relationshipsResult.data ?? [],
      assets: assetsResult.data ?? [],
      memories: memoryResult.data ?? [],
    });

    return { finding, core: buildIntelligenceCore(context) };
  });

  return traces;
}

export async function GET() {
  try {
    const supabase = await createClient();
    const { user, organizationId } = await getOrganization(supabase);
    if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
    if (!organizationId) return NextResponse.json({ error: "Organization required." }, { status: 403 });

    const { data, error } = await supabase
      .from("security_memory")
      .select("id,subject_id,title,summary,state,data,occurred_at")
      .eq("organization_id", organizationId)
      .eq("memory_type", "reasoning_trace")
      .order("occurred_at", { ascending: false })
      .limit(50);

    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    return NextResponse.json({
      traces: (data ?? []).map((memory) => ({
        id: memory.id,
        findingId: memory.subject_id,
        title: memory.title,
        summary: memory.summary,
        state: memory.state,
        occurredAt: memory.occurred_at,
        traceId: typeof memory.data?.trace_id === "string" ? memory.data.trace_id : memory.id,
        trace: memory.data?.trace ?? null,
        confidence: typeof memory.data?.confidence === "number" ? memory.data.confidence : null,
        decision: typeof memory.data?.decision === "string" ? memory.data.decision : null,
      })),
      boundary: "Persisted reasoning traces are historical explanations of recorded intelligence context. They do not establish compromise, attribution, causation, or response success.",
    });
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "Reasoning trace retrieval failed." }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const supabase = await createClient();
    const { user, organizationId } = await getOrganization(supabase);
    if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
    if (!organizationId) return NextResponse.json({ error: "Organization required." }, { status: 403 });

    const body = await request.json().catch(() => ({}));
    const findingId = typeof body?.findingId === "string" ? body.findingId : undefined;
    const built = await buildCoreForOrganization(supabase, organizationId, findingId);

    if (!built.length) return NextResponse.json({ error: "No matching finding was available." }, { status: 404 });

    const rows = built.map(({ finding, core }) => ({
      organization_id: organizationId,
      memory_type: "reasoning_trace",
      subject_id: finding.id,
      title: `Reasoning trace · ${finding.title}`,
      summary: `Persisted ${core.reasoningTrace.stages.length}-stage reasoning trace at ${core.confidence}% core confidence.`,
      state: core.state,
      data: {
        trace_id: core.reasoningTrace.traceId,
        trace: core.reasoningTrace,
        confidence: core.confidence,
        decision: core.decisionReasoning.assessment.priority,
      },
      occurred_at: core.generatedAt,
    }));

    const { data, error } = await supabase
      .from("security_memory")
      .insert(rows)
      .select("id,subject_id,title,summary,state,data,occurred_at");

    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    return NextResponse.json({
      persisted: data ?? [],
      count: data?.length ?? 0,
      boundary: "Persistence records the reasoning trace for longitudinal inspection. It does not authorize or execute a security action.",
    });
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "Reasoning trace persistence failed." }, { status: 500 });
  }
}
