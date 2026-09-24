import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

type EvidenceItem = {
  id: string;
  evidence_type: string;
  source: string;
  title: string;
  summary: string | null;
  observed_at: string;
  data: Record<string, unknown>;
};

type FindingItem = {
  id: string;
  asset_id: string | null;
  title: string;
  finding_type: string;
  severity: string;
  status: string;
  summary: string | null;
  remediation: string | null;
  evidence: Record<string, unknown>;
};

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

function severityWeight(value: string) {
  return value === "critical" ? 4 : value === "high" ? 3 : value === "medium" ? 2 : 1;
}

export async function POST(request: Request) {
  try {
    const { supabase, user, organizationId } = await getContext();

    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    if (!organizationId) {
      return NextResponse.json({
        answer: "No organization is connected, so SentinelX has no organization-scoped security evidence to analyze.",
        evidence: [],
        boundary: "No inference was made.",
      });
    }

    const body = (await request.json()) as { question?: string };
    const question = body.question?.trim();

    if (!question) {
      return NextResponse.json({ error: "A security question is required." }, { status: 400 });
    }

    const [findingsResult, evidenceResult] = await Promise.all([
      supabase
        .from("security_findings")
        .select("id,asset_id,title,finding_type,severity,status,summary,remediation,evidence")
        .eq("organization_id", organizationId)
        .in("status", ["open", "acknowledged"])
        .order("detected_at", { ascending: false })
        .limit(100),
      supabase
        .from("security_evidence")
        .select("id,evidence_type,source,title,summary,observed_at,data")
        .eq("organization_id", organizationId)
        .order("observed_at", { ascending: false })
        .limit(100),
    ]);

    const error = findingsResult.error ?? evidenceResult.error;
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    const findings = (findingsResult.data ?? []) as FindingItem[];
    const evidence = (evidenceResult.data ?? []) as EvidenceItem[];

    const normalized = question.toLowerCase();
    const requestedEvidence = normalized.includes("evidence") || normalized.includes("why") || normalized.includes("because");
    const requestedActions = normalized.includes("fix") || normalized.includes("respond") || normalized.includes("action") || normalized.includes("remediat");

    const rankedFindings = [...findings]
      .sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity))
      .slice(0, 5);

    const relevantEvidence = evidence.filter((item) => {
      const haystack = [item.title, item.summary ?? "", item.source, item.evidence_type].join(" ").toLowerCase();
      return normalized.split(/\s+/).some((term) => term.length > 3 && haystack.includes(term));
    }).slice(0, 8);

    const citedEvidence = (relevantEvidence.length ? relevantEvidence : evidence.slice(0, 5)).map((item) => ({
      id: item.id,
      title: item.title,
      source: item.source,
      observedAt: item.observed_at,
      summary: item.summary,
    }));

    const top = rankedFindings[0];
    const answer = top
      ? requestedActions
        ? "The current evidence supports reviewing the highest-severity finding first, validating its cited evidence, and creating an authorized response action only after that validation. SentinelX has not inferred a remediation that the telemetry does not support."
        : requestedEvidence
          ? "The strongest current signal is the highest-severity open finding below. Its conclusion is bounded by the evidence attached to that finding; SentinelX does not treat missing telemetry as proof of safety or compromise."
          : "Based on the currently stored security evidence, SentinelX has open findings that require review. The highest-severity finding is summarized below; this analysis is limited to organization-scoped evidence and findings."
      : "There are currently no open or acknowledged findings in the stored Security Brain data. That does not establish that the environment is secure because telemetry coverage may be incomplete.";

    return NextResponse.json({
      answer,
      question,
      topFinding: top ? {
        id: top.id,
        title: top.title,
        severity: top.severity,
        summary: top.summary,
        remediation: top.remediation,
      } : null,
      findingsReviewed: findings.length,
      evidenceReviewed: evidence.length,
      evidence: citedEvidence,
      suggestedNextStep: top
        ? "Review the finding evidence, then use the Security Actions center if an authorized response is appropriate."
        : "Connect authorized telemetry sources and register protected assets before drawing stronger conclusions.",
      boundary: "Evidence-grounded deterministic analysis. No external AI inference or invented security facts were used.",
    });
  } catch {
    return NextResponse.json({ error: "Security analyst could not complete the analysis." }, { status: 500 });
  }
}
