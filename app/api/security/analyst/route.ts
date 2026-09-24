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

type RelationshipItem = {
  id: string;
  source_asset_id: string;
  target_asset_id: string;
  relationship_type: string;
  confidence: number | null;
  evidence_source: string;
};

type AssetItem = {
  id: string;
  name: string;
  asset_type: string;
  criticality: string | null;
  status: string;
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

async function runGroundedAI(question: string, context: {
  findings: FindingItem[];
  evidence: EvidenceItem[];
  relationships: RelationshipItem[];
  assets: AssetItem[];
}) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) return null;

  const model = process.env.OPENAI_SECURITY_MODEL || "gpt-5.6-luna";

  const payload = {
    model,
    input: [
      {
        role: "system",
        content: [
          {
            type: "input_text",
            text:
              "You are SentinelX Security Analyst. Analyze only the supplied security records. " +
              "Never invent telemetry, compromise, attribution, vulnerabilities, identities, or remediation facts. " +
              "Treat confirmed relationships as confirmed and everything else as unknown. " +
              "Missing telemetry is not proof of safety. Do not claim an incident is confirmed unless the supplied evidence explicitly supports that conclusion. " +
              "Do not execute or authorize actions. Recommend review steps only. " +
              "Return concise analyst prose with these headings: Assessment, Evidence, Unknowns, Recommended next step.",
          },
        ],
      },
      {
        role: "user",
        content: [
          {
            type: "input_text",
            text: JSON.stringify({
              question,
              findings: context.findings.slice(0, 20),
              evidence: context.evidence.slice(0, 30),
              confirmedRelationships: context.relationships.slice(0, 50),
              assets: context.assets.slice(0, 50),
            }),
          },
        ],
      },
    ],
  };

  const response = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      Authorization: "Bearer " + apiKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) return null;

  const data = (await response.json()) as {
    output_text?: string;
    output?: Array<{
      content?: Array<{ type?: string; text?: string }>;
    }>;
  };

  const direct = typeof data.output_text === "string" ? data.output_text.trim() : "";
  if (direct) return direct;

  const fallback = (data.output ?? [])
    .flatMap((item) => item.content ?? [])
    .map((item) => item.text ?? "")
    .join("\n")
    .trim();

  return fallback || null;
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
        aiUsed: false,
      });
    }

    const body = (await request.json()) as { question?: string };
    const question = body.question?.trim();

    if (!question) {
      return NextResponse.json({ error: "A security question is required." }, { status: 400 });
    }

    const [findingsResult, evidenceResult, relationshipsResult, assetsResult] = await Promise.all([
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
      supabase
        .from("security_asset_relationships")
        .select("id,source_asset_id,target_asset_id,relationship_type,confidence,evidence_source")
        .eq("organization_id", organizationId)
        .eq("status", "confirmed")
        .limit(200),
      supabase
        .from("security_assets")
        .select("id,name,asset_type,criticality,status")
        .eq("organization_id", organizationId)
        .limit(200),
    ]);

    const error = findingsResult.error ?? evidenceResult.error ?? relationshipsResult.error ?? assetsResult.error;
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    const findings = (findingsResult.data ?? []) as FindingItem[];
    const evidence = (evidenceResult.data ?? []) as EvidenceItem[];
    const relationships = (relationshipsResult.data ?? []) as RelationshipItem[];
    const assets = (assetsResult.data ?? []) as AssetItem[];

    const rankedFindings = [...findings]
      .sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity))
      .slice(0, 5);

    const normalized = question.toLowerCase();
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

    const aiAnswer = await runGroundedAI(question, {
      findings: rankedFindings,
      evidence: relevantEvidence.length ? relevantEvidence : evidence.slice(0, 20),
      relationships,
      assets,
    });

    const top = rankedFindings[0];

    const deterministicAnswer = top
      ? "The stored Security Brain data contains an open finding requiring review. SentinelX has limited its conclusion to recorded findings, evidence, assets, and confirmed relationships; missing telemetry is not treated as proof of safety or compromise."
      : "There are currently no open or acknowledged findings in the stored Security Brain data. That does not establish that the environment is secure because telemetry coverage may be incomplete.";

    return NextResponse.json({
      answer: aiAnswer ?? deterministicAnswer,
      question,
      aiUsed: Boolean(aiAnswer),
      model: aiAnswer ? (process.env.OPENAI_SECURITY_MODEL || "gpt-5.6-luna") : null,
      topFinding: top ? {
        id: top.id,
        title: top.title,
        severity: top.severity,
        summary: top.summary,
        remediation: top.remediation,
      } : null,
      findingsReviewed: findings.length,
      evidenceReviewed: evidence.length,
      confirmedRelationshipsReviewed: relationships.length,
      assetsReviewed: assets.length,
      evidence: citedEvidence,
      suggestedNextStep: top
        ? "Validate the cited evidence, inspect the confirmed graph context, and use Security Actions only if an authorized response is appropriate."
        : "Connect authorized telemetry sources and register protected assets before drawing stronger conclusions.",
      boundary: aiAnswer
        ? "AI-assisted analysis grounded only in organization-scoped SentinelX records. The model cannot execute or authorize response actions."
        : "Deterministic evidence-grounded analysis. OPENAI_API_KEY was unavailable or the AI request was unsuccessful, so no external AI conclusion was used.",
    });
  } catch {
    return NextResponse.json({ error: "Security analyst could not complete the analysis." }, { status: 500 });
  }
}
