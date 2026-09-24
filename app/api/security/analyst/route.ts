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

  return { supabase, user, organizationId: profile?.organization_id ?? null };
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

  const response = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      Authorization: "Bearer " + apiKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model,
      input: [
        {
          role: "system",
          content: [{
            type: "input_text",
            text:
              "You are SentinelX Security Copilot. Analyze only supplied records. " +
              "Never invent telemetry, compromise, vulnerabilities, attribution, identities, or remediation facts. " +
              "Confirmed relationships are usable graph evidence; do not upgrade proposed or missing relationships. " +
              "Missing telemetry is not proof of safety. Never execute, approve, or claim an action was executed. " +
              "Give a concise response with exactly these sections: Assessment, Evidence, Unknowns, Recommended next step.",
          }],
        },
        {
          role: "user",
          content: [{
            type: "input_text",
            text: JSON.stringify({
              question,
              findings: context.findings.slice(0, 20),
              evidence: context.evidence.slice(0, 40),
              confirmedRelationships: context.relationships.slice(0, 80),
              assets: context.assets.slice(0, 80),
            }),
          }],
        },
      ],
    }),
  });

  if (!response.ok) return null;

  const data = (await response.json()) as {
    output_text?: string;
    output?: Array<{ content?: Array<{ text?: string }> }>;
  };

  if (typeof data.output_text === "string" && data.output_text.trim()) {
    return data.output_text.trim();
  }

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

    const body = (await request.json()) as { question?: string; findingId?: string };
    let question = body.question?.trim() ?? "";

    if (!question && !body.findingId) {
      return NextResponse.json({ error: "A security question or finding ID is required." }, { status: 400 });
    }

    if (!organizationId) {
      return NextResponse.json({
        answer: "No organization is connected, so SentinelX has no organization-scoped security evidence to analyze.",
        evidence: [],
        boundary: "No inference was made.",
        aiUsed: false,
      });
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
        .limit(150),
      supabase
        .from("security_asset_relationships")
        .select("id,source_asset_id,target_asset_id,relationship_type,confidence,evidence_source")
        .eq("organization_id", organizationId)
        .eq("status", "confirmed")
        .limit(300),
      supabase
        .from("security_assets")
        .select("id,name,asset_type,criticality,status")
        .eq("organization_id", organizationId)
        .limit(300),
    ]);

    const error = findingsResult.error ?? evidenceResult.error ?? relationshipsResult.error ?? assetsResult.error;
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    const findings = (findingsResult.data ?? []) as FindingItem[];
    const evidence = (evidenceResult.data ?? []) as EvidenceItem[];
    const relationships = (relationshipsResult.data ?? []) as RelationshipItem[];
    const assets = (assetsResult.data ?? []) as AssetItem[];

    let selectedFinding: FindingItem | null = null;

    if (body.findingId) {
      selectedFinding = findings.find((finding) => finding.id === body.findingId) ?? null;
      if (!selectedFinding) {
        return NextResponse.json({ error: "Finding was not found in the current organization." }, { status: 404 });
      }
      question = question || "Explain this finding, the evidence supporting it, the confirmed graph context, the unknowns, and the safest authorized next step.";
    }

    const rankedFindings = selectedFinding
      ? [selectedFinding, ...findings.filter((finding) => finding.id !== selectedFinding?.id)].slice(0, 10)
      : [...findings].sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity)).slice(0, 10);

    const selectedEvidence = selectedFinding
      ? evidence.filter((item) => {
          const haystack = [item.title, item.summary ?? "", item.source, item.evidence_type].join(" ").toLowerCase();
          const findingTerms = [
            selectedFinding?.title ?? "",
            selectedFinding?.finding_type ?? "",
            selectedFinding?.asset_id ?? "",
          ].join(" ").toLowerCase().split(/\s+/).filter((term) => term.length > 3);
          return findingTerms.some((term) => haystack.includes(term));
        }).slice(0, 15)
      : evidence.slice(0, 20);

    const evidenceForAI = selectedEvidence.length ? selectedEvidence : evidence.slice(0, 20);

    const aiAnswer = await runGroundedAI(question, {
      findings: rankedFindings,
      evidence: evidenceForAI,
      relationships,
      assets,
    });

    const citedEvidence = evidenceForAI.slice(0, 10).map((item) => ({
      id: item.id,
      title: item.title,
      source: item.source,
      observedAt: item.observed_at,
      summary: item.summary,
    }));

    return NextResponse.json({
      answer: aiAnswer ?? (
        selectedFinding
          ? "This finding is supported only by the recorded finding data and available evidence. Review the cited evidence and confirmed graph context before taking action."
          : "SentinelX found no available AI response. Review the recorded findings and evidence directly."
      ),
      question,
      aiUsed: Boolean(aiAnswer),
      model: aiAnswer ? modelName() : null,
      finding: selectedFinding,
      findingsReviewed: rankedFindings.length,
      evidenceReviewed: evidenceForAI.length,
      confirmedRelationshipsReviewed: relationships.length,
      assetsReviewed: assets.length,
      evidence: citedEvidence,
      suggestedNextStep: selectedFinding
        ? "Validate the finding evidence, inspect its confirmed graph context, and create a Security Action only when an authorized response is appropriate."
        : "Review the highest-severity finding and its evidence before creating a response recommendation.",
      boundary: aiAnswer
        ? "AI-assisted analysis grounded only in organization-scoped SentinelX records. The model cannot execute or authorize response actions."
        : "Deterministic evidence-grounded analysis. No unsupported AI conclusion was used.",
    });
  } catch {
    return NextResponse.json({ error: "Security analyst could not complete the analysis." }, { status: 500 });
  }
}

function modelName() {
  return process.env.OPENAI_SECURITY_MODEL || "gpt-5.6-luna";
}
