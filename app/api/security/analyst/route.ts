import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { buildSecurityPatterns, type SecurityPatternMemory } from "@/lib/security/patterns";

type EvidenceItem = {
  id: string;
  evidence_type: string;
  source: string;
  title: string;
  summary: string | null;
  observed_at: string;
  data: Record<string, unknown>;
  asset_id?: string | null;
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
  investigation?: Record<string, unknown> | null;
  memory?: SecurityPatternMemory[];
  patterns?: ReturnType<typeof buildSecurityPatterns>;
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
              investigation: context.investigation ?? null,
              securityMemory: context.memory ?? [],
              securityPatterns: context.patterns ?? [],
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
    .join("
")
    .trim();

  return fallback || null;
}

export async function POST(request: Request) {
  try {
    const { supabase, user, organizationId } = await getContext();

    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const body = (await request.json()) as { question?: string; findingId?: string; mode?: "standard" | "investigate" };
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

    const [findingsResult, evidenceResult, relationshipsResult, assetsResult, memoryResult] = await Promise.all([
      supabase
        .from("security_findings")
        .select("id,asset_id,title,finding_type,severity,status,summary,remediation,evidence")
        .eq("organization_id", organizationId)
        .in("status", ["open", "acknowledged"])
        .order("detected_at", { ascending: false })
        .limit(100),
      supabase
        .from("security_evidence")
        .select("id,asset_id,evidence_type,source,title,summary,observed_at,data")
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
      supabase
        .from("security_memory")
        .select("memory_type,subject_id,title,summary,state,data,occurred_at")
        .eq("organization_id", organizationId)
        .order("occurred_at", { ascending: false })
        .limit(100),
    ]);

    const error = findingsResult.error ?? evidenceResult.error ?? relationshipsResult.error ?? assetsResult.error ?? memoryResult.error;
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    const findings = (findingsResult.data ?? []) as FindingItem[];
    const evidence = (evidenceResult.data ?? []) as EvidenceItem[];
    const relationships = (relationshipsResult.data ?? []) as RelationshipItem[];
    const assets = (assetsResult.data ?? []) as AssetItem[];
    const memory = (memoryResult.data ?? []) as Array<{ memory_type: string; subject_id: string | null; title: string; summary: string; state: string; data: Record<string, unknown>; occurred_at: string }>;

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

    let investigation: {
      affectedAsset: AssetItem | null;
      blastRadius: Array<{ asset: AssetItem; hops: number; confidence: number; chain: string[] }>;
      supportingEvidence: EvidenceItem[];
      unknowns: string[];
      memory: Array<{ memory_type: string; title: string; summary: string; state: string; occurred_at: string }>;
    } | null = null;

    if (selectedFinding && body.mode === "investigate") {
      const assetMap = new Map(assets.map((asset) => [asset.id, asset]));
      const rootAssetId = selectedFinding.asset_id ?? (
        typeof selectedFinding.evidence?.asset_id === "string"
          ? selectedFinding.evidence.asset_id
          : null
      );
      const supportingEvidence = evidence.filter((item) => {
        if (rootAssetId && item.asset_id === rootAssetId) return true;
        const haystack = [item.title, item.summary ?? "", item.source, item.evidence_type].join(" ").toLowerCase();
        return [selectedFinding.title, selectedFinding.finding_type]
          .some((term) => term && haystack.includes(term.toLowerCase()));
      }).slice(0, 20);

      const downstream = new Map<string, { asset: AssetItem; hops: number; confidence: number; chain: string[] }>();
      if (rootAssetId && assetMap.has(rootAssetId)) {
        const queue: Array<{ assetId: string; hops: number; confidence: number; chain: string[] }> = [
          { assetId: rootAssetId, hops: 0, confidence: 1, chain: [] },
        ];
        const bestDepth = new Map<string, number>([[rootAssetId, 0]]);
        while (queue.length) {
          const current = queue.shift()!;
          if (current.hops >= 4) continue;
          for (const edge of relationships.filter((item) => item.source_asset_id === current.assetId)) {
            const nextHops = current.hops + 1;
            if (bestDepth.has(edge.target_asset_id) && (bestDepth.get(edge.target_asset_id) ?? 99) <= nextHops) continue;
            const target = assetMap.get(edge.target_asset_id);
            if (!target) continue;
            const nextConfidence = Math.min(current.confidence, edge.confidence ?? 0);
            bestDepth.set(edge.target_asset_id, nextHops);
            const chain = [...current.chain, edge.relationship_type];
            downstream.set(edge.target_asset_id, { asset: target, hops: nextHops, confidence: nextConfidence, chain });
            queue.push({ assetId: edge.target_asset_id, hops: nextHops, confidence: nextConfidence, chain });
          }
        }
      }

      const blastRadius = [...downstream.values()]
        .filter((item) => item.asset.id !== rootAssetId)
        .sort((a, b) => a.hops - b.hops || b.confidence - a.confidence)
        .slice(0, 25);

      investigation = {
        affectedAsset: rootAssetId ? assetMap.get(rootAssetId) ?? null : null,
        blastRadius,
        supportingEvidence,
        memory: memory
          .filter((item) => item.subject_id === selectedFinding.id || item.memory_type === "finding_state")
          .slice(0, 20)
          .map((item) => ({ memory_type: item.memory_type, title: item.title, summary: item.summary, state: item.state, occurred_at: item.occurred_at })),
        unknowns: [
          !rootAssetId ? "The finding is not linked to a confirmed asset." : null,
          supportingEvidence.length === 0 ? "No directly matching evidence record was found." : null,
          relationships.length === 0 ? "No confirmed graph relationships are available." : null,
          blastRadius.length === 0 && rootAssetId ? "No confirmed downstream assets were established." : null,
          "Confirmed reachability does not establish compromise, attacker movement, or successful exploitation.",
        ].filter((value): value is string => Boolean(value)),
      };
    }

    if (selectedFinding && body.mode === "investigate" && organizationId) {
      const investigationFingerprint = [
        selectedFinding.id,
        investigation?.affectedAsset?.id ?? "none",
        investigation?.blastRadius.map((item) => item.asset.id).sort().join(",") ?? "",
        investigation?.supportingEvidence.map((item) => item.id).sort().join(",") ?? "",
      ].join("|");

      const { data: priorInvestigation } = await supabase
        .from("security_memory")
        .select("id")
        .eq("organization_id", organizationId)
        .eq("memory_type", "investigation")
        .eq("subject_id", selectedFinding.id)
        .eq("data->>fingerprint", investigationFingerprint)
        .limit(1)
        .maybeSingle();

      if (!priorInvestigation) {
        await supabase.from("security_memory").insert({
          organization_id: organizationId,
          memory_type: "investigation",
          subject_id: selectedFinding.id,
          title: `Investigation: ${selectedFinding.title}`,
          summary: `SentinelX investigated this finding using recorded evidence and confirmed graph relationships. ${investigation?.blastRadius.length ?? 0} downstream asset(s) were established.`,
          data: {
            fingerprint: investigationFingerprint,
            finding_id: selectedFinding.id,
            affected_asset_id: investigation?.affectedAsset?.id ?? null,
            blast_radius_count: investigation?.blastRadius.length ?? 0,
            supporting_evidence_count: investigation?.supportingEvidence.length ?? 0,
            unknowns: investigation?.unknowns ?? [],
            mode: "investigate",
          },
        });
      }
    }

    const relevantMemory = selectedFinding
      ? memory
          .filter((item) => {
            if (item.subject_id === selectedFinding?.id) return true;
            if (item.memory_type === "finding_state") {
              const findingId = typeof item.data?.finding_id === "string" ? item.data.finding_id : null;
              return findingId === selectedFinding?.id;
            }
            const assetId = typeof item.data?.asset_id === "string"
              ? item.data.asset_id
              : typeof item.data?.affected_asset_id === "string"
                ? item.data.affected_asset_id
                : null;
            return Boolean(selectedFinding?.asset_id && assetId === selectedFinding.asset_id);
          })
          .slice(0, 30)
      : memory.slice(0, 30);

    const securityPatterns = buildSecurityPatterns(
      selectedFinding ? relevantMemory : memory,
    );
    const relevantPatternIds = new Set(
      relevantMemory.flatMap((item) => item.id),
    );
    const contextualPatterns = selectedFinding
      ? securityPatterns.filter((pattern) =>
          pattern.memoryIds.some((memoryId) => relevantPatternIds.has(memoryId)),
        )
      : securityPatterns;

    const historicalContext = selectedFinding
      ? {
          priorFindingStates: relevantMemory
            .filter((item) => item.memory_type === "finding_state")
            .slice(0, 10)
            .map((item) => ({
              occurred_at: item.occurred_at,
              state: item.state,
              title: item.title,
              summary: item.summary,
              current_state: item.data?.current_state ?? item.data?.current_security_state ?? null,
              previous_state: item.data?.previous_state ?? item.data?.previous_security_state ?? null,
            })),
          priorInvestigations: relevantMemory
            .filter((item) => item.memory_type === "investigation")
            .slice(0, 10)
            .map((item) => ({
              occurred_at: item.occurred_at,
              title: item.title,
              summary: item.summary,
              blast_radius_count: item.data?.blast_radius_count ?? null,
              supporting_evidence_count: item.data?.supporting_evidence_count ?? null,
            })),
          evidenceTransitions: relevantMemory
            .filter((item) => item.memory_type === "evidence_change")
            .slice(0, 15)
            .map((item) => ({
              occurred_at: item.occurred_at,
              title: item.title,
              summary: item.summary,
              change_type: item.data?.change_type ?? null,
              previous_state: item.data?.previous_security_state ?? item.data?.previous_state ?? null,
              current_state: item.data?.current_security_state ?? item.data?.current_state ?? null,
            })),
          operatorDecisions: relevantMemory
            .filter((item) => item.memory_type === "operator_decision" || item.memory_type === "response_outcome")
            .slice(0, 10)
            .map((item) => ({
              occurred_at: item.occurred_at,
              title: item.title,
              summary: item.summary,
              state: item.state,
            })),
        }
      : null;

    const aiAnswer = await runGroundedAI(question, {
      findings: rankedFindings,
      evidence: evidenceForAI,
      relationships,
      assets,
      investigation,
      memory: relevantMemory,
      patterns: contextualPatterns,
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
      investigation,
      findingsReviewed: rankedFindings.length,
      evidenceReviewed: evidenceForAI.length,
      confirmedRelationshipsReviewed: relationships.length,
      assetsReviewed: assets.length,
      memoryReviewed: relevantMemory.length,
      patternsReviewed: derivedPatterns.length,
      securityPatterns: derivedPatterns,
      historicalContext,
      temporalBoundary:
        "Historical memory can explain what SentinelX previously recorded and how state changed over time. It does not prove that a historical condition still exists. Current evidence and telemetry remain authoritative; missing telemetry is not resolution.",
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
