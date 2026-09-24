import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

type Finding = {
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

type Evidence = {
  id: string;
  title: string;
  source: string;
  summary: string | null;
  evidence_type: string;
  observed_at: string;
};

type Asset = {
  id: string;
  name: string;
  asset_type: string;
  criticality: string | null;
  status: string;
};

type Relationship = {
  source_asset_id: string;
  target_asset_id: string;
  relationship_type: string;
  confidence: number | null;
};

const ACTIONS = [
  "investigate_asset",
  "review_finding",
  "contain_asset",
  "disable_integration",
  "revoke_access",
  "isolate_endpoint",
  "block_indicator",
] as const;

function chooseAction(finding: Finding): (typeof ACTIONS)[number] {
  if (finding.finding_type.includes("access") || finding.finding_type.includes("identity")) return "review_finding";
  if (finding.finding_type.includes("endpoint")) return "isolate_endpoint";
  if (finding.finding_type.includes("integration")) return "disable_integration";
  return finding.severity === "critical" || finding.severity === "high"
    ? "investigate_asset"
    : "review_finding";
}

export async function POST(request: Request) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
    const organizationId = profile?.organization_id;
    if (!organizationId) return NextResponse.json({ error: "Organization is required." }, { status: 400 });

    const body = (await request.json()) as { findingId?: string };
    if (!body.findingId) return NextResponse.json({ error: "findingId is required." }, { status: 400 });

    const { data: finding, error: findingError } = await supabase
      .from("security_findings")
      .select("id,asset_id,title,finding_type,severity,status,summary,remediation,evidence")
      .eq("id", body.findingId)
      .eq("organization_id", organizationId)
      .in("status", ["open", "acknowledged"])
      .maybeSingle();

    if (findingError) return NextResponse.json({ error: findingError.message }, { status: 500 });
    if (!finding) return NextResponse.json({ error: "Finding was not found or is no longer active." }, { status: 404 });

    const [evidenceResult, relationshipsResult, assetsResult] = await Promise.all([
      supabase.from("security_evidence")
        .select("id,title,source,summary,evidence_type,observed_at")
        .eq("organization_id", organizationId)
        .order("observed_at", { ascending: false }).limit(50),
      supabase.from("security_asset_relationships")
        .select("source_asset_id,target_asset_id,relationship_type,confidence")
        .eq("organization_id", organizationId).eq("status", "confirmed").limit(100),
      supabase.from("security_assets")
        .select("id,name,asset_type,criticality,status")
        .eq("organization_id", organizationId).limit(100),
    ]);

    const error = evidenceResult.error ?? relationshipsResult.error ?? assetsResult.error;
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    const evidence = (evidenceResult.data ?? []) as Evidence[];
    const relationships = (relationshipsResult.data ?? []) as Relationship[];
    const assets = (assetsResult.data ?? []) as Asset[];
    const typedFinding = finding as Finding;
    const targetAsset = assets.find((asset) => asset.id === typedFinding.asset_id) ?? null;

    const relatedAssetIds = new Set<string>();
    if (targetAsset) relatedAssetIds.add(targetAsset.id);
    relationships.forEach((edge) => {
      if (edge.source_asset_id === typedFinding.asset_id) relatedAssetIds.add(edge.target_asset_id);
      if (edge.target_asset_id === typedFinding.asset_id) relatedAssetIds.add(edge.source_asset_id);
    });

    const relatedAssets = assets.filter((asset) => relatedAssetIds.has(asset.id));
    const relevantEvidence = evidence.filter((item) => {
      const text = [item.title, item.summary ?? "", item.source, item.evidence_type].join(" ").toLowerCase();
      return [typedFinding.title, typedFinding.finding_type, typedFinding.asset_id ?? ""]
        .join(" ").toLowerCase().split(/\s+/).some((term) => term.length > 3 && text.includes(term));
    }).slice(0, 10);

    const recommendedAction = chooseAction(typedFinding);
    const plan = {
      objective: `Validate and safely respond to “${typedFinding.title}” without assuming compromise.`,
      severity: typedFinding.severity,
      finding: typedFinding.title,
      target: targetAsset ? { id: targetAsset.id, name: targetAsset.name, type: targetAsset.asset_type, criticality: targetAsset.criticality } : null,
      evidence: relevantEvidence.map((item) => ({ id: item.id, title: item.title, source: item.source, observedAt: item.observed_at })),
      graphContext: relatedAssets.map((asset) => ({ id: asset.id, name: asset.name, type: asset.asset_type, criticality: asset.criticality })),
      confirmedRelationships: relationships.filter((edge) => relatedAssetIds.has(edge.source_asset_id) && relatedAssetIds.has(edge.target_asset_id)),
      validationSteps: [
        "Verify the finding against the original telemetry or evidence source.",
        "Inspect the target asset and its confirmed graph relationships.",
        "Check whether the relevant activity is expected and authorized.",
        "Record additional evidence before taking a high-impact action.",
      ],
      recommendedAction,
      authorizationRequired: ["contain_asset", "disable_integration", "revoke_access", "isolate_endpoint", "block_indicator"].includes(recommendedAction),
      executionBoundary: "This plan creates a recommendation only. SentinelX does not execute external or destructive actions from this endpoint.",
      unknowns: [
        "No conclusion is made about compromise unless supporting evidence explicitly establishes it.",
        "Missing telemetry is treated as unknown, not safe.",
      ],
    };

    const { data: action, error: actionError } = await supabase
      .from("security_actions")
      .insert({
        organization_id: organizationId,
        finding_id: typedFinding.id,
        requested_by: user.id,
        action_type: recommendedAction,
        status: "pending",
        target: targetAsset ? { asset_id: targetAsset.id, asset_name: targetAsset.name } : {},
        authorization: {
          required: plan.authorizationRequired,
          state: "pending_operator_authorization",
          requested_at: new Date().toISOString(),
          requested_by: user.id,
          reason: "Created from an evidence-grounded SentinelX response plan.",
          execution_boundary: plan.executionBoundary,
        },
        result: {
          state: "recommendation_created",
          response_plan: plan,
        },
      })
      .select("id,finding_id,action_type,status,target,authorization,result,created_at,executed_at")
      .single();

    if (actionError) return NextResponse.json({ error: actionError.message }, { status: 500 });

    return NextResponse.json({
      plan,
      action,
      message: "Response plan created and queued for explicit operator review.",
    }, { status: 201 });
  } catch {
    return NextResponse.json({ error: "Response planning could not be completed." }, { status: 500 });
  }
}
