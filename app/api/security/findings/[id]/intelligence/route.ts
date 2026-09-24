import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

type Edge = {
  id: string;
  source_asset_id: string;
  target_asset_id: string;
  relationship_type: string;
  confidence: number | null;
  evidence_source: string;
};

type Asset = {
  id: string;
  name: string;
  asset_type: string;
  criticality: string;
  environment: string;
};

type Finding = {
  id: string;
  asset_id: string | null;
  title: string;
  finding_type: string;
  severity: string;
  status: string;
  summary: string | null;
  evidence: Record<string, unknown>;
  remediation: string | null;
  detected_at: string;
};

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const { data: profile } = await supabase
      .from("profiles")
      .select("organization_id")
      .eq("id", user.id)
      .maybeSingle();

    const organizationId = profile?.organization_id;
    if (!organizationId) return NextResponse.json({ error: "No organization connected." }, { status: 400 });

    const { id } = await params;

    const [findingResult, assetsResult, edgesResult, evidenceResult] = await Promise.all([
      supabase.from("security_findings")
        .select("id,asset_id,title,finding_type,severity,status,summary,evidence,remediation,detected_at")
        .eq("id", id).eq("organization_id", organizationId).maybeSingle(),
      supabase.from("security_assets")
        .select("id,name,asset_type,criticality,environment")
        .eq("organization_id", organizationId).limit(500),
      supabase.from("security_asset_relationships")
        .select("id,source_asset_id,target_asset_id,relationship_type,confidence,evidence_source")
        .eq("organization_id", organizationId).eq("status", "confirmed").limit(1000),
      supabase.from("security_evidence")
        .select("id,asset_id,evidence_type,source,title,summary,data,observed_at")
        .eq("organization_id", organizationId).order("observed_at", { ascending: false }).limit(500),
    ]);

    if (findingResult.error) throw new Error(findingResult.error.message);
    if (!findingResult.data) return NextResponse.json({ error: "Finding not found." }, { status: 404 });
    if (assetsResult.error) throw new Error(assetsResult.error.message);
    if (edgesResult.error) throw new Error(edgesResult.error.message);
    if (evidenceResult.error) throw new Error(evidenceResult.error.message);

    const finding = findingResult.data as Finding;
    const assets = (assetsResult.data ?? []) as Asset[];
    const edges = (edgesResult.data ?? []) as Edge[];
    const evidence = evidenceResult.data ?? [];
    const assetMap = new Map(assets.map((asset) => [asset.id, asset]));

    const rootAssetId =
      finding.asset_id ??
      (typeof finding.evidence?.asset_id === "string" ? finding.evidence.asset_id : null);

    const relatedEvidence = evidence.filter((item) => {
      if (rootAssetId && item.asset_id === rootAssetId) return true;
      const haystack = [item.title, item.summary ?? "", item.evidence_type, JSON.stringify(item.data ?? {})].join(" ").toLowerCase();
      return haystack.includes(finding.title.toLowerCase()) || haystack.includes(finding.finding_type.toLowerCase());
    }).slice(0, 25);

    const downstream = new Map<string, { asset: Asset; hops: number; confidence: number; chain: string[] }>();

    if (rootAssetId && assetMap.has(rootAssetId)) {
      const queue: Array<{ assetId: string; hops: number; confidence: number; chain: string[] }> = [
        { assetId: rootAssetId, hops: 0, confidence: 1, chain: [] },
      ];
      const bestDepth = new Map<string, number>([[rootAssetId, 0]]);

      while (queue.length) {
        const current = queue.shift()!;
        if (current.hops >= 4) continue;

        for (const edge of edges.filter((item) => item.source_asset_id === current.assetId)) {
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

    const unknowns = [
      !rootAssetId ? "The finding is not linked to a confirmed asset." : null,
      relatedEvidence.length === 0 ? "No directly matching evidence record was found." : null,
      edges.length === 0 ? "No confirmed graph relationships are available." : null,
      blastRadius.length === 0 && rootAssetId ? "No confirmed downstream assets were established from the finding asset." : null,
      "Reachability is derived from confirmed relationships and does not establish compromise, attacker movement, or successful exploitation.",
    ].filter(Boolean);

    return NextResponse.json({
      finding,
      affectedAsset: rootAssetId ? assetMap.get(rootAssetId) ?? null : null,
      blastRadius,
      supportingEvidence: relatedEvidence,
      confirmedEdgeCount: edges.length,
      unknowns,
      boundary: "Blast radius is confirmed-graph reachability only. It is not proof of compromise or attacker activity.",
    });
  } catch {
    return NextResponse.json({ error: "Unable to build finding intelligence." }, { status: 500 });
  }
}
