import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

type Asset = { id: string; name: string; asset_type: string; criticality: string };
type Edge = {
  id: string;
  source_asset_id: string;
  target_asset_id: string;
  relationship_type: string;
  confidence: number | null;
  evidence_source: string;
};

async function context() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return { supabase, organizationId: null };
  const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
  return { supabase, organizationId: profile?.organization_id ?? null };
}

export async function GET() {
  try {
    const { supabase, organizationId } = await context();
    if (!organizationId) return NextResponse.json({ paths: [] });

    const [assetsResult, edgesResult] = await Promise.all([
      supabase.from("security_assets").select("id,name,asset_type,criticality").eq("organization_id", organizationId).limit(500),
      supabase.from("security_asset_relationships").select("id,source_asset_id,target_asset_id,relationship_type,confidence,evidence_source").eq("organization_id", organizationId).eq("status", "confirmed").limit(1000),
    ]);
    if (assetsResult.error) return NextResponse.json({ error: assetsResult.error.message }, { status: 500 });
    if (edgesResult.error) return NextResponse.json({ error: edgesResult.error.message }, { status: 500 });

    const assets = (assetsResult.data ?? []) as Asset[];
    const edges = (edgesResult.data ?? []) as Edge[];
    const assetMap = new Map(assets.map((a) => [a.id, a]));
    const adjacency = new Map<string, Edge[]>();

    for (const edge of edges) {
      const list = adjacency.get(edge.source_asset_id) ?? [];
      list.push(edge);
      adjacency.set(edge.source_asset_id, list);
    }

    const sensitiveTypes = new Set(["database", "api", "ai_agent", "ai_system"]);
    const paths: Array<{ id: string; source: Asset; target: Asset; hops: Array<{ asset: Asset; relationship: string; confidence: number | null }>; confidence: number; rationale: string }> = [];

    for (const source of assets) {
      const queue: Array<{ assetId: string; hops: Array<{ asset: Asset; relationship: string; confidence: number | null }>; visited: Set<string> }> = [
        { assetId: source.id, hops: [], visited: new Set([source.id]) },
      ];

      while (queue.length) {
        const current = queue.shift();
        if (!current || current.hops.length >= 4) continue;

        for (const edge of adjacency.get(current.assetId) ?? []) {
          if (current.visited.has(edge.target_asset_id)) continue;
          const target = assetMap.get(edge.target_asset_id);
          if (!target) continue;

          const hops = [...current.hops, { asset: target, relationship: edge.relationship_type, confidence: edge.confidence }];
          const confidence = hops.reduce((min, hop) => Math.min(min, hop.confidence ?? 0), 1);

          if (hops.length >= 2 && sensitiveTypes.has(target.asset_type)) {
            paths.push({
              id: source.id + ":" + target.id + ":" + hops.map((h) => h.relationship).join(">"),
              source,
              target,
              hops,
              confidence,
              rationale: "Confirmed multi-hop path reaches a security-sensitive asset type. This is attack-path context, not proof of compromise.",
            });
          }

          if (hops.length < 4) {
            const visited = new Set(current.visited);
            visited.add(edge.target_asset_id);
            queue.push({ assetId: edge.target_asset_id, hops, visited });
          }
        }
      }
    }

    const unique = Array.from(new Map(paths.map((path) => [path.id, path])).values())
      .sort((a, b) => b.confidence - a.confidence)
      .slice(0, 100);

    return NextResponse.json({ paths: unique, confirmedEdges: edges.length });
  } catch {
    return NextResponse.json({ error: "Attack path analysis could not be completed." }, { status: 500 });
  }
}
