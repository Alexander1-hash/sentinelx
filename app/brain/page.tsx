"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Boxes, BrainCircuit, CircleDashed, GitBranch, Loader2, ShieldCheck, Sparkles } from "lucide-react";

type Asset = {
  id: string;
  name: string;
  asset_type: string;
  provider: string | null;
  environment: string;
  criticality: string;
  status: string;
  metadata: { onboarding?: { telemetry?: string } } | null;
};

type Relationship = {
  id: string;
  source_asset_id: string;
  target_asset_id: string;
  relationship_type: string;
  confidence: number | null;
  evidence: Record<string, unknown>;
  created_at: string;
};

export default function SecurityBrainPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [relationships, setRelationships] = useState<Relationship[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");

  async function loadGraph() {
    setLoading(true);
    try {
      const [assetsResponse, relationshipsResponse] = await Promise.all([
        fetch("/api/security/assets", { cache: "no-store" }),
        fetch("/api/security/relationships", { cache: "no-store" }),
      ]);
      const assetsData = await assetsResponse.json();
      const relationshipsData = await relationshipsResponse.json();

      if (!assetsResponse.ok) {
        setMessage(assetsData.error ?? "Unable to load assets.");
        return;
      }
      if (!relationshipsResponse.ok) {
        setMessage(relationshipsData.error ?? "Unable to load relationships.");
        return;
      }

      setAssets(assetsData.assets ?? []);
      setRelationships(relationshipsData.relationships ?? []);
    } catch {
      setMessage("Security Graph could not be loaded.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadGraph();
  }, []);

  const assetMap = useMemo(
    () => new Map(assets.map((asset) => [asset.id, asset])),
    [assets]
  );

  const connectedAssetIds = useMemo(() => {
    const ids = new Set<string>();
    relationships.forEach((relationship) => {
      ids.add(relationship.source_asset_id);
      ids.add(relationship.target_asset_id);
    });
    return ids;
  }, [relationships]);

  return (
    <main className="min-h-screen bg-[#071018] text-slate-100">
      <header className="border-b border-white/10 bg-[#071018]/95">
        <div className="mx-auto flex max-w-[1200px] items-center justify-between px-4 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
              <BrainCircuit className="h-5 w-5" />
            </div>
            <div>
              <p className="font-semibold text-white">Security Brain</p>
              <p className="text-[11px] text-slate-500">Evidence-backed Security Graph</p>
            </div>
          </div>
          <Link href="/" className="inline-flex items-center gap-2 rounded-xl border border-white/10 px-3 py-2 text-xs text-slate-400 hover:text-white">
            <ArrowLeft className="h-3.5 w-3.5" /> Command Center
          </Link>
        </div>
      </header>

      <div className="mx-auto max-w-[1200px] px-4 py-8 sm:px-6">
        <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">Security intelligence</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Security Graph</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
          SentinelX reasons from known assets and explicit relationships. An asset without telemetry or relationships remains an observed unknown, not a fabricated risk.
        </p>

        <div className="mt-6 grid gap-3 sm:grid-cols-3">
          <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Nodes</p>
            <p className="mt-2 text-2xl font-semibold text-white">{assets.length}</p>
            <p className="mt-1 text-xs text-slate-600">Registered assets</p>
          </div>
          <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Relationships</p>
            <p className="mt-2 text-2xl font-semibold text-cyan-200">{relationships.length}</p>
            <p className="mt-1 text-xs text-slate-600">Evidence-backed graph edges</p>
          </div>
          <div className="rounded-2xl border border-amber-400/10 bg-amber-400/[0.03] p-4">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Unconnected nodes</p>
            <p className="mt-2 text-2xl font-semibold text-amber-200">{Math.max(assets.length - connectedAssetIds.size, 0)}</p>
            <p className="mt-1 text-xs text-slate-600">Relationships still missing</p>
          </div>
        </div>

        {message && <div className="mt-5 rounded-xl border border-amber-400/10 bg-amber-400/[0.03] p-4 text-sm text-amber-200">{message}</div>}

        {loading ? (
          <div className="mt-8 flex items-center gap-2 text-sm text-slate-500"><Loader2 className="h-4 w-4 animate-spin" /> Building verified graph...</div>
        ) : !assets.length ? (
          <div className="mt-8 rounded-3xl border border-dashed border-white/10 px-6 py-16 text-center">
            <Boxes className="mx-auto h-9 w-9 text-slate-700" />
            <h2 className="mt-4 font-semibold text-slate-300">The Security Brain has no nodes yet</h2>
            <p className="mx-auto mt-2 max-w-md text-xs leading-5 text-slate-600">Register an authorized asset first. SentinelX will not manufacture security entities that have not been observed or provided.</p>
            <Link href="/assets" className="mt-5 inline-flex items-center gap-2 rounded-xl bg-cyan-300 px-4 py-3 text-xs font-semibold text-slate-950">Add first asset</Link>
          </div>
        ) : (
          <div className="mt-8 grid gap-6 lg:grid-cols-[1.15fr_.85fr]">
            <section className="rounded-3xl border border-white/10 bg-white/[0.025] p-5 sm:p-6">
              <div className="flex items-center gap-2">
                <GitBranch className="h-4 w-4 text-cyan-300" />
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Graph nodes</p>
              </div>

              <div className="mt-5 space-y-3">
                {assets.map((asset) => {
                  const links = relationships.filter(
                    (relationship) => relationship.source_asset_id === asset.id || relationship.target_asset_id === asset.id
                  ).length;

                  return (
                    <div key={asset.id} className="rounded-2xl border border-white/10 bg-black/10 p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="font-medium text-white">{asset.name}</p>
                          <p className="mt-1 text-[11px] capitalize text-slate-600">
                            {asset.asset_type.replaceAll("_", " ")} · {asset.environment}{asset.provider ? ` · ${asset.provider}` : ""}
                          </p>
                        </div>
                        <span className="rounded-full bg-white/5 px-2 py-1 text-[9px] uppercase tracking-wider text-slate-500">{asset.criticality}</span>
                      </div>

                      <div className="mt-3 flex flex-wrap items-center gap-3 text-[10px] text-slate-500">
                        <span className="inline-flex items-center gap-1"><GitBranch className="h-3 w-3" /> {links} relationship{links === 1 ? "" : "s"}</span>
                        <span className="inline-flex items-center gap-1"><CircleDashed className="h-3 w-3" /> {asset.metadata?.onboarding?.telemetry ?? "Telemetry not connected"}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </section>

            <section className="rounded-3xl border border-white/10 bg-white/[0.025] p-5 sm:p-6">
              <div className="flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-cyan-300" />
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Reasoning inputs</p>
              </div>

              {relationships.length ? (
                <div className="mt-5 space-y-3">
                  {relationships.map((relationship) => (
                    <div key={relationship.id} className="rounded-2xl border border-cyan-400/10 bg-cyan-400/[0.025] p-4">
                      <p className="text-sm font-medium text-white">
                        {assetMap.get(relationship.source_asset_id)?.name ?? "Unknown asset"}
                        <span className="mx-2 text-cyan-300">→</span>
                        {assetMap.get(relationship.target_asset_id)?.name ?? "Unknown asset"}
                      </p>
                      <p className="mt-1 text-[11px] text-cyan-200/70">
                        {relationship.relationship_type.replaceAll("_", " ")}{relationship.confidence !== null ? ` · ${Math.round(relationship.confidence * 100)}% confidence` : ""}
                      </p>
                      <p className="mt-2 text-[10px] leading-5 text-slate-600">This relationship is treated as an input to analysis only; it is not a finding by itself.</p>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="mt-5 rounded-2xl border border-dashed border-white/10 p-5">
                  <p className="text-sm font-medium text-slate-300">No relationships recorded</p>
                  <p className="mt-2 text-xs leading-5 text-slate-600">The next intelligence layer is to connect assets such as User → AI Agent → Tool → API → Database.</p>
                </div>
              )}

              <div className="mt-5 rounded-2xl border border-cyan-400/10 bg-cyan-400/[0.03] p-4">
                <p className="text-xs font-semibold text-cyan-200">Evidence boundary</p>
                <p className="mt-2 text-[11px] leading-5 text-slate-500">SentinelX will distinguish observed relationships, operator-provided context, and AI analysis. It will not convert missing evidence into a security claim.</p>
              </div>
            </section>
          </div>
        )}
      </div>

      <footer className="mx-auto max-w-[1200px] px-4 pb-8 text-[10px] text-slate-600 sm:px-6">
        <div className="flex items-center gap-2 border-t border-white/10 pt-6"><ShieldCheck className="h-3.5 w-3.5" /> Authorized systems only · Evidence-first security</div>
      </footer>
    </main>
  );
}
