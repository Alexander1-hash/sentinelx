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

type Finding = {\n  id: string;\n  asset_id: string | null;\n  title: string;\n  finding_type: string;\n  severity: "low" | "medium" | "high" | "critical";\n  status: "open" | "acknowledged" | "resolved" | "dismissed";\n  summary: string | null;\n  remediation: string | null;\n  detected_at: string;\n};\n\ntype Relationship = {
  id: string;
  source_asset_id: string;
  target_asset_id: string;
  relationship_type: string;
  confidence: number | null;
  status: "proposed" | "confirmed" | "rejected";
  evidence: Record<string, unknown>;
  evidence_source: string;
  created_at: string;
};

export default function SecurityBrainPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [relationships, setRelationships] = useState<Relationship[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");
  const [reviewingId, setReviewingId] = useState("");
  const [discovering, setDiscovering] = useState(false);\n  const [analyzing, setAnalyzing] = useState(false);\n  const [findings, setFindings] = useState<Finding[]>([]);

  const [sourceAssetId, setSourceAssetId] = useState("");
  const [targetAssetId, setTargetAssetId] = useState("");
  const [relationshipType, setRelationshipType] = useState("depends_on");
  const [addingRelationship, setAddingRelationship] = useState(false);

  async function loadGraph() {
    setLoading(true);
    try {
      const [assetsResponse, relationshipsResponse, findingsResponse] = await Promise.all([
        fetch("/api/security/assets", { cache: "no-store" }),
        fetch("/api/security/relationships", { cache: "no-store" }),\n        fetch("/api/security/analysis", { cache: "no-store" }),
      ]);

      const assetsData = await assetsResponse.json();
      const relationshipsData = await relationshipsResponse.json();\n      const findingsData = await (async () => {\n        try { return await fetch("/api/security/analysis", { cache: "no-store" }).then((response) => response.json()); } catch { return { findings: [] }; }\n      })();

      if (!assetsResponse.ok) {
        setMessage(assetsData.error ?? "Unable to load assets.");
        return;
      }

      if (!relationshipsResponse.ok) {
        setMessage(relationshipsData.error ?? "Unable to load relationships.");
        return;
      }

      setAssets(assetsData.assets ?? []);
      setRelationships(relationshipsData.relationships ?? []);\n      setFindings(findingsData.findings ?? []);
    } catch {
      setMessage("Security Graph could not be loaded.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadGraph();
  }, []);

  async function addRelationship(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAddingRelationship(true);
    setMessage("");

    try {
      const response = await fetch("/api/security/relationships", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sourceAssetId,
          targetAssetId,
          relationshipType,
          confidence: 1,
          evidence: { source: "operator_provided", status: "operator_confirmed" },
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setMessage(data.error ?? "Unable to create relationship.");
        return;
      }

      setSourceAssetId("");
      setTargetAssetId("");
      setMessage("Relationship recorded as operator-confirmed evidence.");
      await loadGraph();
    } catch {
      setMessage("Unable to create relationship.");
    } finally {
      setAddingRelationship(false);
    }
  }

  async function runAnalysis() {\n    setAnalyzing(true);\n    setMessage("");\n\n    try {\n      const response = await fetch("/api/security/analysis", { method: "POST" });\n      const data = await response.json();\n      if (!response.ok) {\n        setMessage(data.error ?? "Unable to analyze security evidence.");\n        return;\n      }\n      setMessage(data.message ?? "Security Brain analysis completed.");\n      await loadGraph();\n    } catch {\n      setMessage("Unable to run Security Brain analysis.");\n    } finally {\n      setAnalyzing(false);\n    }\n  }\n\n  async function runDiscovery() {
    setDiscovering(true);
    setMessage("");

    try {
      const response = await fetch("/api/security/discovery", {
        method: "POST",
      });

      const data = await response.json();

      if (!response.ok) {
        setMessage(data.error ?? "Unable to run relationship discovery.");
        return;
      }

      setMessage(
        data.candidatesCreated
          ? `${data.candidatesCreated} new relationship candidate${data.candidatesCreated === 1 ? "" : "s"} discovered. Review them before confirmation.`
          : data.message ?? "No new relationship candidates were discovered."
      );
      await loadGraph();
    } catch {
      setMessage("Unable to run Security Brain discovery.");
    } finally {
      setDiscovering(false);
    }
  }

  async function reviewRelationship(id: string, status: "confirmed" | "rejected") {
    setReviewingId(id);
    setMessage("");

    try {
      const response = await fetch("/api/security/relationships", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, status }),
      });

      const data = await response.json();

      if (!response.ok) {
        setMessage(data.error ?? "Unable to review relationship.");
        return;
      }

      setMessage(status === "confirmed" ? "Relationship confirmed." : "Relationship rejected.");
      await loadGraph();
    } catch {
      setMessage("Unable to review relationship.");
    } finally {
      setReviewingId("");
    }
  }

  const assetMap = useMemo(
    () => new Map(assets.map((asset) => [asset.id, asset])),
    [assets]
  );

  const activeRelationships = useMemo(
    () => relationships.filter((relationship) => relationship.status !== "rejected"),
    [relationships]
  );

  const proposedRelationships = useMemo(
    () => relationships.filter((relationship) => relationship.status === "proposed"),
    [relationships]
  );

  const confirmedRelationships = useMemo(
    () => relationships.filter((relationship) => relationship.status === "confirmed"),
    [relationships]
  );

  const connectedAssetIds = useMemo(() => {
    const ids = new Set<string>();

    confirmedRelationships.forEach((relationship) => {
      ids.add(relationship.source_asset_id);
      ids.add(relationship.target_asset_id);
    });

    return ids;
  }, [confirmedRelationships]);

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
          <div className="flex items-center gap-2">
            <button
              onClick={() => void runAnalysis()}\n              disabled={analyzing || loading || !assets.length}\n              className="inline-flex items-center gap-2 rounded-xl border border-cyan-400/20 bg-cyan-400/10 px-3 py-2 text-xs font-semibold text-cyan-200 disabled:opacity-50"\n            >\n              {analyzing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <BrainCircuit className="h-3.5 w-3.5" />}\n              {analyzing ? "Analyzing..." : "Analyze evidence"}\n            </button>\n            <button\n              onClick={() => void runDiscovery()}
              disabled={discovering || loading || !assets.length}
              className="inline-flex items-center gap-2 rounded-xl border border-cyan-400/20 bg-cyan-400/10 px-3 py-2 text-xs font-semibold text-cyan-200 disabled:opacity-50"
            >
              {discovering ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
              {discovering ? "Discovering..." : "Run discovery"}
            </button>
            <Link href="/" className="inline-flex items-center gap-2 rounded-xl border border-white/10 px-3 py-2 text-xs text-slate-400 hover:text-white">
              <ArrowLeft className="h-3.5 w-3.5" /> Command Center
            </Link>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-[1200px] px-4 py-8 sm:px-6">
        <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">Security intelligence</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Security Graph</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
          SentinelX separates what is known, what is discovered, and what is confirmed. Proposed relationships never become confirmed evidence automatically.
        </p>

        <div className="mt-6 grid gap-3 sm:grid-cols-4">
          <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Nodes</p>
            <p className="mt-2 text-2xl font-semibold text-white">{assets.length}</p>
            <p className="mt-1 text-xs text-slate-600">Registered assets</p>
          </div>
          <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Confirmed</p>
            <p className="mt-2 text-2xl font-semibold text-cyan-200">{confirmedRelationships.length}</p>
            <p className="mt-1 text-xs text-slate-600">Verified graph edges</p>
          </div>
          <div className="rounded-2xl border border-amber-400/10 bg-amber-400/[0.03] p-4">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Needs review</p>
            <p className="mt-2 text-2xl font-semibold text-amber-200">{proposedRelationships.length}</p>
            <p className="mt-1 text-xs text-slate-600">Discovered candidates</p>
          </div>
          <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Unconnected</p>
            <p className="mt-2 text-2xl font-semibold text-slate-200">{Math.max(assets.length - connectedAssetIds.size, 0)}</p>
            <p className="mt-1 text-xs text-slate-600">No confirmed edges</p>
          </div>
        </div>

        {findings.length > 0 && (\n          <section className="mt-6 rounded-3xl border border-rose-400/10 bg-rose-400/[0.025] p-5 sm:p-6">\n            <div className="flex items-center justify-between gap-3">\n              <div>\n                <p className="text-xs font-semibold uppercase tracking-wider text-rose-200">Evidence-backed findings</p>\n                <p className="mt-1 text-[10px] leading-5 text-slate-600">Created only from observed high-impact security or AI security events.</p>\n              </div>\n              <span className="rounded-full bg-white/5 px-2 py-1 text-[9px] uppercase tracking-wider text-slate-500">{findings.length} open</span>\n            </div>\n            <div className="mt-4 grid gap-3 md:grid-cols-2">\n              {findings.filter((finding) => finding.status === "open" || finding.status === "acknowledged").map((finding) => (\n                <div key={finding.id} className="rounded-2xl border border-white/10 bg-black/10 p-4">\n                  <div className="flex items-start justify-between gap-3">\n                    <p className="text-sm font-medium text-white">{finding.title}</p>\n                    <span className="rounded-full bg-white/5 px-2 py-1 text-[9px] uppercase tracking-wider text-rose-200">{finding.severity}</span>\n                  </div>\n                  <p className="mt-2 text-[11px] leading-5 text-slate-500">{finding.summary ?? "Evidence-backed finding requiring investigation."}</p>\n                  <p className="mt-3 text-[10px] text-slate-600">Type: {finding.finding_type.replaceAll("_", " ")}</p>\n                  {finding.remediation && <p className="mt-2 text-[10px] leading-5 text-slate-600">Next step: {finding.remediation}</p>}\n                </div>\n              ))}\n            </div>\n          </section>\n        )}\n\n        {message && (
          <div className="mt-5 rounded-xl border border-cyan-400/10 bg-cyan-400/[0.03] p-4 text-sm text-cyan-200">
            {message}
          </div>
        )}

        {loading ? (
          <div className="mt-8 flex items-center gap-2 text-sm text-slate-500">
            <Loader2 className="h-4 w-4 animate-spin" /> Building verified graph...
          </div>
        ) : !assets.length ? (
          <div className="mt-8 rounded-3xl border border-dashed border-white/10 px-6 py-16 text-center">
            <Boxes className="mx-auto h-9 w-9 text-slate-700" />
            <h2 className="mt-4 font-semibold text-slate-300">The Security Brain has no nodes yet</h2>
            <p className="mx-auto mt-2 max-w-md text-xs leading-5 text-slate-600">
              Register an authorized asset first. SentinelX will not manufacture security entities that have not been observed or provided.
            </p>
            <Link href="/assets" className="mt-5 inline-flex items-center gap-2 rounded-xl bg-cyan-300 px-4 py-3 text-xs font-semibold text-slate-950">
              Add first asset
            </Link>
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
                  const links = activeRelationships.filter(
                    (relationship) =>
                      relationship.source_asset_id === asset.id ||
                      relationship.target_asset_id === asset.id
                  ).length;

                  return (
                    <div key={asset.id} className="rounded-2xl border border-white/10 bg-black/10 p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="font-medium text-white">{asset.name}</p>
                          <p className="mt-1 text-[11px] capitalize text-slate-600">
                            {asset.asset_type.replaceAll("_", " ")} · {asset.environment}
                            {asset.provider ? ` · ${asset.provider}` : ""}
                          </p>
                        </div>
                        <span className="rounded-full bg-white/5 px-2 py-1 text-[9px] uppercase tracking-wider text-slate-500">
                          {asset.criticality}
                        </span>
                      </div>

                      <div className="mt-3 flex flex-wrap items-center gap-3 text-[10px] text-slate-500">
                        <span className="inline-flex items-center gap-1">
                          <GitBranch className="h-3 w-3" /> {links} relationship{links === 1 ? "" : "s"}
                        </span>
                        <span className="inline-flex items-center gap-1">
                          <CircleDashed className="h-3 w-3" /> {asset.metadata?.onboarding?.telemetry ?? "Telemetry not connected"}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </section>

            <section className="rounded-3xl border border-white/10 bg-white/[0.025] p-5 sm:p-6">
              <div className="flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-cyan-300" />
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Discovered intelligence</p>
              </div>

              {proposedRelationships.length > 0 && (
                <div className="mt-5">
                  <p className="text-xs font-semibold text-amber-200">Needs confirmation</p>
                  <p className="mt-1 text-[10px] leading-5 text-slate-600">
                    These candidates came from evidence. Review them before they enter the confirmed graph.
                  </p>

                  <div className="mt-3 space-y-3">
                    {proposedRelationships.map((relationship) => (
                      <div key={relationship.id} className="rounded-2xl border border-amber-400/10 bg-amber-400/[0.025] p-4">
                        <p className="text-sm font-medium text-white">
                          {assetMap.get(relationship.source_asset_id)?.name ?? "Unknown asset"}
                          <span className="mx-2 text-amber-300">→</span>
                          {assetMap.get(relationship.target_asset_id)?.name ?? "Unknown asset"}
                        </p>
                        <p className="mt-1 text-[11px] capitalize text-amber-200/70">
                          {relationship.relationship_type.replaceAll("_", " ")}
                          {relationship.confidence !== null ? ` · ${Math.round(relationship.confidence * 100)}% confidence` : ""}
                        </p>
                        <p className="mt-2 text-[10px] text-slate-600">
                          Evidence source: {relationship.evidence_source}
                        </p>

                        <div className="mt-3 grid grid-cols-2 gap-2">
                          <button
                            disabled={reviewingId === relationship.id}
                            onClick={() => void reviewRelationship(relationship.id, "confirmed")}
                            className="rounded-xl bg-cyan-300 px-3 py-2 text-[10px] font-semibold text-slate-950 disabled:opacity-50"
                          >
                            Confirm
                          </button>
                          <button
                            disabled={reviewingId === relationship.id}
                            onClick={() => void reviewRelationship(relationship.id, "rejected")}
                            className="rounded-xl border border-white/10 px-3 py-2 text-[10px] font-semibold text-slate-400 disabled:opacity-50"
                          >
                            Reject
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="mt-6">
                <p className="text-xs font-semibold text-slate-300">Confirmed graph</p>

                {confirmedRelationships.length ? (
                  <div className="mt-3 space-y-3">
                    {confirmedRelationships.map((relationship) => (
                      <div key={relationship.id} className="rounded-2xl border border-cyan-400/10 bg-cyan-400/[0.025] p-4">
                        <p className="text-sm font-medium text-white">
                          {assetMap.get(relationship.source_asset_id)?.name ?? "Unknown asset"}
                          <span className="mx-2 text-cyan-300">→</span>
                          {assetMap.get(relationship.target_asset_id)?.name ?? "Unknown asset"}
                        </p>
                        <p className="mt-1 text-[11px] capitalize text-cyan-200/70">
                          {relationship.relationship_type.replaceAll("_", " ")}
                          {relationship.confidence !== null ? ` · ${Math.round(relationship.confidence * 100)}% confidence` : ""}
                        </p>
                        <p className="mt-2 text-[10px] leading-5 text-slate-600">
                          Confirmed relationship. It is a reasoning input, not a security finding by itself.
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="mt-3 rounded-2xl border border-dashed border-white/10 p-5">
                    <p className="text-sm font-medium text-slate-300">No confirmed relationships</p>
                    <p className="mt-2 text-xs leading-5 text-slate-600">
                      SentinelX can promote evidence-backed candidates here after operator review.
                    </p>
                  </div>
                )}
              </div>

              <div className="mt-6 rounded-2xl border border-white/10 bg-black/10 p-4">
                <p className="text-xs font-semibold text-white">Connect known assets</p>
                <p className="mt-1 text-[10px] leading-5 text-slate-600">
                  Use this only when you are authorized to confirm the relationship.
                </p>

                <form onSubmit={addRelationship} className="mt-4 space-y-3">
                  <select value={sourceAssetId} onChange={(e) => setSourceAssetId(e.target.value)} required className="w-full rounded-xl border border-white/10 bg-[#071018] px-3 py-3 text-xs text-white">
                    <option value="">Source asset</option>
                    {assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.name}</option>)}
                  </select>

                  <select value={relationshipType} onChange={(e) => setRelationshipType(e.target.value)} className="w-full rounded-xl border border-white/10 bg-[#071018] px-3 py-3 text-xs text-white">
                    {["hosts","resolves_to","depends_on","authenticates_to","connects_to","uses","reads_from","writes_to","calls","protects","managed_by","part_of"].map((type) => (
                      <option key={type} value={type}>{type.replaceAll("_", " ")}</option>
                    ))}
                  </select>

                  <select value={targetAssetId} onChange={(e) => setTargetAssetId(e.target.value)} required className="w-full rounded-xl border border-white/10 bg-[#071018] px-3 py-3 text-xs text-white">
                    <option value="">Target asset</option>
                    {assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.name}</option>)}
                  </select>

                  <button disabled={addingRelationship} className="flex w-full items-center justify-center gap-2 rounded-xl bg-cyan-300 px-3 py-3 text-xs font-semibold text-slate-950 disabled:opacity-50">
                    {addingRelationship ? (
                      <><Loader2 className="h-3.5 w-3.5 animate-spin" /> Recording...</>
                    ) : (
                      <><GitBranch className="h-3.5 w-3.5" /> Confirm relationship</>
                    )}
                  </button>
                </form>
              </div>

              <div className="mt-5 rounded-2xl border border-cyan-400/10 bg-cyan-400/[0.03] p-4">
                <p className="text-xs font-semibold text-cyan-200">Evidence boundary</p>
                <p className="mt-2 text-[11px] leading-5 text-slate-500">
                  SentinelX distinguishes observed evidence, discovered candidates, operator confirmation, and AI analysis. Missing evidence never becomes a security claim.
                </p>
              </div>
            </section>
          </div>
        )}
      </div>

      <footer className="mx-auto max-w-[1200px] px-4 pb-8 text-[10px] text-slate-600 sm:px-6">
        <div className="flex items-center gap-2 border-t border-white/10 pt-6">
          <ShieldCheck className="h-3.5 w-3.5" /> Authorized systems only · Evidence-first security
        </div>
      </footer>
    </main>
  );
}
