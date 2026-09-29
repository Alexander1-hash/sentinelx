"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

type Action = {
  id: string;
  action_type: string;
  status: string;
  result?: { verification?: { state?: string; summary?: string } };
  created_at: string;
};

const labels: Record<string, string> = {
  investigate_asset: "Investigate asset",
  review_finding: "Review finding",
  contain_asset: "Contain asset",
  disable_integration: "Disable integration",
  revoke_access: "Revoke access",
  isolate_endpoint: "Isolate endpoint",
  block_indicator: "Block indicator",
};

export default function VerificationPage() {
  const [actions, setActions] = useState<Action[]>([]);
  const [selected, setSelected] = useState("");
  const [state, setState] = useState("resolved");
  const [summary, setSummary] = useState("");
  const [evidence, setEvidence] = useState("");
  const [reference, setReference] = useState("");
  const [message, setMessage] = useState("");

  async function load() {
    const response = await fetch("/api/security/actions", { cache: "no-store" });
    const data = await response.json();
    if (response.ok) setActions(Array.isArray(data.actions) ? data.actions : []);
    else setMessage(data.error ?? "Unable to load actions.");
  }

  useEffect(() => { void load(); }, []);

  const eligible = actions.filter((item) => item.status === "completed" || item.status === "failed");

  async function record(actionId: string) {
    setMessage("");
    const response = await fetch("/api/security/actions/verification", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        actionId,
        state,
        summary,
        evidence: [{ type: "post_response_observation", source: "operator_verification", summary: evidence, reference }],
      }),
    });
    const data = await response.json();
    setMessage(response.ok ? "Verification recorded in existing Trinorin security memory." : (data.error ?? "Unable to record verification."));
    if (response.ok) {
      setSelected("");
      setSummary("");
      setEvidence("");
      setReference("");
      await load();
    }
  }

  return (
    <main className="min-h-screen bg-[#071018] px-4 py-8 text-slate-100">
      <div className="mx-auto max-w-4xl">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-emerald-300">Verify → Learn</p>
            <h1 className="mt-2 text-3xl font-semibold text-white">Response Verification</h1>
            <p className="mt-2 text-sm text-slate-500">Record explicit post-response evidence without creating another memory store.</p>
          </div>
          <Link href="/actions" className="rounded-lg border border-white/10 px-3 py-2 text-xs text-slate-400">Actions</Link>
        </div>

        {message && <p className="mt-5 rounded-xl border border-cyan-400/10 bg-cyan-400/5 p-3 text-sm text-cyan-200">{message}</p>}

        <div className="mt-6 rounded-2xl border border-amber-400/10 bg-amber-400/5 p-4 text-xs leading-5 text-slate-400">
          Verification is separate from execution outcome. It must use explicit evidence; missing telemetry is not treated as resolution.
        </div>

        <section className="mt-6 space-y-3">
          {eligible.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-white/10 p-8 text-center text-sm text-slate-600">No completed or failed response is ready for verification.</div>
          ) : eligible.map((action) => {
            const verification = action.result?.verification;
            return (
              <article key={action.id} className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h2 className="text-sm font-medium text-white">{labels[action.action_type] ?? action.action_type.replaceAll("_", " ")}</h2>
                    <p className="mt-1 text-[10px] text-slate-600">{action.status} · {new Date(action.created_at).toLocaleString()}</p>
                  </div>
                  <span className="rounded-full bg-white/5 px-2 py-1 text-[9px] text-slate-400">{verification?.state ?? "awaiting verification"}</span>
                </div>

                {verification ? (
                  <div className="mt-3 rounded-xl border border-emerald-400/10 bg-emerald-400/5 p-3 text-xs text-slate-400">
                    <p className="font-medium text-emerald-200">Verification recorded</p>
                    <p className="mt-2">{verification.summary}</p>
                  </div>
                ) : selected === action.id ? (
                  <div className="mt-3 space-y-2">
                    <select value={state} onChange={(e) => setState(e.target.value)} className="w-full rounded-lg border border-white/10 bg-[#071018] p-2 text-xs text-white">
                      <option value="resolved">Resolved</option>
                      <option value="persisting">Persisting</option>
                      <option value="returned">Returned</option>
                      <option value="unknown">Unknown</option>
                    </select>
                    <textarea value={summary} onChange={(e) => setSummary(e.target.value)} placeholder="Verification summary" className="w-full rounded-lg border border-white/10 bg-[#071018] p-2 text-xs text-white" rows={3} />
                    <textarea value={evidence} onChange={(e) => setEvidence(e.target.value)} placeholder="Explicit evidence observed after the response" className="w-full rounded-lg border border-white/10 bg-[#071018] p-2 text-xs text-white" rows={3} />
                    <input value={reference} onChange={(e) => setReference(e.target.value)} placeholder="Evidence/event/ticket reference" className="w-full rounded-lg border border-white/10 bg-[#071018] p-2 text-xs text-white" />
                    <div className="grid grid-cols-2 gap-2">
                      <button disabled={!summary.trim() || !evidence.trim() || !reference.trim()} onClick={() => void record(action.id)} className="rounded-lg bg-emerald-300 p-2 text-xs font-semibold text-slate-950 disabled:opacity-40">Record verification</button>
                      <button onClick={() => setSelected("")} className="rounded-lg border border-white/10 p-2 text-xs text-slate-400">Close</button>
                    </div>
                  </div>
                ) : (
                  <button onClick={() => setSelected(action.id)} className="mt-3 rounded-lg border border-emerald-400/20 bg-emerald-400/10 px-3 py-2 text-xs font-semibold text-emerald-200">Record post-response verification</button>
                )}
              </article>
            );
          })}
        </section>
      </div>
    </main>
  );
}
