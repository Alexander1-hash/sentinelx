"use client";

import { useEffect, useState } from "react";

type Evaluation = {
  findingId: string;
  overall: number;
  evidenceGrounding: number;
  uncertaintyCalibration: number;
  verificationDiscipline: number;
  contextConsistency: number;
  actionability: number;
  safetyBoundary: number;
  strengths: string[];
  gaps: string[];
};

type ResponseData = {
  results: Evaluation[];
  summary: {
    evaluatedFindings: number;
    overall: number;
    dimensions: Record<string, number>;
    boundary: string;
  };
};

export default function EvaluationPage() {
  const [data, setData] = useState<ResponseData | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch("/api/security/evaluation", { cache: "no-store" })
      .then(async (response) => {
        if (!response.ok) throw new Error((await response.json()).error ?? "Evaluation unavailable.");
        return response.json() as Promise<ResponseData>;
      })
      .then(setData)
      .catch((reason) => setError(reason instanceof Error ? reason.message : "Evaluation unavailable."));
  }, []);

  return (
    <main className="min-h-screen bg-[#07090d] px-5 py-8 text-white sm:px-8 lg:px-12">
      <div className="mx-auto max-w-6xl">
        <div className="mb-8">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-violet-300">Trinorin Intelligence Lab</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight">Intelligence evaluation</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
            A deterministic measurement layer for evidence grounding, uncertainty, verification, consistency, actionability and safety boundaries.
          </p>
        </div>

        {error ? <div className="rounded-2xl border border-red-400/20 bg-red-400/5 p-4 text-sm text-red-200">{error}</div> : null}

        {data ? (
          <>
            <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Metric label="Overall" value={data.summary.overall} />
              <Metric label="Findings evaluated" value={data.summary.evaluatedFindings} suffix="" />
              <Metric label="Evidence grounding" value={data.summary.dimensions.evidenceGrounding} />
              <Metric label="Safety boundary" value={data.summary.dimensions.safetyBoundary} />
            </section>

            <section className="mt-5 rounded-3xl border border-white/10 bg-white/[0.025] p-5">
              <h2 className="text-lg font-semibold">Evaluation dimensions</h2>
              <div className="mt-4 grid gap-3 md:grid-cols-2">
                {Object.entries(data.summary.dimensions).map(([key, value]) => (
                  <div key={key} className="rounded-2xl border border-white/10 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-xs capitalize text-slate-400">{key.replace(/([A-Z])/g, " $1")}</span>
                      <span className="text-sm font-semibold">{value}</span>
                    </div>
                    <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/10">
                      <div className="h-full rounded-full bg-violet-400" style={{ width: `${value}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <section className="mt-5 space-y-3">
              {data.results.map((item) => (
                <article key={item.findingId} className="rounded-3xl border border-white/10 bg-white/[0.025] p-5">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-xs uppercase tracking-wider text-slate-500">Finding</p>
                      <p className="mt-1 font-mono text-xs text-slate-300">{item.findingId}</p>
                    </div>
                    <span className="rounded-full bg-violet-400/10 px-3 py-1 text-xs font-semibold text-violet-200">{item.overall}/100</span>
                  </div>
                  <div className="mt-4 grid gap-2 sm:grid-cols-3 lg:grid-cols-6">
                    {[
                      ["Evidence", item.evidenceGrounding],
                      ["Uncertainty", item.uncertaintyCalibration],
                      ["Verification", item.verificationDiscipline],
                      ["Consistency", item.contextConsistency],
                      ["Actionability", item.actionability],
                      ["Safety", item.safetyBoundary],
                    ].map(([label, value]) => (
                      <div key={String(label)} className="rounded-xl bg-black/15 p-3">
                        <p className="text-[9px] uppercase tracking-wider text-slate-600">{label}</p>
                        <p className="mt-1 text-sm font-semibold">{value}</p>
                      </div>
                    ))}
                  </div>
                  {(item.strengths.length || item.gaps.length) ? (
                    <div className="mt-4 grid gap-3 md:grid-cols-2">
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-emerald-300">Strengths</p>
                        <ul className="mt-2 space-y-1 text-xs leading-5 text-slate-400">{item.strengths.map((x) => <li key={x}>• {x}</li>)}</ul>
                      </div>
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-amber-300">Improvement gaps</p>
                        <ul className="mt-2 space-y-1 text-xs leading-5 text-slate-400">{item.gaps.map((x) => <li key={x}>• {x}</li>)}</ul>
                      </div>
                    </div>
                  ) : null}
                </article>
              ))}
            </section>

            <p className="mt-6 text-xs leading-5 text-slate-600">{data.summary.boundary}</p>
          </>
        ) : !error ? <p className="text-sm text-slate-500">Evaluating current intelligence context…</p> : null}
      </div>
    </main>
  );
}

function Metric({ label, value, suffix = "%" }: { label: string; value: number; suffix?: string }) {
  return (
    <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-5">
      <p className="text-[10px] uppercase tracking-wider text-slate-600">{label}</p>
      <p className="mt-2 text-3xl font-semibold">{value}{suffix}</p>
    </div>
  );
}
