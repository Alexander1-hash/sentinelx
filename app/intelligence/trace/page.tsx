"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, BrainCircuit, CheckCircle2, Clock3, GitBranch, ShieldAlert, Sparkles } from "lucide-react";

type TraceStage = {
  stage: string;
  status: string;
  inputIds: string[];
  outputIds: string[];
  confidence: number | null;
  rationale: string[];
  unresolved: string[];
};

type TraceRecord = {
  id: string;
  findingId: string | null;
  title: string;
  summary: string;
  state: string;
  occurredAt: string;
  traceId: string;
  confidence: number | null;
  decision: string | null;
  trace: {
    stages: TraceStage[];
    unresolvedQuestions: string[];
    evidenceChain: string[];
    boundary: string;
  } | null;
};

export default function ReasoningTracePage() {
  const [traces, setTraces] = useState<TraceRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [persisting, setPersisting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    try {
      const response = await fetch("/api/security/reasoning-trace", { cache: "no-store" });
      if (response.ok) {
        const data = await response.json();
        setTraces(Array.isArray(data.traces) ? data.traces : []);
      }
    } finally {
      setLoading(false);
    }
  }

  async function persist() {
    setPersisting(true);
    setMessage(null);
    try {
      const response = await fetch("/api/security/reasoning-trace", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const data = await response.json();
      if (!response.ok) {
        setMessage(data.error ?? "Could not persist reasoning traces.");
        return;
      }
      setMessage(`Persisted ${data.count ?? 0} reasoning trace(s) into Security Memory.`);
      await load();
    } catch {
      setMessage("Reasoning trace persistence failed.");
    } finally {
      setPersisting(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  return (
    <main className="min-h-screen bg-[#071018] text-slate-100">
      <header className="border-b border-white/10 bg-[#071018]/95">
        <div className="mx-auto flex max-w-[1200px] items-center justify-between gap-4 px-4 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
              <BrainCircuit className="h-5 w-5" />
            </div>
            <div>
              <p className="font-semibold text-white">Reasoning Trace</p>
              <p className="text-[11px] text-slate-500">Persistent, inspectable intelligence history</p>
            </div>
          </div>
          <Link href="/intelligence" className="inline-flex items-center gap-2 text-xs text-slate-400 hover:text-white">
            <ArrowLeft className="h-3.5 w-3.5" /> Intelligence
          </Link>
        </div>
      </header>

      <div className="mx-auto max-w-[1200px] px-4 py-8 sm:px-6">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-3xl">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">Inspectable intelligence</p>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white sm:text-4xl">Why Trinorin reached a conclusion.</h1>
            <p className="mt-3 text-sm leading-6 text-slate-500">
              Each persisted trace records the path from observed signals and evidence through hypotheses, contradictions, decisions, response recommendations, verification and learned state.
            </p>
          </div>
          <button
            type="button"
            onClick={() => void persist()}
            disabled={persisting}
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-400 px-4 py-3 text-xs font-semibold text-slate-950 disabled:opacity-50"
          >
            <Sparkles className="h-4 w-4" />
            {persisting ? "Persisting…" : "Capture current reasoning"}
          </button>
        </div>

        {message && <p className="mt-4 rounded-xl border border-cyan-400/15 bg-cyan-400/[0.04] p-3 text-xs text-cyan-100">{message}</p>}

        <section className="mt-6 grid gap-3 sm:grid-cols-3">
          <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
            <p className="text-[10px] uppercase tracking-wider text-slate-600">Persisted traces</p>
            <p className="mt-2 text-2xl font-semibold text-white">{loading ? "—" : traces.length}</p>
          </div>
          <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
            <p className="text-[10px] uppercase tracking-wider text-slate-600">Latest stages</p>
            <p className="mt-2 text-2xl font-semibold text-white">{loading ? "—" : traces[0]?.trace?.stages.length ?? 0}</p>
          </div>
          <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
            <p className="text-[10px] uppercase tracking-wider text-slate-600">Historical confidence</p>
            <p className="mt-2 text-2xl font-semibold text-white">{loading ? "—" : traces[0]?.confidence == null ? "—" : `${traces[0].confidence}%`}</p>
          </div>
        </section>

        <div className="mt-6 space-y-4">
          {!loading && !traces.length && (
            <div className="rounded-3xl border border-dashed border-white/10 p-8 text-center">
              <p className="text-sm font-semibold text-white">No persisted reasoning trace yet.</p>
              <p className="mt-2 text-xs text-slate-500">Capture the current intelligence state to begin the longitudinal reasoning history.</p>
            </div>
          )}

          {traces.map((record) => (
            <article key={record.id} className="rounded-3xl border border-white/10 bg-white/[0.025] p-5 sm:p-6">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded-full bg-cyan-400/10 px-2 py-1 text-[9px] font-semibold uppercase tracking-wider text-cyan-200">{record.state}</span>
                    {record.decision && <span className="rounded-full bg-white/5 px-2 py-1 text-[9px] uppercase tracking-wider text-slate-400">next: {record.decision}</span>}
                  </div>
                  <h2 className="mt-3 text-base font-semibold text-white">{record.title}</h2>
                  <p className="mt-1 text-xs text-slate-500">{record.summary}</p>
                </div>
                <div className="flex items-center gap-2 text-[10px] text-slate-600">
                  <Clock3 className="h-3.5 w-3.5" />
                  {new Date(record.occurredAt).toLocaleString()}
                </div>
              </div>

              {record.trace && (
                <>
                  <div className="mt-5 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                    {record.trace.stages.map((stage) => (
                      <div key={stage.stage} className="rounded-2xl border border-white/10 bg-black/10 p-3">
                        <div className="flex items-center justify-between gap-2">
                          <p className="text-[9px] font-semibold uppercase tracking-wider text-cyan-200">{stage.stage.replaceAll("_", " ")}</p>
                          <CheckCircle2 className="h-3.5 w-3.5 text-slate-500" />
                        </div>
                        <p className="mt-2 text-[10px] text-slate-400">{stage.status}</p>
                        {stage.confidence != null && <p className="mt-1 text-[9px] text-slate-600">{stage.confidence}% stage confidence</p>}
                      </div>
                    ))}
                  </div>

                  <div className="mt-5 grid gap-4 lg:grid-cols-2">
                    <div className="rounded-2xl border border-white/10 bg-black/10 p-4">
                      <div className="flex items-center gap-2"><GitBranch className="h-4 w-4 text-cyan-300" /><p className="text-xs font-semibold text-white">Evidence chain</p></div>
                      <p className="mt-2 text-[10px] leading-5 text-slate-500">{record.trace.evidenceChain.length ? record.trace.evidenceChain.join(" → ") : "No evidence chain recorded."}</p>
                    </div>
                    <div className="rounded-2xl border border-amber-400/10 bg-amber-400/[0.02] p-4">
                      <div className="flex items-center gap-2"><ShieldAlert className="h-4 w-4 text-amber-300" /><p className="text-xs font-semibold text-white">Unresolved questions</p></div>
                      <ul className="mt-2 space-y-1">
                        {(record.trace.unresolvedQuestions.length ? record.trace.unresolvedQuestions : ["No unresolved question was recorded."]).slice(0, 8).map((item) => (
                          <li key={item} className="text-[10px] leading-4 text-slate-500">• {item}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </>
              )}
            </article>
          ))}
        </div>

        <p className="mt-6 text-[10px] leading-5 text-slate-600">
          {traces[0]?.trace?.boundary ?? "Persisted reasoning is an audit and explanation structure. It does not establish compromise, attribution, causation, or response success."}
        </p>
      </div>
    </main>
  );
}
