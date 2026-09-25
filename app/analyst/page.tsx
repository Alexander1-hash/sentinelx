"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { ArrowLeft, BrainCircuit, Loader2, ShieldAlert, ShieldCheck } from "lucide-react";

type AnalystResponse = {
  answer: string;
  topFinding: {
    id: string;
    title: string;
    severity: string;
    summary: string | null;
    remediation: string | null;
  } | null;
  findingsReviewed: number;
  evidenceReviewed: number;
  evidence: Array<{
    id: string;
    title: string;
    source: string;
    observedAt: string;
    summary: string | null;
  }>;
  suggestedNextStep: string;
  boundary: string;
  patternsReviewed?: number;
  securityPatterns?: Array<{ pattern: string; title: string; detail: string; confidence: string; firstObserved: string; lastObserved: string; sequence?: string[] }>;
};

export default function AnalystPage() {
  const [question, setQuestion] = useState("");
  const [response, setResponse] = useState<AnalystResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");

  async function ask(event: FormEvent) {
    event.preventDefault();
    if (!question.trim()) return;

    setLoading(true);
    setMessage("");

    try {
      const result = await fetch("/api/security/analyst", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question }),
      });
      const data = await result.json();

      if (!result.ok) {
        setMessage(data.error ?? "The Security Analyst could not answer.");
        return;
      }

      setResponse(data);
    } catch {
      setMessage("The Security Analyst could not connect to the Security Brain.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#071018] text-slate-100">
      <header className="border-b border-white/10 bg-[#071018]/95">
        <div className="mx-auto flex max-w-[1100px] items-center justify-between gap-3 px-4 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
              <BrainCircuit className="h-5 w-5" />
            </div>
            <div>
              <p className="font-semibold text-white">Security Analyst</p>
              <p className="text-[11px] text-slate-500">Evidence-grounded intelligence</p>
            </div>
          </div>
          <Link href="/" className="inline-flex items-center gap-2 rounded-xl border border-white/10 px-3 py-2 text-xs text-slate-400 hover:text-white">
            <ArrowLeft className="h-3.5 w-3.5" /> Command Center
          </Link>
        </div>
      </header>

      <div className="mx-auto max-w-[1100px] px-4 py-8 sm:px-6">
        <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">Security intelligence</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Ask the Security Brain</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
          Ask questions about the security data SentinelX has actually observed. Answers stay inside the organization&apos;s stored evidence and findings.
        </p>

        <form onSubmit={ask} className="mt-7 rounded-3xl border border-white/10 bg-white/[0.025] p-5 sm:p-6">
          <label htmlFor="security-question" className="text-xs font-semibold uppercase tracking-wider text-slate-500">
            Security question
          </label>
          <textarea
            id="security-question"
            value={question}
            onChange={(event) => setQuestion(event.target.value)}
            placeholder="What should I investigate first? Why does this finding matter? What evidence supports the current risk?"
            rows={4}
            className="mt-3 w-full resize-none rounded-2xl border border-white/10 bg-black/20 p-4 text-sm text-white outline-none placeholder:text-slate-700 focus:border-cyan-300/30"
          />
          <div className="mt-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-[10px] text-slate-600">No unsupported conclusions. No fabricated telemetry.</p>
            <button
              type="submit"
              disabled={loading || !question.trim()}
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-300 px-5 py-3 text-xs font-semibold text-slate-950 disabled:opacity-50"
            >
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <BrainCircuit className="h-4 w-4" />}
              Analyze evidence
            </button>
          </div>
        </form>

        {message && <div className="mt-5 rounded-xl border border-rose-400/10 bg-rose-400/[0.04] p-4 text-sm text-rose-200">{message}</div>}

        {response && (
          <div className="mt-6 space-y-5">
            <section className="rounded-3xl border border-cyan-400/10 bg-cyan-400/[0.025] p-5 sm:p-6">
              <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">Analyst conclusion</p>
              <p className="mt-3 text-sm leading-7 text-slate-300">{response.answer}</p>
              <div className="mt-5 grid gap-3 sm:grid-cols-2">
                <Stat label="Findings reviewed" value={response.findingsReviewed} />
                <Stat label="Evidence reviewed" value={response.evidenceReviewed} />
              </div>
            </section>

            {response.topFinding && (
              <section className="rounded-3xl border border-white/10 bg-white/[0.025] p-5 sm:p-6">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Highest-severity finding</p>
                    <h2 className="mt-1 text-lg font-semibold text-white">{response.topFinding.title}</h2>
                  </div>
                  <span className="w-fit rounded-full bg-amber-400/10 px-2 py-1 text-[9px] uppercase tracking-wider text-amber-200">
                    {response.topFinding.severity}
                  </span>
                </div>
                <p className="mt-4 text-sm leading-6 text-slate-400">{response.topFinding.summary ?? "No finding summary was recorded."}</p>
                <div className="mt-4 rounded-2xl border border-white/10 bg-black/10 p-4">
                  <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">Recorded remediation guidance</p>
                  <p className="mt-2 text-xs leading-5 text-slate-500">{response.topFinding.remediation ?? "No remediation guidance was recorded."}</p>
                </div>
              </section>
            )}

            {response.securityPatterns?.length ? (
              <section className="rounded-3xl border border-violet-400/10 bg-violet-400/[0.025] p-5 sm:p-6">
                <div className="flex items-end justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-violet-200">Temporal pattern context</p>
                    <p className="mt-1 text-[10px] text-slate-600">{response.patternsReviewed ?? response.securityPatterns.length} recorded pattern context item(s)</p>
                  </div>
                  <Link href="/history" className="text-[10px] uppercase tracking-wider text-slate-500 hover:text-white">History</Link>
                </div>
                <div className="mt-4 space-y-3">
                  {response.securityPatterns.map((pattern) => (
                    <div key={pattern.title + pattern.lastObserved} className="rounded-2xl border border-white/10 p-4">
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <span className={pattern.pattern === "security_sequence" ? "rounded-full bg-orange-400/10 px-2 py-1 text-[9px] uppercase tracking-wider text-orange-200" : "rounded-full bg-violet-400/10 px-2 py-1 text-[9px] uppercase tracking-wider text-violet-200"}>
                            {pattern.pattern === "security_sequence" ? "security sequence" : pattern.pattern.replaceAll("_", " ")}
                          </span>
                          <p className="mt-2 text-sm font-medium text-white">{pattern.title}</p>
                        </div>
                        <span className="rounded-full bg-violet-400/10 px-2 py-1 text-[9px] uppercase tracking-wider text-violet-200">{pattern.confidence}</span>
                      </div>
                      {pattern.pattern === "security_sequence" && pattern.sequence?.length ? (
                        <div className="mt-4 flex flex-wrap items-center gap-2">
                          {pattern.sequence.map((step, index) => (
                            <span key={step + index} className="flex items-center gap-2">
                              <span className="rounded-lg border border-white/10 bg-black/10 px-2.5 py-2 text-[10px] text-slate-300">{step}</span>
                              {index < pattern.sequence!.length - 1 && <span className="text-orange-300">→</span>}
                            </span>
                          ))}
                        </div>
                      ) : null}
                      <p className="mt-2 text-xs leading-5 text-slate-500">{pattern.detail}</p>
                      <p className="mt-2 text-[9px] text-slate-600">Last observed {new Date(pattern.lastObserved).toLocaleString()}</p>
                    </div>
                  ))}
                </div>
                <p className="mt-4 rounded-xl border border-amber-400/10 bg-amber-400/[0.025] p-3 text-[9px] leading-4 text-slate-600">Pattern context describes recorded history. It does not prove current compromise or current security state.</p>
              </section>
            ) : null}

            <section className="rounded-3xl border border-white/10 bg-white/[0.025] p-5 sm:p-6">
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Supporting evidence</p>
              {response.evidence.length ? (
                <div className="mt-4 space-y-3">
                  {response.evidence.map((item) => (
                    <div key={item.id} className="rounded-2xl border border-white/10 p-4">
                      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                        <p className="text-sm font-medium text-white">{item.title}</p>
                        <span className="text-[9px] uppercase tracking-wider text-slate-600">{item.source}</span>
                      </div>
                      <p className="mt-2 text-xs leading-5 text-slate-500">{item.summary ?? "No summary recorded."}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="mt-4 text-sm text-slate-600">No supporting evidence records matched the current question.</p>
              )}
            </section>

            <section className="rounded-2xl border border-orange-400/10 bg-orange-400/[0.025] p-4">
              <p className="text-xs font-semibold text-orange-200">Next step</p>
              <p className="mt-2 text-[11px] leading-5 text-slate-500">{response.suggestedNextStep}</p>
              <p className="mt-3 text-[10px] leading-5 text-slate-600">{response.boundary}</p>
            </section>

            <Link href="/actions" className="inline-flex items-center gap-2 rounded-xl border border-white/10 px-4 py-3 text-xs font-semibold text-slate-300 hover:bg-white/5">
              <ShieldAlert className="h-4 w-4" /> Review Security Actions
            </Link>
          </div>
        )}

        <div className="mt-8 flex items-center gap-2 border-t border-white/10 pt-6 text-[10px] text-slate-600">
          <ShieldCheck className="h-3.5 w-3.5" /> Evidence-first · Authorized systems only
        </div>
      </div>
    </main>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-black/10 p-4">
      <p className="text-[10px] uppercase tracking-wider text-slate-600">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-white">{value}</p>
    </div>
  );
}
