"use client";

import { FormEvent, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, BrainCircuit, Loader2, ShieldAlert, ShieldCheck } from "lucide-react";

type InvestigationContext = {
  affectedAsset: { id: string; name: string; asset_type: string; status: string } | null;
  blastRadius: Array<{
    asset: { id: string; name: string; asset_type: string; status: string };
    hops: number;
    confidence: number;
    chain: string[];
  }>;
  supportingEvidence: Array<{ id: string; title: string; source: string; observedAt: string; summary: string | null }>;
  unknowns: string[];
};

type MultiSignalCorrelation = {
  findingId: string;
  rootAssetId: string | null;
  timeWindowMinutes: number;
  correlationConfidence: "strong" | "moderate" | "limited";
  confidenceReasons: string[];
  timeline: Array<{ observedAt: string; signalType: "event" | "evidence" | "identity"; title: string; source: string; assetId: string | null; identity: string | null }>;
  signalCount: number;
  eventSignals: Array<{ id: string; type: string; source: string; observedAt: string; assetId: string | null; title: string }>;
  evidenceSignals: Array<{ id: string; type: string; source: string; observedAt: string; assetId: string | null; title: string }>;
  identitySignals: Array<{ id: string; identity: string; observedAt: string; source: string }>;
  graphContext: Array<{ sourceAssetId: string; targetAssetId: string; relationshipType: string; confidence: number | null }>;
  timing: { findingDetectedAt: string | null; earliestObservedAt: string | null; latestObservedAt: string | null; spanMinutes: number | null };
  correlationReasons: string[];
};

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
  investigation?: InvestigationContext;
  multiSignalCorrelation?: MultiSignalCorrelation | null;
  patternsReviewed?: number;
  securityPatterns?: Array<{ pattern: string; title: string; detail: string; confidence: string; firstObserved: string; lastObserved: string; sequence?: string[] }>;
  historicalContext?: {
    priorInvestigations: Array<{ occurred_at: string; title: string; summary: string; blast_radius_count: number | null; supporting_evidence_count: number | null }>;
    operatorDecisions: Array<{ occurred_at: string; title: string; summary: string; state: string; action_id: string | null; action_type: string | null; authorization_state: string | null }>;
    responseOutcomes: Array<{ occurred_at: string; title: string; summary: string; state: string; action_id: string | null; action_type: string | null; executor_type: string | null; execution_reference: string | null; evidence: Array<{ type?: string; source?: string; summary?: string; reference?: string }> }>;
    responseLearning?: Array<{ occurred_at: string; action_type: string | null; state: string; evidence_count: number; summary: string; matchContext: string }>;
    priorFindingStates: Array<{
      occurred_at: string;
      title: string;
      summary: string;
      previous_state: string | null;
      current_state: string | null;
    }>;
  };
};

type LifecycleStep = {
  key: string;
  label: string;
  description: string;
  state: "current" | "recorded" | "pending";
};

export default function AnalystPage() {
  const [question, setQuestion] = useState("");
  const [response, setResponse] = useState<AnalystResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [investigating, setInvestigating] = useState(false);
  const [verificationLoading, setVerificationLoading] = useState(false);
  const [verificationChanges, setVerificationChanges] = useState<Array<{
    id: string;
    title: string;
    detail: string;
    observedAt: string;
    verificationState?: "improved" | "observed" | "uncertain" | "awaiting_evidence";
  }>>([]);

  async function investigateFindingById(findingId: string) {
    setInvestigating(true);
    setMessage("");

    try {
      const result = await fetch("/api/security/analyst", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ findingId, mode: "investigate" }),
      });
      const data = await result.json();

      if (!result.ok) {
        setMessage(data.error ?? "The investigation could not be completed.");
        return;
      }

      setResponse(data);
      await loadVerificationChanges(findingId);
    } catch {
      setMessage("The investigation could not connect to the Security Brain.");
    } finally {
      setInvestigating(false);
    }
  }

  async function loadVerificationChanges(findingId: string) {
    setVerificationLoading(true);
    try {
      const result = await fetch(`/api/security/changes?findingId=${encodeURIComponent(findingId)}`);
      const data = await result.json();
      if (result.ok) {
        setVerificationChanges((data.changes ?? []).filter((item: { kind?: string }) => item.kind === "verification"));
      }
    } finally {
      setVerificationLoading(false);
    }
  }

  async function investigateFinding() {
    if (!response?.topFinding) return;
    await investigateFindingById(response.topFinding.id);
  }

  useEffect(() => {
    const findingId = new URLSearchParams(window.location.search).get("findingId");
    if (findingId) void investigateFindingById(findingId);
  }, []);

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
      setVerificationChanges([]);
    } catch {
      setMessage("The Security Analyst could not connect to the Security Brain.");
    } finally {
      setLoading(false);
    }
  }

  const lifecycleSteps: LifecycleStep[] = response?.topFinding
    ? [
        {
          key: "finding",
          label: "Finding",
          description: "A recorded security finding is in focus.",
          state: "current",
        },
        {
          key: "investigate",
          label: "Investigate",
          description: response.investigation
            ? "Affected assets, relationships, evidence, and unknowns have been inspected."
            : "Open the investigation to establish affected assets and evidence.",
          state: response.investigation ? "recorded" : "current",
        },
        {
          key: "decide",
          label: "Decide",
          description: response.historicalContext?.operatorDecisions?.length
            ? "An operator decision is recorded in Security Brain history."
            : "No operator authorization decision is recorded for this finding yet.",
          state: response.historicalContext?.operatorDecisions?.length ? "recorded" : "pending",
        },
        {
          key: "respond",
          label: "Respond",
          description: response.historicalContext?.responseOutcomes?.length
            ? "An explicit executor outcome is recorded."
            : "No explicit response outcome is recorded yet.",
          state: response.historicalContext?.responseOutcomes?.length ? "recorded" : "pending",
        },
        {
          key: "verify",
          label: "Verify",
          description: verificationChanges.length
            ? "SentinelX has post-response evidence or a recorded verification state to review."
            : "Verification is waiting for a recorded response and post-response evidence.",
          state: verificationChanges.length ? "recorded" : "pending",
        },
        {
          key: "learn",
          label: "Learn",
          description: response.securityPatterns?.length
            ? "Historical patterns are available as context for future investigations."
            : "Pattern learning will use future recorded security history.",
          state: response.securityPatterns?.length ? "recorded" : "pending",
        },
      ]
    : [];

  return (
    <main className="min-h-screen bg-[#071018] text-slate-100">
      <header className="border-b border-white/10 bg-[#071018]/95">
        <div className="mx-auto flex max-w-[1100px] flex-col gap-3 px-4 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-6">
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
            className="mt-3 w-full resize-none rounded-2xl border border-white/10 bg-black/20 p-4 text-sm text-white outline-none placeholder:text-slate-700 focus:border-cyan-300/30 focus-visible:ring-2 focus-visible:ring-cyan-300/20"
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
            {lifecycleSteps.length > 0 && (
              <section className="rounded-3xl border border-white/10 bg-white/[0.025] p-5 sm:p-6">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">Defense lifecycle</p>
                    <h2 className="mt-1 text-lg font-semibold text-white">From finding to verified learning</h2>
                  </div>
                  <p className="text-[10px] text-slate-600">SentinelX never treats an unverified step as completed.</p>
                </div>
                <div className="mt-5 grid gap-2 md:grid-cols-6">
                  {lifecycleSteps.map((step, index) => (
                    <div key={step.key} className="relative rounded-2xl border border-white/10 bg-black/10 p-3">
                      <div className="flex items-center gap-2">
                        <span className={
                          step.state === "recorded"
                            ? "flex h-6 w-6 items-center justify-center rounded-full bg-emerald-400/10 text-[10px] font-semibold text-emerald-200"
                            : step.state === "current"
                              ? "flex h-6 w-6 items-center justify-center rounded-full bg-cyan-400/10 text-[10px] font-semibold text-cyan-200"
                              : "flex h-6 w-6 items-center justify-center rounded-full bg-amber-400/10 text-[10px] font-semibold text-amber-200"
                        }>
                          {index + 1}
                        </span>
                        <span className="text-[10px] font-semibold text-white">{step.label}</span>
                      </div>
                      <p className="mt-2 text-[9px] leading-4 text-slate-600">{step.description}</p>
                      <span className={
                        step.state === "recorded"
                          ? "mt-3 inline-flex rounded-full bg-emerald-400/10 px-2 py-1 text-[8px] uppercase tracking-wider text-emerald-200"
                          : step.state === "current"
                            ? "mt-3 inline-flex rounded-full bg-cyan-400/10 px-2 py-1 text-[8px] uppercase tracking-wider text-cyan-200"
                            : "mt-3 inline-flex rounded-full bg-amber-400/10 px-2 py-1 text-[8px] uppercase tracking-wider text-amber-200"
                      }>
                        {step.state === "recorded" ? "recorded" : step.state === "current" ? "current" : "pending"}
                      </span>
                    </div>
                  ))}
                </div>
              </section>
            )}

            <section className="rounded-3xl border border-cyan-400/10 bg-cyan-400/[0.025] p-5 sm:p-6">
              <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">Analyst conclusion</p>
              <p className="mt-3 text-sm leading-7 text-slate-300">{response.answer}</p>
              <div className="mt-5 grid gap-3 sm:grid-cols-2">
                <Stat label="Findings reviewed" value={response.findingsReviewed} />
                <Stat label="Evidence reviewed" value={response.evidenceReviewed} />
              </div>
            </section>

            {response.topFinding && (
              <section className="rounded-3xl border border-cyan-400/10 bg-cyan-400/[0.025] p-5 sm:p-6">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0">
                    <p className="text-xs font-semibold uppercase tracking-wider text-cyan-200">Finding in focus</p>
                    <h2 className="mt-1 truncate text-lg font-semibold text-white">{response.topFinding.title}</h2>
                    <div className="mt-2 flex flex-wrap items-center gap-2 text-[9px] uppercase tracking-wider text-slate-500">
                      <span className="rounded-full bg-white/5 px-2 py-1">ID {response.topFinding.id}</span>
                      <span className="rounded-full bg-white/5 px-2 py-1">{response.topFinding.severity}</span>
                      <span className="rounded-full bg-white/5 px-2 py-1">Investigation context loaded</span>
                    </div>
                  </div>
                  <div className="flex shrink-0 gap-2">
                    <Link href={"/actions?findingId=" + encodeURIComponent(response.topFinding.id)} className="inline-flex items-center gap-1 rounded-xl border border-white/10 px-3 py-2 text-[10px] font-semibold text-slate-300 hover:bg-white/5">Review actions</Link>
                    <Link href="/brain" className="inline-flex items-center gap-1 rounded-xl border border-white/10 px-3 py-2 text-[10px] font-semibold text-slate-300 hover:bg-white/5">Open Brain</Link>
                  </div>
                </div>
                <p className="mt-4 text-[11px] leading-5 text-slate-500">This investigation is scoped to the selected finding. SentinelX keeps observed evidence, confirmed relationships, historical context, and unknowns separate so the operator can see exactly what is established.</p>
              </section>
            )}

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
                <button
                  type="button"
                  onClick={investigateFinding}
                  disabled={investigating}
                  className="mt-4 inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-300 px-4 py-2.5 text-xs font-semibold text-slate-950 transition hover:bg-cyan-200 disabled:opacity-50"
                >
                  {investigating ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldAlert className="h-4 w-4" />}
                  {investigating ? "Investigating…" : "Investigate this finding"}
                </button>
              </section>
            )}

            {response.historicalContext?.responseLearning?.length ? (
              <section className="rounded-3xl border border-violet-400/10 bg-violet-400/[0.025] p-5 sm:p-6">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-violet-200">Learned response context</p>
                  <h2 className="mt-1 text-lg font-semibold text-white">Previously recorded response outcomes</h2>
                  <p className="mt-2 text-[11px] leading-5 text-slate-500">
                    These are historical execution records only. They provide context for a new decision; they do not establish that the same response will work now.
                  </p>
                </div>
                <div className="mt-4 grid gap-2 sm:grid-cols-2">
                  {response.historicalContext.responseLearning.slice(0, 6).map((item, index) => (
                    <div key={`${item.occurred_at}-${index}`} className="rounded-2xl border border-white/10 bg-black/10 p-4">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-xs font-medium text-white">
                          {item.action_type ? item.action_type.replaceAll("_", " ") : "Recorded response"}
                        </p>
                        <div className="flex items-center gap-1.5">
                          <span className="rounded-full bg-violet-400/10 px-2 py-1 text-[8px] uppercase tracking-wider text-violet-200">
                            {item.state}
                          </span>
                          <span className="rounded-full bg-white/5 px-2 py-1 text-[8px] uppercase tracking-wider text-slate-500">
                            {item.matchContext}
                          </span>
                        </div>
                      </div>
                      <p className="mt-2 text-[10px] leading-5 text-slate-500">{item.summary}</p>
                      <p className="mt-2 text-[9px] text-slate-600">
                        {item.evidence_count} evidence record{item.evidence_count === 1 ? "" : "s"} recorded with this outcome · {new Date(item.occurred_at).toLocaleString()}
                      </p>
                    </div>
                  ))}
                </div>
              </section>
            ) : null}

            {response.multiSignalCorrelation && response.topFinding && (
              <section className="rounded-3xl border border-cyan-400/10 bg-cyan-400/[0.02] p-5 sm:p-6">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-cyan-200">Multi-signal correlation</p>
                    <h2 className="mt-1 text-lg font-semibold text-white">One investigation context, multiple confirmed signals</h2>
                    <p className="mt-2 max-w-2xl text-[11px] leading-5 text-slate-500">
                      SentinelX correlates existing evidence around the finding. This layer does not create a second detector or change finding severity.
                    </p>
                  </div>
                  <span className="rounded-full bg-cyan-400/10 px-2 py-1 text-[9px] uppercase tracking-wider text-cyan-200">
                    {response.multiSignalCorrelation.signalCount} correlated signal{response.multiSignalCorrelation.signalCount === 1 ? "": "s"}
                  </span>
                </div>

                <div className="mt-5 grid gap-3 sm:grid-cols-4">
                  <Stat label="Events" value={response.multiSignalCorrelation.eventSignals.length} />
                  <Stat label="Other evidence" value={response.multiSignalCorrelation.evidenceSignals.length} />
                  <Stat label="Explicit identities" value={response.multiSignalCorrelation.identitySignals.length} />
                  <Stat label="Confirmed graph links" value={response.multiSignalCorrelation.graphContext.length} />
                </div>

                <div className="mt-4 grid gap-3 md:grid-cols-2">
                  <div className="rounded-2xl border border-white/10 bg-black/10 p-4">
                    <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">Timing window</p>
                    <p className="mt-2 text-sm font-medium text-white">
                      {response.multiSignalCorrelation.timing.spanMinutes === null ? "No correlated time span" : response.multiSignalCorrelation.timing.spanMinutes + " minute span"}
                    </p>
                    <p className="mt-1 text-[10px] text-slate-600">
                      Correlation window: ±{response.multiSignalCorrelation.timeWindowMinutes} minutes around finding detection.
                    </p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-black/10 p-4">
                    <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">Identity boundary</p>
                    <p className="mt-2 text-sm font-medium text-white">
                      {response.multiSignalCorrelation.identitySignals.length ? "Explicit identity recorded" : "No explicit identity recorded"}
                    </p>
                    <p className="mt-1 text-[10px] leading-5 text-slate-600">
                      Identity fields are displayed only when present in stored evidence; SentinelX does not infer attribution.
                    </p>
                  </div>
                </div>

                <div className="mt-4 rounded-2xl border border-white/10 bg-black/10 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">Correlation confidence</p>
                    <span className="rounded-full bg-white/5 px-2 py-1 text-[9px] uppercase tracking-wider text-cyan-200">{response.multiSignalCorrelation.correlationConfidence}</span>
                  </div>
                  <div className="mt-3 grid gap-2 sm:grid-cols-3">
                    {response.multiSignalCorrelation.confidenceReasons.map((reason) => (
                      <p key={reason} className="rounded-xl border border-white/10 p-3 text-[10px] leading-5 text-slate-500">{reason}</p>
                    ))}
                  </div>
                </div>

                {response.multiSignalCorrelation.timeline.length > 0 && (
                  <div className="mt-4 rounded-2xl border border-white/10 bg-black/10 p-4">
                    <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">Correlated timeline</p>
                    <div className="mt-3 space-y-2">
                      {response.multiSignalCorrelation.timeline.slice(0, 10).map((item, index) => (
                        <div key={item.observedAt + item.title + index} className="flex gap-3 rounded-xl border border-white/5 p-3">
                          <div className="mt-1 h-2 w-2 shrink-0 rounded-full bg-cyan-300" />
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap justify-between gap-2">
                              <p className="text-[10px] font-medium text-white">{item.title}</p>
                              <time className="text-[9px] text-slate-600">{new Date(item.observedAt).toLocaleString()}</time>
                            </div>
                            <p className="mt-1 text-[9px] text-slate-600">{item.signalType} · {item.source}{item.identity ? " · " + item.identity : ""}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {response.multiSignalCorrelation.identitySignals.length > 0 && (
                  <div className="mt-4 rounded-2xl border border-white/10 bg-black/10 p-4">
                    <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">Recorded identities</p>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {response.multiSignalCorrelation.identitySignals.slice(0, 8).map((item) => (
                        <span key={item.id} className="rounded-full bg-white/5 px-2.5 py-1.5 text-[9px] text-slate-300">
                          {item.identity} · {item.source}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {response.multiSignalCorrelation.correlationReasons.length > 0 && (
                  <div className="mt-4 rounded-2xl border border-white/10 bg-black/10 p-4">
                    <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">Why these signals were correlated</p>
                    <ul className="mt-2 space-y-1.5 text-[11px] leading-5 text-slate-500">
                      {response.multiSignalCorrelation.correlationReasons.map((reason) => <li key={reason}>• {reason}</li>)}
                    </ul>
                  </div>
                )}
              </section>
            )}

            {response.investigation && response.topFinding && (
              <section className="rounded-3xl border border-orange-400/10 bg-orange-400/[0.025] p-5 sm:p-6">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-orange-200">Decision point</p>
                    <h2 className="mt-1 text-lg font-semibold text-white">Investigation is ready for an operator decision</h2>
                    <p className="mt-2 text-[11px] leading-5 text-slate-500">
                      Review the confirmed target, evidence, relationships, and known unknowns before creating or authorizing a response.
                    </p>
                  </div>
                  <Link
                    href={`/actions?findingId=${encodeURIComponent(response.topFinding.id)}`}
                    className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl bg-cyan-300 px-4 py-3 text-xs font-semibold text-slate-950 hover:bg-cyan-200"
                  >
                    <ShieldAlert className="h-4 w-4" /> Continue to Decision
                  </Link>
                </div>
              </section>
            )}

            {response.investigation && (
              <section className="rounded-3xl border border-emerald-400/10 bg-emerald-400/[0.025] p-5 sm:p-6">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-emerald-300">Investigation context</p>
                    <h2 className="mt-1 text-lg font-semibold text-white">Confirmed security relationships</h2>
                  </div>
                  <ShieldCheck className="h-5 w-5 text-emerald-300" />
                </div>

                <div className="mt-5 grid gap-3 sm:grid-cols-3">
                  <Stat label="Affected asset" value={response.investigation.affectedAsset ? 1 : 0} />
                  <Stat label="Related assets" value={response.investigation.blastRadius.length} />
                  <Stat label="Evidence matched" value={response.investigation.supportingEvidence.length} />
                </div>

                {response.investigation.affectedAsset && (
                  <div className="mt-4 rounded-2xl border border-white/10 bg-black/10 p-4">
                    <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">Affected asset</p>
                    <p className="mt-1 text-sm font-medium text-white">{response.investigation.affectedAsset.name}</p>
                    <p className="mt-1 text-[10px] text-slate-500">{response.investigation.affectedAsset.asset_type} · {response.investigation.affectedAsset.status}</p>
                  </div>
                )}

                {response.investigation.blastRadius.length ? (
                  <div className="mt-4 space-y-2">
                    {response.investigation.blastRadius.slice(0, 8).map((item) => (
                      <div key={item.asset.id} className="flex flex-col gap-2 rounded-2xl border border-white/10 p-3 sm:flex-row sm:items-center sm:justify-between">
                        <div>
                          <p className="text-xs font-medium text-white">{item.asset.name}</p>
                          <p className="mt-1 text-[10px] text-slate-600">{item.asset.asset_type} · {item.hops} hop{item.hops === 1 ? "" : "s"} · {(item.confidence * 100).toFixed(0)}% relationship confidence</p>
                        </div>
                        <span className="text-[10px] text-emerald-300">{item.chain.join(" → ")}</span>
                      </div>
                    ))}
                  </div>
                ) : null}

                {response.investigation.unknowns.length ? (
                  <div className="mt-4 rounded-2xl border border-amber-400/10 bg-amber-400/[0.025] p-4">
                    <p className="text-[9px] font-semibold uppercase tracking-wider text-amber-200">Known unknowns</p>
                    <ul className="mt-2 space-y-1.5 text-[11px] leading-5 text-slate-500">
                      {response.investigation.unknowns.map((unknown) => <li key={unknown}>• {unknown}</li>)}
                    </ul>
                  </div>
                ) : null}
              </section>
            )}

            {response.topFinding && verificationChanges.length > 0 ? (
              <section className="rounded-3xl border border-cyan-400/10 bg-cyan-400/[0.025] p-5 sm:p-6">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-cyan-200">Post-response verification</p>
                    <p className="mt-1 text-[10px] text-slate-600">What SentinelX can currently verify after the recorded response.</p>
                  </div>
                  <ShieldCheck className="h-5 w-5 text-cyan-300" />
                </div>
                <div className="mt-4 space-y-3">
                  {verificationChanges.map((change) => (
                    <div key={change.id} className="rounded-2xl border border-white/10 p-4">
                      <div className="mb-3 flex flex-wrap items-center gap-2 text-[8px] uppercase tracking-wider text-slate-600">
                        <span className="rounded-full border border-white/10 bg-black/10 px-2 py-1">Evidence after response</span>
                        <span className="rounded-full border border-white/10 bg-black/10 px-2 py-1">Current finding context</span>
                      </div>
                      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                        <p className="text-sm font-medium text-white">{change.title.replace("Response verification: ", "")}</p>
                        <span className={
                          change.verificationState === "improved"
                            ? "rounded-full bg-emerald-400/10 px-2 py-1 text-[9px] uppercase tracking-wider text-emerald-200"
                            : change.verificationState === "observed"
                              ? "rounded-full bg-cyan-400/10 px-2 py-1 text-[9px] uppercase tracking-wider text-cyan-200"
                              : change.verificationState === "uncertain"
                                ? "rounded-full bg-rose-400/10 px-2 py-1 text-[9px] uppercase tracking-wider text-rose-200"
                                : "rounded-full bg-amber-400/10 px-2 py-1 text-[9px] uppercase tracking-wider text-amber-200"
                        }>
                          {change.verificationState?.replaceAll("_", " ") ?? "pending"}
                        </span>
                      </div>
                      <p className="mt-3 text-xs leading-5 text-slate-400">{change.detail}</p>
                      <p className="mt-2 text-[9px] text-slate-600">Observed {new Date(change.observedAt).toLocaleString()}</p>
                    </div>
                  ))}
                </div>
              </section>
            ) : verificationLoading ? (
              <section className="rounded-2xl border border-white/10 bg-white/[0.025] p-4 text-[10px] text-slate-600">
                Checking post-response evidence…
              </section>
            ) : null}

            {response.historicalContext && (response.historicalContext.priorFindingStates.length > 0 || response.historicalContext.priorInvestigations.length > 0) && (
              <section className="rounded-3xl border border-orange-400/10 bg-orange-400/[0.025] p-5 sm:p-6">
                <div className="flex flex-col gap-1">
                  <p className="text-xs font-semibold uppercase tracking-wider text-orange-200">Recurrence context</p>
                  <h2 className="mt-1 text-lg font-semibold text-white">What SentinelX has seen before</h2>
                  <p className="mt-2 text-[11px] leading-5 text-slate-500">
                    Historical recurrence is shown alongside recorded response outcomes where available. It is context for the next decision, not proof that the same condition or response applies now.
                  </p>
                </div>

                <div className="mt-4 grid gap-3 sm:grid-cols-3">
                  <div className="rounded-2xl border border-white/10 bg-black/10 p-4">
                    <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">State changes</p>
                    <p className="mt-2 text-2xl font-semibold text-white">{response.historicalContext.priorFindingStates.length}</p>
                    <p className="mt-1 text-[10px] text-slate-600">Recorded historical finding-state transitions.</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-black/10 p-4">
                    <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">Investigations</p>
                    <p className="mt-2 text-2xl font-semibold text-white">{response.historicalContext.priorInvestigations.length}</p>
                    <p className="mt-1 text-[10px] text-slate-600">Previously recorded investigations.</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-black/10 p-4">
                    <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">Response outcomes</p>
                    <p className="mt-2 text-2xl font-semibold text-white">{response.historicalContext?.responseOutcomes?.length ?? 0}</p>
                    <p className="mt-1 text-[10px] text-slate-600">Recorded executor outcomes connected to this context.</p>
                  </div>
                </div>

                {response.historicalContext.priorFindingStates.length > 0 && (
                  <div className="mt-4 space-y-2">
                    {response.historicalContext.priorFindingStates.slice(0, 5).map((item, index) => (
                      <div key={item.occurred_at + item.title + index} className="rounded-2xl border border-white/10 bg-black/10 p-4">
                        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                          <div>
                            <p className="text-xs font-medium text-white">{item.title}</p>
                            <p className="mt-1 text-[9px] uppercase tracking-wider text-slate-600">Historical state transition</p>
                          </div>
                          <time className="text-[9px] text-slate-600">{new Date(item.occurred_at).toLocaleString()}</time>
                        </div>
                        <p className="mt-2 text-[10px] leading-5 text-slate-500">{item.summary}</p>
                        {(item.previous_state || item.current_state) && (
                          <div className="mt-3 flex flex-wrap items-center gap-2 text-[9px] uppercase tracking-wider">
                            {item.previous_state && <span className="rounded-full bg-white/5 px-2 py-1 text-slate-500">{String(item.previous_state)}</span>}
                            {item.previous_state && item.current_state && <span className="text-orange-300">→</span>}
                            {item.current_state && <span className="rounded-full bg-orange-400/10 px-2 py-1 text-orange-200">{String(item.current_state)}</span>}
                          </div>
                        )}

                        {response.historicalContext?.responseOutcomes?.length ?? 0 > 0 && (
                          <div className="mt-4 rounded-xl border border-white/10 p-3">
                            <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">Recorded response context</p>
                            <div className="mt-2 space-y-2">
                              {response.historicalContext?.responseOutcomes?.slice(0, 2).map((outcome, outcomeIndex) => (
                                <div key={(outcome.action_id ?? "outcome") + outcome.occurred_at + outcomeIndex} className="rounded-xl border border-white/5 bg-white/[0.02] p-3">
                                  <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
                                    <p className="text-[10px] font-medium text-slate-300">{outcome.title}</p>
                                    <span className="text-[8px] uppercase tracking-wider text-slate-600">{outcome.state}</span>
                                  </div>
                                  <p className="mt-1 text-[9px] leading-4 text-slate-600">
                                    {outcome.action_type?.replaceAll("_", " ") ?? "response"} · {outcome.executor_type ?? "recorded executor"} · {outcome.evidence.length} evidence record{outcome.evidence.length === 1 ? "" : "s"}
                                  </p>
                                  <p className="mt-1 text-[9px] leading-4 text-slate-600">{outcome.summary}</p>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                <p className="mt-4 rounded-xl border border-amber-400/10 bg-amber-400/[0.025] p-3 text-[9px] leading-4 text-slate-600">
                  SentinelX does not infer that a historical response caused a current condition, nor that a previously used action will work again. Current decisions remain grounded in current evidence and explicit authorization.
                </p>
              </section>
            )}

            {response.historicalContext?.responseOutcomes?.length ? (
              <section className="rounded-3xl border border-emerald-400/10 bg-emerald-400/[0.025] p-5 sm:p-6">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-emerald-200">Response verification history</p>
                    <p className="mt-1 text-[10px] text-slate-600">Recorded outcomes for this finding. Historical outcomes do not prove the current state.</p>
                  </div>
                  <ShieldCheck className="h-5 w-5 text-emerald-300" />
                </div>
                <div className="mt-4 space-y-3">
                  {response.historicalContext.responseOutcomes.map((outcome, index) => (
                    <div key={outcome.action_id ?? outcome.occurred_at + index} className="rounded-2xl border border-white/10 p-4">
                      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                        <div>
                          <p className="text-sm font-medium text-white">{outcome.title}</p>
                          <p className="mt-1 text-[10px] text-slate-600">{outcome.action_type?.replaceAll("_", " ") ?? "response"} · {outcome.executor_type ?? "recorded executor"}</p>
                        </div>
                        <span className={outcome.state === "completed" ? "rounded-full bg-emerald-400/10 px-2 py-1 text-[9px] uppercase tracking-wider text-emerald-200" : "rounded-full bg-rose-400/10 px-2 py-1 text-[9px] uppercase tracking-wider text-rose-200"}>
                          {outcome.state}
                        </span>
                      </div>
                      <p className="mt-3 text-xs leading-5 text-slate-500">{outcome.summary}</p>
                      {outcome.execution_reference && (
                        <p className="mt-2 text-[9px] text-slate-600">Execution reference: {outcome.execution_reference}</p>
                      )}
                      {outcome.evidence.length ? (
                        <div className="mt-3 rounded-xl border border-white/10 bg-black/10 p-3">
                          <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">Recorded outcome evidence</p>
                          <p className="mt-1 text-[10px] leading-4 text-slate-500">{outcome.evidence[0]?.summary || outcome.evidence[0]?.reference || "Explicit executor evidence recorded."}</p>
                        </div>
                      ) : null}
                    </div>
                  ))}
                </div>
              </section>
            ) : null}

            {response.historicalContext && (response.historicalContext.priorFindingStates.length > 0 || response.historicalContext.priorInvestigations.length > 0) && (
              <section className="rounded-3xl border border-orange-400/10 bg-orange-400/[0.025] p-5 sm:p-6">
                <div className="flex flex-col gap-1">
                  <p className="text-xs font-semibold uppercase tracking-wider text-orange-200">Recurrence context</p>
                  <h2 className="mt-1 text-lg font-semibold text-white">What SentinelX has seen before</h2>
                  <p className="mt-2 text-[11px] leading-5 text-slate-500">
                    This is a record of prior state changes and investigations connected to the selected finding. Repetition is historical context, not proof that the same condition exists now.
                  </p>
                </div>

                <div className="mt-4 grid gap-3 sm:grid-cols-2">
                  <div className="rounded-2xl border border-white/10 bg-black/10 p-4">
                    <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">Recorded state changes</p>
                    <p className="mt-2 text-2xl font-semibold text-white">{response.historicalContext.priorFindingStates.length}</p>
                    <p className="mt-1 text-[10px] text-slate-600">Historical finding-state records in the current context.</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-black/10 p-4">
                    <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">Prior investigations</p>
                    <p className="mt-2 text-2xl font-semibold text-white">{response.historicalContext.priorInvestigations.length}</p>
                    <p className="mt-1 text-[10px] text-slate-600">Previously recorded investigations for this finding.</p>
                  </div>
                </div>

                {response.historicalContext.priorFindingStates.length > 0 && (
                  <div className="mt-4 space-y-2">
                    {response.historicalContext.priorFindingStates.slice(0, 5).map((item, index) => (
                      <div key={item.occurred_at + item.title + index} className="rounded-2xl border border-white/10 p-4">
                        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                          <p className="text-xs font-medium text-white">{item.title}</p>
                          <time className="text-[9px] text-slate-600">{new Date(item.occurred_at).toLocaleString()}</time>
                        </div>
                        <p className="mt-2 text-[10px] leading-5 text-slate-500">{item.summary}</p>
                        {(item.previous_state || item.current_state) && (
                          <div className="mt-3 flex flex-wrap items-center gap-2 text-[9px] uppercase tracking-wider">
                            {item.previous_state && <span className="rounded-full bg-white/5 px-2 py-1 text-slate-500">{String(item.previous_state)}</span>}
                            {item.previous_state && item.current_state && <span className="text-orange-300">→</span>}
                            {item.current_state && <span className="rounded-full bg-orange-400/10 px-2 py-1 text-orange-200">{String(item.current_state)}</span>}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
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

            <Link href={response.topFinding ? `/actions?findingId=${encodeURIComponent(response.topFinding.id)}` : "/actions"} className="inline-flex items-center gap-2 rounded-xl border border-white/10 px-4 py-3 text-xs font-semibold text-slate-300 hover:bg-white/5">
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