"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ArrowLeft, BrainCircuit, Clock3, FileSearch, GitBranch, History, Loader2, ShieldCheck, UserCheck } from "lucide-react";

type TimelineItem = {
  id: string;
  memoryId: string;
  type: "finding_state" | "investigation" | "operator_decision" | "response_outcome" | "evidence_change";
  title: string;
  summary: string;
  state: string;
  occurredAt: string;
  subject: { kind: string; id: string | null; name: string | null };
  context: {
    findingId: string | null;
    assetId: string | null;
    evidenceId: string | null;
    actionId: string | null;
    changeType: string | null;
    previousState: string | null;
    currentState: string | null;
  };
  historical: boolean;
};

type Summary = {
  total: number;
  findings: number;
  investigations: number;
  decisions: number;
  outcomes: number;
  evidenceChanges: number;
};

const typeMeta: Record<TimelineItem["type"], { label: string; icon: typeof History }> = {
  finding_state: { label: "Finding state", icon: ShieldCheck },
  investigation: { label: "Investigation", icon: BrainCircuit },
  operator_decision: { label: "Operator decision", icon: UserCheck },
  response_outcome: { label: "Response outcome", icon: ShieldCheck },
  evidence_change: { label: "Evidence change", icon: FileSearch },
};

function formatDate(value: string) {
  return new Date(value).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

export default function SecurityHistoryPage() {
  const [timeline, setTimeline] = useState<TimelineItem[]>([]);
  const [summary, setSummary] = useState<Summary>({ total: 0, findings: 0, investigations: 0, decisions: 0, outcomes: 0, evidenceChanges: 0 });
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");
  const [filter, setFilter] = useState<"all" | TimelineItem["type"]>("all");

  async function loadHistory() {
    setLoading(true);
    setMessage("");
    try {
      const response = await fetch("/api/security/memory?limit=100", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) {
        setMessage(data.error ?? "Security History could not be loaded.");
        return;
      }
      setTimeline(data.timeline ?? []);
      setSummary(data.summary ?? summary);
    } catch {
      setMessage("Security History could not be loaded.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadHistory();
  }, []);

  const visible = useMemo(
    () => filter === "all" ? timeline : timeline.filter((item) => item.type === filter),
    [filter, timeline]
  );

  return (
    <main className="min-h-screen bg-[#071018] text-slate-100">
      <header className="border-b border-white/10 bg-[#071018]/95">
        <div className="mx-auto flex max-w-[1200px] items-center justify-between px-4 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
              <History className="h-5 w-5" />
            </div>
            <div>
              <p className="font-semibold text-white">Security History</p>
              <p className="text-[11px] text-slate-500">Longitudinal security memory</p>
            </div>
          </div>
          <Link href="/brain" className="inline-flex items-center gap-2 rounded-xl border border-white/10 px-3 py-2 text-xs text-slate-400 hover:text-white">
            <ArrowLeft className="h-3.5 w-3.5" /> Security Brain
          </Link>
        </div>
      </header>

      <div className="mx-auto max-w-[1200px] px-4 py-8 sm:px-6">
        <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">Historical context</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">What happened before?</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
          SentinelX connects findings, investigations, operator decisions, response outcomes, and evidence transitions so an investigation can start with context instead of starting from zero.
        </p>

        <div className="mt-6 grid gap-3 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6">
          {[
            ["Events", summary.total],
            ["Findings", summary.findings],
            ["Investigations", summary.investigations],
            ["Decisions", summary.decisions],
            ["Response outcomes", summary.outcomes],
            ["Evidence changes", summary.evidenceChanges],
          ].map(([label, value]) => (
            <div key={label} className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
              <p className="text-[10px] uppercase tracking-wider text-slate-500">{label}</p>
              <p className="mt-2 text-2xl font-semibold text-white">{value}</p>
            </div>
          ))}
        </div>

        <div className="mt-6 flex flex-wrap gap-2">
          <button onClick={() => setFilter("all")} className={`rounded-full px-3 py-1.5 text-[10px] font-semibold ${filter === "all" ? "bg-cyan-400/10 text-cyan-200" : "bg-white/5 text-slate-500"}`}>All</button>
          {(Object.keys(typeMeta) as TimelineItem["type"][]).map((type) => {
            const Icon = typeMeta[type].icon;
            return (
              <button key={type} onClick={() => setFilter(type)} className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-[10px] font-semibold ${filter === type ? "bg-cyan-400/10 text-cyan-200" : "bg-white/5 text-slate-500"}`}>
                <Icon className="h-3 w-3" /> {typeMeta[type].label}
              </button>
            );
          })}
        </div>

        {message && <div className="mt-5 rounded-xl border border-red-400/20 bg-red-400/5 p-3 text-xs text-red-200">{message}</div>}

        {loading ? (
          <div className="mt-8 flex items-center gap-2 text-xs text-slate-500"><Loader2 className="h-4 w-4 animate-spin" /> Loading security memory...</div>
        ) : visible.length === 0 ? (
          <div className="mt-8 rounded-3xl border border-dashed border-white/10 p-8 text-center">
            <Clock3 className="mx-auto h-6 w-6 text-slate-600" />
            <p className="mt-3 text-sm font-medium text-slate-300">No historical security memory yet</p>
            <p className="mt-2 text-xs leading-5 text-slate-600">As SentinelX records evidence changes, investigations, and operator decisions, they will appear here.</p>
          </div>
        ) : (
          <section className="mt-8">
            <div className="relative ml-2 border-l border-white/10 pl-6">
              {visible.map((item) => {
                const Icon = typeMeta[item.type].icon;
                return (
                  <article key={item.id} className="relative pb-6 last:pb-0">
                    <div className="absolute -left-[35px] top-1 flex h-7 w-7 items-center justify-center rounded-full border border-cyan-400/15 bg-[#071018] text-cyan-300">
                      <Icon className="h-3.5 w-3.5" />
                    </div>
                    <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
                      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                        <div>
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="rounded-full bg-white/5 px-2 py-1 text-[9px] font-semibold uppercase tracking-wider text-slate-500">{typeMeta[item.type].label}</span>
                            {item.historical && <span className="rounded-full bg-amber-400/10 px-2 py-1 text-[9px] font-semibold uppercase tracking-wider text-amber-200">Historical</span>}
                            {item.context.changeType && <span className="rounded-full bg-cyan-400/10 px-2 py-1 text-[9px] font-semibold uppercase tracking-wider text-cyan-200">{item.context.changeType}</span>}
                          </div>
                          <h2 className="mt-2 text-sm font-semibold text-white">{item.title}</h2>
                        </div>
                        <time className="shrink-0 text-[10px] text-slate-600">{formatDate(item.occurredAt)}</time>
                      </div>

                      <p className="mt-2 text-xs leading-5 text-slate-400">{item.summary}</p>

                      {item.subject.name && (
                        <div className="mt-3 rounded-xl border border-white/5 bg-black/10 px-3 py-2 text-[10px] text-slate-500">
                          <span className="uppercase tracking-wider text-slate-600">{item.subject.kind}:</span> <span className="text-slate-300">{item.subject.name}</span>
                        </div>
                      )}

                      {(item.context.previousState || item.context.currentState) && (
                        <div className="mt-3 flex flex-wrap items-center gap-2 text-[10px]">
                          <span className="text-slate-600">State transition</span>
                          {item.context.previousState && <span className="rounded-lg bg-white/5 px-2 py-1 text-slate-400">{item.context.previousState}</span>}
                          {item.context.previousState && item.context.currentState && <span className="text-cyan-300">→</span>}
                          {item.context.currentState && <span className="rounded-lg bg-cyan-400/10 px-2 py-1 text-cyan-200">{item.context.currentState}</span>}
                        </div>
                      )}

                      <p className="mt-3 text-[10px] leading-5 text-slate-600">
                        Historical context is not current-state proof. SentinelX must rely on current evidence and telemetry for present-state claims.
                      </p>
                    </div>
                  </article>
                );
              })}
            </div>
          </section>
        )}
      </div>
    </main>
  );
}
