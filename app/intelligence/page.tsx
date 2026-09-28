"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Activity, ArrowRight, BrainCircuit, CheckCircle2, Clock3, Network, ShieldAlert, Sparkles } from "lucide-react";

type AttentionItem = {
  id: string;
  kind: string;
  priority: string;
  title: string;
  detail: string;
  observedAt: string;
  href: string;
};

type ChangeItem = {
  id: string;
  kind: string;
  title: string;
  detail: string;
  observedAt: string;
  state: string;
  href: string;
  verificationState?: string;
};

type Pattern = {
  id: string;
  pattern: string;
  title: string;
  detail: string;
  confidence: string;
  memoryIds: string[];
  lastObserved: string;
  boundary: string;
};

type Overview = {
  connected: boolean;
  metrics: {
    protectedAssets: number;
    openFindings: number;
    securityEvents: number;
    attackPaths: number;
    aiSystems: number;
    aiAgents: number;
  };
};

export default function IntelligencePage() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [attention, setAttention] = useState<AttentionItem[]>([]);
  const [changes, setChanges] = useState<ChangeItem[]>([]);
  const [patterns, setPatterns] = useState<Pattern[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshedAt, setRefreshedAt] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    try {
      const [overviewResponse, attentionResponse, changesResponse, patternsResponse] = await Promise.all([
        fetch("/api/security/overview", { cache: "no-store" }),
        fetch("/api/security/attention", { cache: "no-store" }),
        fetch("/api/security/changes", { cache: "no-store" }),
        fetch("/api/security/patterns", { cache: "no-store" }),
      ]);

      if (overviewResponse.ok) setOverview(await overviewResponse.json());
      if (attentionResponse.ok) {
        const data = await attentionResponse.json();
        setAttention(Array.isArray(data.items) ? data.items : []);
      }
      if (changesResponse.ok) {
        const data = await changesResponse.json();
        setChanges(Array.isArray(data.changes) ? data.changes : []);
      }
      if (patternsResponse.ok) {
        const data = await patternsResponse.json();
        setPatterns(Array.isArray(data.patterns) ? data.patterns : []);
      }
      setRefreshedAt(new Date().toISOString());
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
    const interval = window.setInterval(() => void load(), 30000);
    return () => window.clearInterval(interval);
  }, []);

  const context = useMemo(() => {
    const verification = changes.filter((item) => item.kind === "verification");
    const activePattern = patterns[0] ?? null;
    const highAttention = attention.filter((item) => item.priority === "high").length;
    const changed = changes.filter((item) => item.state === "changed" || item.state === "new").length;

    if (highAttention > 0) {
      return {
        label: "Investigation needed",
        tone: "amber",
        headline: attention[0]?.title ?? "Recorded security attention requires review.",
        detail: attention[0]?.detail ?? "SentinelX has recorded signals that should be investigated.",
        href: attention[0]?.href ?? "/analyst",
        action: "Investigate signal",
      };
    }

    if (verification.length > 0) {
      return {
        label: "Verify response",
        tone: "emerald",
        headline: verification[0].title,
        detail: verification[0].detail,
        href: verification[0].href,
        action: "Review verification",
      };
    }

    if (activePattern) {
      return {
        label: "Historical context",
        tone: "violet",
        headline: activePattern.title,
        detail: activePattern.detail,
        href: "/brain",
        action: "Open Security Brain",
      };
    }

    if (changed > 0) {
      return {
        label: "State changed",
        tone: "cyan",
        headline: changes[0]?.title ?? "Security state has changed.",
        detail: changes[0]?.detail ?? "Review the latest recorded security change.",
        href: changes[0]?.href ?? "/brain",
        action: "Review change",
      };
    }

    return {
      label: overview?.connected ? "Monitoring" : "Awaiting telemetry",
      tone: "slate",
      headline: overview?.connected ? "No new high-impact signal is currently recorded." : "Connect a protected surface to begin intelligence collection.",
      detail: overview?.connected
        ? "SentinelX is retaining the latest verified security state and will reassess it during background refresh."
        : "The intelligence layer does not infer risk when the underlying telemetry is missing.",
      href: overview?.connected ? "/assets" : "/integrations",
      action: overview?.connected ? "Review assets" : "Connect telemetry",
    };
  }, [attention, changes, patterns, overview]);

  const toneClasses: Record<string, string> = {
    amber: "border-amber-400/15 bg-amber-400/[0.035] text-amber-200",
    emerald: "border-emerald-400/15 bg-emerald-400/[0.035] text-emerald-200",
    violet: "border-violet-400/15 bg-violet-400/[0.035] text-violet-200",
    cyan: "border-cyan-400/15 bg-cyan-400/[0.035] text-cyan-200",
    slate: "border-white/10 bg-white/[0.025] text-slate-300",
  };

  return (
    <main className="min-h-screen bg-[#071018] text-slate-100">
      <header className="border-b border-white/10 bg-[#071018]/95">
        <div className="mx-auto flex max-w-[1200px] items-center justify-between gap-3 px-4 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
              <Sparkles className="h-5 w-5" />
            </div>
            <div>
              <p className="font-semibold text-white">Security Intelligence</p>
              <p className="text-[11px] text-slate-500">Cross-signal security context</p>
            </div>
          </div>
          <Link href="/" className="text-xs text-slate-400 hover:text-white">Command Center</Link>
        </div>
      </header>

      <div className="mx-auto max-w-[1200px] px-4 py-8 sm:px-6">
        <div className="max-w-3xl">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">Continuous intelligence</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white sm:text-4xl">What SentinelX understands right now.</h1>
          <p className="mt-3 text-sm leading-6 text-slate-500">
            This layer connects existing findings, attention signals, security changes, response verification and historical patterns into one operator view. It does not create a separate source of truth.
          </p>
        </div>

        <section className={`mt-7 rounded-3xl border p-5 sm:p-6 ${toneClasses[context.tone]}`}>
          <div className="flex flex-col gap-5 md:flex-row md:items-center md:justify-between">
            <div className="max-w-3xl">
              <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider">
                <Activity className="h-3.5 w-3.5" />
                {context.label}
              </div>
              <h2 className="mt-2 text-xl font-semibold text-white">{loading ? "Reconstructing security context…" : context.headline}</h2>
              <p className="mt-2 text-sm leading-6 text-slate-400">{context.detail}</p>
            </div>
            <Link href={context.href} className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl bg-white/10 px-4 py-3 text-xs font-semibold text-white hover:bg-white/15">
              {context.action}
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </section>

        <section className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { label: "Protected assets", value: overview?.metrics.protectedAssets ?? 0, Icon: BoxesIcon },
            { label: "Open findings", value: overview?.metrics.openFindings ?? 0, Icon: ShieldAlert },
            { label: "Attack paths", value: overview?.metrics.attackPaths ?? 0, Icon: Network },
            { label: "Security events", value: overview?.metrics.securityEvents ?? 0, Icon: Activity },
          ].map(({ label, value, Icon }) => (
            <div key={label} className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
              <div className="flex items-center justify-between">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-600">{label}</p>
                <Icon className="h-4 w-4 text-slate-500" />
              </div>
              <p className="mt-3 text-2xl font-semibold text-white">{loading ? "—" : String(value)}</p>
              <p className="mt-1 text-[10px] text-slate-600">Verified source data only</p>
            </div>
          ))}
        </section>

        <section className="mt-5 grid gap-5 lg:grid-cols-2">
          <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-5 sm:p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-amber-200">Signal chain</p>
                <h2 className="mt-1 text-lg font-semibold text-white">Detect → investigate → decide</h2>
              </div>
              <BrainCircuit className="h-5 w-5 text-cyan-300" />
            </div>
            <div className="mt-5 space-y-3">
              {attention.slice(0, 3).map((item) => (
                <Link key={item.id} href={item.href} className="block rounded-2xl border border-white/10 bg-black/10 p-3 hover:bg-white/[0.04]">
                  <div className="flex items-center gap-2">
                    <span className={`h-2 w-2 rounded-full ${item.priority === "high" ? "bg-rose-300" : "bg-amber-300"}`} />
                    <p className="text-xs font-medium text-white">{item.title}</p>
                  </div>
                  <p className="mt-1 text-[10px] leading-4 text-slate-500">{item.detail}</p>
                </Link>
              ))}
              {!attention.length && <p className="rounded-2xl border border-dashed border-white/10 p-4 text-xs text-slate-600">No attention signal is currently recorded.</p>}
            </div>
          </div>

          <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-5 sm:p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-cyan-200">State transitions</p>
                <h2 className="mt-1 text-lg font-semibold text-white">What changed</h2>
              </div>
              <Clock3 className="h-5 w-5 text-cyan-300" />
            </div>
            <div className="mt-5 space-y-3">
              {changes.slice(0, 3).map((item) => (
                <Link key={item.id} href={item.href} className="block rounded-2xl border border-white/10 bg-black/10 p-3 hover:bg-white/[0.04]">
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-xs font-medium text-white">{item.title}</p>
                    <span className="text-[9px] uppercase tracking-wider text-slate-600">{item.state}</span>
                  </div>
                  <p className="mt-1 text-[10px] leading-4 text-slate-500">{item.detail}</p>
                </Link>
              ))}
              {!changes.length && <p className="rounded-2xl border border-dashed border-white/10 p-4 text-xs text-slate-600">No security-state transition is currently recorded.</p>}
            </div>
          </div>
        </section>

        <section className="mt-5 rounded-3xl border border-violet-400/10 bg-violet-400/[0.025] p-5 sm:p-6">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-violet-200">Memory → context</p>
              <h2 className="mt-1 text-lg font-semibold text-white">Patterns SentinelX can carry forward</h2>
            </div>
            <Link href="/brain" className="text-[10px] font-semibold uppercase tracking-wider text-violet-200 hover:text-white">Security Brain</Link>
          </div>
          <div className="mt-5 grid gap-3 md:grid-cols-2">
            {patterns.slice(0, 4).map((pattern) => (
              <Link key={pattern.id} href="/brain" className="rounded-2xl border border-white/10 bg-black/10 p-4 hover:bg-white/[0.04]">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-sm font-medium text-white">{pattern.title}</p>
                  <span className="rounded-full bg-violet-400/10 px-2 py-1 text-[9px] uppercase tracking-wider text-violet-200">{pattern.confidence}</span>
                </div>
                <p className="mt-2 text-[10px] leading-4 text-slate-500">{pattern.detail}</p>
                <p className="mt-3 text-[9px] text-slate-600">{pattern.memoryIds.length} linked memory records · last observed {new Date(pattern.lastObserved).toLocaleString()}</p>
              </Link>
            ))}
            {!patterns.length && <p className="rounded-2xl border border-dashed border-white/10 p-4 text-xs text-slate-600">No historical pattern has been established yet.</p>}
          </div>
          <p className="mt-4 rounded-2xl border border-amber-400/10 bg-amber-400/[0.025] p-3 text-[9px] leading-4 text-slate-600">
            Historical patterns describe recorded history. They do not prove current compromise, causation, or that a previous response will work again.
          </p>
        </section>

        <div className="mt-5 flex flex-wrap items-center gap-3 text-[10px] text-slate-600">
          <span className="inline-flex items-center gap-1.5"><CheckCircle2 className="h-3 w-3 text-emerald-300" /> Evidence-first</span>
          <span>•</span>
          <span>Refreshes every 30 seconds</span>
          {refreshedAt && <><span>•</span><span>Last refresh {new Date(refreshedAt).toLocaleTimeString()}</span></>}
        </div>
      </div>
    </main>
  );
}

function BoxesIcon({ className }: { className?: string }) {
  return <Network className={className} />;
}
