"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Bot,
  Boxes,
  BrainCircuit,
  CheckCircle2,
  ChevronRight,
  Cloud,
  Database,
  Globe2,
  KeyRound,
  Link2,
  LogOut,
  Network,
  Radar,
  RefreshCw,
  Settings,
  Shield,
  ShieldCheck,
  Sparkles,
  UserRound,
  ShieldAlert,
  Wifi,
} from "lucide-react";
import { createClient } from "@/lib/supabase/client";

type UserState = {
  email: string;
  displayName: string;
};

type Surface = {
  title: string;
  description: string;
  icon: typeof Globe2;
  status: "ready" | "coming";
};

type Metric = {
  label: string;
  value: string;
  detail: string;
  icon: typeof Boxes;
};

const surfaces: Surface[] = [
  {
    title: "Websites & domains",
    description: "Authorized public-facing applications, domains and APIs.",
    icon: Globe2,
    status: "ready",
  },
  {
    title: "Cloud & infrastructure",
    description: "Cloud accounts, workloads, networks and exposed services.",
    icon: Cloud,
    status: "ready",
  },
  {
    title: "Identity & access",
    description: "Users, credentials, sessions, roles and authentication signals.",
    icon: KeyRound,
    status: "ready",
  },
  {
    title: "Endpoints & devices",
    description: "Company computers, servers and managed devices.",
    icon: Network,
    status: "coming",
  },
  {
    title: "Email & collaboration",
    description: "Business mail, collaboration systems and account activity.",
    icon: Wifi,
    status: "coming",
  },
  {
    title: "Business software",
    description: "SaaS applications, internal software and critical workflows.",
    icon: Boxes,
    status: "coming",
  },
  {
    title: "Databases & data",
    description: "Data stores, sensitive records and access relationships.",
    icon: Database,
    status: "coming",
  },
  {
    title: "AI systems & agents",
    description: "AI models, agents, prompts, tools and delegated permissions.",
    icon: Bot,
    status: "ready",
  },
];

const navigation = [
  { label: "Command Center", href: "#command-center", icon: Radar },
  { label: "Assets", href: "/assets", icon: Boxes },
  { label: "Security Brain", href: "/brain", icon: BrainCircuit },
  { label: "AI Security Center", href: "/ai-security", icon: Bot },
  { label: "Security Analyst", href: "/analyst", icon: BrainCircuit },
  { label: "Actions", href: "/actions", icon: ShieldAlert },
  { label: "Integrations", href: "/integrations", icon: Link2 },
  { label: "Activity", href: "#activity", icon: Activity },
];

type SecurityOverview = {
  connected: boolean;
  metrics: {
    protectedAssets: number;
    openFindings: number;
    securityEvents: number;
    attackPaths: number;
    aiSystems: number;
    aiAgents: number;
  };
  latestEvents: Array<{
    id: string;
    event_type: string;
    severity: string;
    source: string;
    title: string;
    description: string | null;
    observed_at: string;
    asset_id: string | null;
  }>;
};

export default function DashboardPage() {
  const [user, setUser] = useState<UserState>({ email: "", displayName: "" });
  const [loading, setLoading] = useState(true);
  const [signingOut, setSigningOut] = useState(false);
  const [overview, setOverview] = useState<SecurityOverview | null>(null);
  const [overviewLoading, setOverviewLoading] = useState(true);

  useEffect(() => {
    const supabase = createClient();

    async function loadUser() {
      const {
        data: { user: currentUser },
      } = await supabase.auth.getUser();

      if (currentUser) {
        const metadataName =
          typeof currentUser.user_metadata?.full_name === "string"
            ? currentUser.user_metadata.full_name.trim()
            : "";

        setUser({
          email: currentUser.email ?? "",
          displayName: metadataName,
        });
      }

      try {
        const response = await fetch("/api/security/overview", {
          method: "GET",
          cache: "no-store",
        });
        if (response.ok) {
          setOverview((await response.json()) as SecurityOverview);
        }
      } finally {
        setOverviewLoading(false);
      }

      setLoading(false);
    }

    void loadUser();
  }, []);

  async function handleSignOut() {
    setSigningOut(true);

    try {
      await createClient().auth.signOut();
    } finally {
      window.location.href = "/login";
    }
  }

  const operatorName = useMemo(
    () => user.displayName || user.email.split("@")[0] || "Security operator",
    [user.displayName, user.email]
  );

  const liveMetrics: Metric[] = [
    {
      label: "Protected assets",
      value: String(overview?.metrics.protectedAssets ?? 0),
      detail: overviewLoading ? "Loading verified data" : overview?.metrics.protectedAssets ? "Verified security assets" : "Connect your first surface",
      icon: Boxes,
    },
    {
      label: "Open findings",
      value: String(overview?.metrics.openFindings ?? 0),
      detail: overviewLoading ? "Loading verified data" : overview?.metrics.openFindings ? "Open or acknowledged findings" : "No findings recorded",
      icon: AlertTriangle,
    },
    {
      label: "Security events",
      value: String(overview?.metrics.securityEvents ?? 0),
      detail: overviewLoading ? "Loading verified data" : overview?.metrics.securityEvents ? "Verified telemetry events" : "Telemetry not connected",
      icon: Activity,
    },
    {
      label: "Attack paths",
      value: String(overview?.metrics.attackPaths ?? 0),
      detail: overviewLoading ? "Loading verified data" : overview?.metrics.attackPaths ? "Known asset relationships" : "Graph builds from relationships",
      icon: Network,
    },
  ];

  return (
    <main className="min-h-screen bg-[#071018] text-slate-100">
      <header className="sticky top-0 z-50 border-b border-white/10 bg-[#071018]/90 backdrop-blur-xl">
        <div className="mx-auto flex max-w-[1500px] items-center justify-between px-4 py-3 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <p className="text-sm font-semibold tracking-wide text-white">SentinelX</p>
              <p className="text-[11px] text-slate-500">AI Security Operating System</p>
            </div>
          </div>

          <div className="hidden items-center gap-1 lg:flex">
            {navigation.map((item) => {
              const Icon = item.icon;
              return (
                <a
                  key={item.label}
                  href={item.href}
                  className="flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-medium text-slate-400 transition hover:bg-white/5 hover:text-white"
                >
                  <Icon className="h-3.5 w-3.5" />
                  {item.label}
                </a>
              );
            })}
          </div>

          <div className="flex items-center gap-2">
            <div className="hidden items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 sm:flex">
              <UserRound className="h-4 w-4 text-slate-500" />
              <div className="max-w-[150px]">
                <p className="truncate text-xs font-medium text-white">{operatorName}</p>
                <p className="truncate text-[10px] text-slate-500">
                  {user.email || "Authenticated"}
                </p>
              </div>
            </div>
            <button
              type="button"
              aria-label="Settings"
              className="rounded-xl border border-white/10 p-2.5 text-slate-400 transition hover:bg-white/5 hover:text-white"
            >
              <Settings className="h-4 w-4" />
            </button>
            <button
              type="button"
              onClick={handleSignOut}
              disabled={signingOut}
              aria-label="Sign out"
              className="rounded-xl border border-white/10 p-2.5 text-slate-400 transition hover:bg-white/5 hover:text-white disabled:opacity-50"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-[1500px] px-4 py-6 sm:px-6 sm:py-8">
        <section id="command-center" className="grid gap-5 xl:grid-cols-[1.55fr_0.45fr]">
          <div className="relative overflow-hidden rounded-3xl border border-cyan-400/15 bg-gradient-to-br from-cyan-400/[0.08] via-white/[0.03] to-transparent p-6 sm:p-8">
            <div className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full bg-cyan-400/10 blur-3xl" />

            <div className="relative">
              <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-cyan-300">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan-300" />
                Defense layer online
              </div>

              <h1 className="max-w-3xl text-3xl font-semibold tracking-tight text-white sm:text-5xl">
                Good {new Date().getHours() < 12 ? "morning" : new Date().getHours() < 18 ? "afternoon" : "evening"},{" "}
                {loading ? "security operator" : operatorName}.
              </h1>

              <p className="mt-4 max-w-2xl text-sm leading-6 text-slate-400 sm:text-base">
                SentinelX is moving beyond isolated alerts. It is being built to understand
                your assets, their relationships, the signals around them, and the actions
                that can reduce risk.
              </p>

              <div className="mt-7 flex flex-wrap gap-3">
                <a
                  href="/assets"
                  className="inline-flex items-center gap-2 rounded-xl bg-cyan-300 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200"
                >
                  Add protected surface
                  <ArrowRight className="h-4 w-4" />
                </a>
                <a
                  href="#brain"
                  className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm font-semibold text-white transition hover:bg-white/[0.08]"
                >
                  Explore Security Brain
                  <BrainCircuit className="h-4 w-4" />
                </a>
              </div>
            </div>
          </div>

          <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-slate-500">System state</p>
                <p className="mt-1 text-lg font-semibold text-white">Evidence-first</p>
              </div>
              <Shield className="h-5 w-5 text-cyan-300" />
            </div>

            <div className="mt-6 space-y-4">
              {[
                ["Identity", "Connected", true],
                ["Security telemetry", "Awaiting sources", false],
                ["Automated response", "Not armed", false],
              ].map(([label, value, ok]) => (
                <div key={String(label)} className="flex items-center justify-between border-b border-white/5 pb-3 last:border-0">
                  <span className="text-xs text-slate-400">{label}</span>
                  <span className={ok ? "text-xs font-medium text-emerald-300" : "text-xs font-medium text-amber-300"}>
                    {String(value)}
                  </span>
                </div>
              ))}
            </div>

            <div className="mt-4 rounded-2xl border border-amber-400/10 bg-amber-400/[0.04] p-3">
              <p className="text-[11px] leading-5 text-slate-400">
                SentinelX will not invent a security score or threat count. Metrics appear
                only after verified telemetry is connected.
              </p>
            </div>
          </div>
        </section>

        <section className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {liveMetrics.map(({ label, value, detail, icon: Icon }) => (
            <div key={label} className="rounded-2xl border border-white/10 bg-white/[0.025] p-5">
              <div className="flex items-center justify-between">
                <p className="text-xs font-medium text-slate-500">{label}</p>
                <Icon className="h-4 w-4 text-slate-600" />
              </div>
              <p className="mt-4 text-3xl font-semibold tracking-tight text-white">{value}</p>
              <p className="mt-1 text-[11px] text-slate-500">{detail}</p>
            </div>
          ))}
        </section>

        <section id="assets" className="mt-8">
          <div className="mb-4 flex items-end justify-between gap-4">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">01 · Asset intelligence</p>
              <h2 className="mt-1 text-xl font-semibold text-white">What should SentinelX protect?</h2>
              <p className="mt-1 text-sm text-slate-500">
                Connect authorized surfaces instead of handing SentinelX raw passwords.
              </p>
            </div>
            <span className="hidden rounded-full border border-white/10 px-3 py-1 text-[10px] text-slate-500 sm:inline-flex">
              Least-privilege by design
            </span>
          </div>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {surfaces.map((surface) => {
              const Icon = surface.icon;
              const ready = surface.status === "ready";

              return (
                <a
                  key={surface.title}
                  href={surface.title === "AI systems & agents" ? "/ai-security" : surface.status === "ready" ? "/assets" : "#"}
                  className="group block text-left rounded-2xl border border-white/10 bg-white/[0.025] p-5 transition hover:border-cyan-300/20 hover:bg-cyan-300/[0.035]"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="rounded-xl border border-white/10 bg-white/[0.04] p-2.5 text-slate-300 group-hover:text-cyan-300">
                      <Icon className="h-5 w-5" />
                    </div>
                    <span className={ready ? "rounded-full bg-emerald-400/10 px-2 py-1 text-[9px] font-semibold uppercase tracking-wider text-emerald-300" : "rounded-full bg-white/5 px-2 py-1 text-[9px] font-semibold uppercase tracking-wider text-slate-500"}>
                      {ready ? "Available" : "Next"}
                    </span>
                  </div>
                  <h3 className="mt-5 text-sm font-semibold text-white">{surface.title}</h3>
                  <p className="mt-2 min-h-10 text-xs leading-5 text-slate-500">{surface.description}</p>
                  <div className="mt-4 flex items-center gap-1 text-[11px] font-medium text-slate-400 group-hover:text-cyan-300">
                    {ready ? "Configure" : "Planned"} <ChevronRight className="h-3.5 w-3.5" />
                  </div>
                </button>
              );
            })}
          </div>
        </section>

        <section id="brain" className="mt-8 grid gap-5 lg:grid-cols-3">
          <div className="lg:col-span-2 rounded-3xl border border-white/10 bg-white/[0.025] p-6 sm:p-7">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">02 · Security Brain</p>
                <h2 className="mt-1 text-xl font-semibold text-white">From alerts to relationships</h2>
              </div>
              <BrainCircuit className="h-6 w-6 text-cyan-300" />
            </div>

            <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-500">
              The Security Brain will connect assets, identities, software, data and events
              into a security graph. This is where SentinelX can reason about context rather
              than treating every alert as an isolated problem.
            </p>

            <div className="mt-6 grid gap-3 sm:grid-cols-3">
              {[
                ["Observe", "Collect verified signals"],
                ["Understand", "Map relationships and risk"],
                ["Act", "Recommend or execute approved responses"],
              ].map(([title, detail], index) => (
                <div key={title} className="rounded-2xl border border-white/10 bg-black/10 p-4">
                  <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-cyan-400/10 text-xs font-semibold text-cyan-300">
                    {index + 1}
                  </div>
                  <p className="mt-3 text-sm font-semibold text-white">{title}</p>
                  <p className="mt-1 text-xs leading-5 text-slate-500">{detail}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
            <div className="flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-cyan-300" />
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">AI analyst</p>
            </div>
            <h3 className="mt-3 text-lg font-semibold text-white">Evidence before action</h3>
            <p className="mt-2 text-sm leading-6 text-slate-500">
              Recommendations will cite the evidence that produced them and distinguish
              observed facts from AI analysis.
            </p>
            <div className="mt-5 rounded-2xl border border-cyan-400/10 bg-cyan-400/[0.04] p-4">
              <div className="flex items-center gap-2 text-xs font-medium text-cyan-200">
                <CheckCircle2 className="h-4 w-4" />
                Safety gate enabled
              </div>
              <p className="mt-2 text-[11px] leading-5 text-slate-500">
                High-impact actions will require explicit authorization until autonomous
                response policies are deliberately configured.
              </p>
            </div>
          </div>
        </section>

        <section id="activity" className="mt-8 rounded-3xl border border-white/10 bg-white/[0.025] p-6 sm:p-7">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">03 · Activity</p>
              <h2 className="mt-1 text-xl font-semibold text-white">Security timeline</h2>
              <p className="mt-1 text-sm text-slate-500">Only verified events will appear here.</p>
            </div>
            <button type="button" className="inline-flex w-fit items-center gap-2 rounded-xl border border-white/10 px-3 py-2 text-xs font-medium text-slate-400">
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </button>
          </div>

          <div className="mt-6 flex flex-col items-center justify-center rounded-2xl border border-dashed border-white/10 px-5 py-12 text-center">
            <Radar className="h-8 w-8 text-slate-700" />
            <h3 className="mt-4 text-sm font-semibold text-slate-300">No security telemetry yet</h3>
            <p className="mt-2 max-w-md text-xs leading-5 text-slate-600">
              Connect an authorized website, cloud environment, identity provider, or other
              protected surface. SentinelX will populate this timeline from real signals.
            </p>
          </div>
        </section>

        <footer className="mt-8 flex flex-col gap-2 border-t border-white/10 py-6 text-[10px] text-slate-600 sm:flex-row sm:items-center sm:justify-between">
          <p>SentinelX · AI Security Operating System</p>
          <p>Authorized systems only · Evidence-first security</p>
        </footer>
      </div>
    </main>
  );
}
