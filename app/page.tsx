import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Globe2,
  LockKeyhole,
  Radar,
  ShieldCheck,
  ShieldAlert,
  Server,
  Settings,
  Terminal,
  Users,
} from "lucide-react";

const findings = [
  {
    title: "Suspicious login activity",
    asset: "Admin Portal",
    severity: "High",
    time: "12 min ago",
  },
  {
    title: "Outdated dependency detected",
    asset: "Web Application",
    severity: "Medium",
    time: "38 min ago",
  },
  {
    title: "Unusual outbound traffic",
    asset: "Production API",
    severity: "Medium",
    time: "1 hr ago",
  },
];

const activity = [
  {
    icon: ShieldCheck,
    title: "Security scan completed",
    description: "142 assets analyzed",
    time: "18 min ago",
  },
  {
    icon: LockKeyhole,
    title: "Access policy updated",
    description: "Admin Portal",
    time: "42 min ago",
  },
  {
    icon: Radar,
    title: "Threat monitoring active",
    description: "Continuous protection enabled",
    time: "1 hr ago",
  },
];

function StatCard({
  icon: Icon,
  label,
  value,
  detail,
}: {
  icon: typeof ShieldCheck;
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex items-start justify-between">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-slate-100">
          <Icon className="h-5 w-5 text-slate-700" />
        </div>
        <ArrowUpRight className="h-4 w-4 text-slate-400" />
      </div>

      <div className="mt-5">
        <p className="text-sm font-medium text-slate-500">{label}</p>
        <p className="mt-1 text-2xl font-semibold tracking-tight text-slate-950">
          {value}
        </p>
        <p className="mt-1 text-xs text-slate-500">{detail}</p>
      </div>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const styles = {
    High: "bg-red-50 text-red-700 border-red-200",
    Medium: "bg-amber-50 text-amber-700 border-amber-200",
    Low: "bg-slate-50 text-slate-600 border-slate-200",
  };

  return (
    <span
      className={`rounded-full border px-2.5 py-1 text-xs font-medium ${
        styles[severity as keyof typeof styles]
      }`}
    >
      {severity}
    </span>
  );
}

export default function Home() {
  return (
    <main className="min-h-screen bg-slate-50 text-slate-950">
      <div className="flex min-h-screen">
        {/* Sidebar */}
        <aside className="hidden w-64 flex-col border-r border-slate-200 bg-white lg:flex">
          <div className="flex h-20 items-center border-b border-slate-200 px-6">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-slate-950">
                <ShieldCheck className="h-5 w-5 text-white" />
              </div>

              <div>
                <p className="text-base font-bold tracking-tight">SentinelX</p>
                <p className="text-[11px] text-slate-500">
                  Security Intelligence
                </p>
              </div>
            </div>
          </div>

          <nav className="flex-1 space-y-1 p-4">
            <a
              href="#"
              className="flex items-center gap-3 rounded-xl bg-slate-950 px-3 py-2.5 text-sm font-medium text-white"
            >
              <Activity className="h-4 w-4" />
              Overview
            </a>

            <a
              href="#"
              className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium text-slate-600 hover:bg-slate-100"
            >
              <Radar className="h-4 w-4" />
              Threat Detection
            </a>

            <a
              href="#"
              className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium text-slate-600 hover:bg-slate-100"
            >
              <Server className="h-4 w-4" />
              Assets
            </a>

            <a
              href="#"
              className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium text-slate-600 hover:bg-slate-100"
            >
              <AlertTriangle className="h-4 w-4" />
              Findings
            </a>

            <a
              href="#"
              className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium text-slate-600 hover:bg-slate-100"
            >
              <Terminal className="h-4 w-4" />
              Security Operations
            </a>

            <a
              href="#"
              className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium text-slate-600 hover:bg-slate-100"
            >
              <Users className="h-4 w-4" />
              Team
            </a>
          </nav>

          <div className="border-t border-slate-200 p-4">
            <a
              href="#"
              className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium text-slate-600 hover:bg-slate-100"
            >
              <Settings className="h-4 w-4" />
              Settings
            </a>
          </div>
        </aside>

        {/* Main content */}
        <section className="min-w-0 flex-1">
          {/* Header */}
          <header className="border-b border-slate-200 bg-white">
            <div className="flex min-h-20 items-center justify-between gap-4 px-5 py-4 sm:px-8">
              <div>
                <p className="text-sm font-medium text-slate-500">
                  Security Operations
                </p>
                <h1 className="mt-1 text-xl font-semibold tracking-tight sm:text-2xl">
                  Security Overview
                </h1>
              </div>

              <div className="flex items-center gap-3">
                <div className="hidden items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1.5 sm:flex">
                  <CircleDot className="h-3.5 w-3.5 fill-emerald-500 text-emerald-500" />
                  <span className="text-xs font-medium text-emerald-700">
                    Systems Operational
                  </span>
                </div>

                <button
                  type="button"
                  className="rounded-xl border border-slate-200 p-2.5 text-slate-600 hover:bg-slate-50"
                  aria-label="Settings"
                >
                  <Settings className="h-4 w-4" />
                </button>
              </div>
            </div>
          </header>

          <div className="mx-auto max-w-7xl space-y-6 p-5 sm:p-8">
            {/* Security status */}
            <section className="overflow-hidden rounded-2xl bg-slate-950 p-6 text-white shadow-sm sm:p-8">
              <div className="flex flex-col justify-between gap-8 lg:flex-row lg:items-center">
                <div className="max-w-2xl">
                  <div className="flex items-center gap-2">
                    <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-white/10">
                      <ShieldCheck className="h-5 w-5" />
                    </div>
                    <span className="text-sm font-medium text-slate-300">
                      SentinelX Protection
                    </span>
                  </div>

                  <h2 className="mt-5 text-2xl font-semibold tracking-tight sm:text-3xl">
                    Your environment is being monitored.
                  </h2>

                  <p className="mt-3 max-w-xl text-sm leading-6 text-slate-400">
                    SentinelX continuously analyzes your digital environment,
                    identifies security risks, and turns findings into
                    actionable intelligence.
                  </p>
                </div>

                <div className="flex shrink-0 items-center gap-4 rounded-2xl border border-white/10 bg-white/5 p-5">
                  <div className="flex h-14 w-14 items-center justify-center rounded-full border border-emerald-400/30 bg-emerald-400/10">
                    <CheckCircle2 className="h-7 w-7 text-emerald-400" />
                  </div>

                  <div>
                    <p className="text-xs text-slate-400">Protection status</p>
                    <p className="mt-1 text-lg font-semibold text-emerald-400">
                      Active
                    </p>
                  </div>
                </div>
              </div>
            </section>

            {/* Stats */}
            <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <StatCard
                icon={Server}
                label="Protected assets"
                value="142"
                detail="Across your environment"
              />

              <StatCard
                icon={AlertTriangle}
                label="Open findings"
                value="7"
                detail="3 require attention"
              />

              <StatCard
                icon={ShieldCheck}
                label="Security score"
                value="94%"
                detail="Up 4% this month"
              />

              <StatCard
                icon={Globe2}
                label="Threats blocked"
                value="1,284"
                detail="Last 30 days"
              />
            </section>

            {/* Findings + Activity */}
            <section className="grid gap-6 xl:grid-cols-[1.4fr_1fr]">
              <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">
                <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4">
                  <div>
                    <h2 className="font-semibold">Priority findings</h2>
                    <p className="mt-1 text-xs text-slate-500">
                      Security issues requiring review
                    </p>
                  </div>

                  <button
                    type="button"
                    className="flex items-center gap-1 text-xs font-medium text-slate-700 hover:text-slate-950"
                  >
                    View all
                    <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                </div>

                <div className="divide-y divide-slate-100">
                  {findings.map((finding) => (
                    <div
                      key={finding.title}
                      className="flex items-center justify-between gap-4 px-5 py-4"
                    >
                      <div className="flex min-w-0 items-center gap-3">
                        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-slate-100">
                          <ShieldAlert className="h-4 w-4 text-slate-700" />
                        </div>

                        <div className="min-w-0">
                          <p className="truncate text-sm font-medium">
                            {finding.title}
                          </p>
                          <p className="mt-1 truncate text-xs text-slate-500">
                            {finding.asset} · {finding.time}
                          </p>
                        </div>
                      </div>

                      <SeverityBadge severity={finding.severity} />
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">
                <div className="border-b border-slate-200 px-5 py-4">
                  <h2 className="font-semibold">Recent activity</h2>
                  <p className="mt-1 text-xs text-slate-500">
                    Latest security events
                  </p>
                </div>

                <div className="divide-y divide-slate-100">
                  {activity.map((item) => {
                    const Icon = item.icon;

                    return (
                      <div
                        key={item.title}
                        className="flex gap-3 px-5 py-4"
                      >
                        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-slate-100">
                          <Icon className="h-4 w-4 text-slate-700" />
                        </div>

                        <div className="min-w-0">
                          <p className="text-sm font-medium">{item.title}</p>
                          <p className="mt-1 text-xs text-slate-500">
                            {item.description}
                          </p>
                          <p className="mt-1 text-[11px] text-slate-400">
                            {item.time}
                          </p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </section>

            {/* Bottom intelligence panel */}
            <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm sm:p-6">
              <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-center">
                <div className="flex items-start gap-4">
                  <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-slate-100">
                    <Radar className="h-5 w-5 text-slate-700" />
                  </div>

                  <div>
                    <h2 className="font-semibold">Security intelligence</h2>
                    <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-500">
                      SentinelX is ready to connect your security data,
                      analyze threats, and provide AI-assisted recommendations.
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  className="inline-flex items-center justify-center gap-2 rounded-xl bg-slate-950 px-4 py-2.5 text-sm font-medium text-white hover:bg-slate-800"
                >
                  Configure protection
                  <ArrowUpRight className="h-4 w-4" />
                </button>
              </div>
            </section>
          </div>
        </section>
      </div>
    </main>
  );
}
