"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  Boxes,
  CheckCircle2,
  CircleDashed,
  Globe2,
  KeyRound,
  Loader2,
  Plus,
  ShieldCheck,
  Sparkles,
  X,
} from "lucide-react";

type Asset = {
  id: string;
  name: string;
  asset_type: string;
  provider: string | null;
  environment: string;
  criticality: string;
  status: string;
  metadata: {
    onboarding?: {
      state?: string;
      next_step?: string;
      telemetry?: string;
      recommended_integrations?: string[];
    };
  } | null;
  created_at: string;
};

const types = [
  ["website", "Website", "Public-facing websites and applications"],
  ["domain", "Domain", "Domains and DNS assets"],
  ["cloud", "Cloud", "Cloud accounts, workloads and infrastructure"],
  ["identity", "Identity", "Identity providers and access systems"],
  ["business_software", "Business software", "SaaS and internal applications"],
  ["database", "Database", "Databases and important data stores"],
  ["ai_system", "AI system", "AI models, assistants and AI applications"],
  ["ai_agent", "AI agent", "Agents with tools or delegated permissions"],
] as const;

const intelligence: Record<string, { next: string; focus: string }> = {
  website: { next: "Connect HTTP, DNS, and application telemetry.", focus: "Web exposure and application signals" },
  domain: { next: "Verify ownership and connect DNS telemetry.", focus: "DNS, certificates and domain relationships" },
  cloud: { next: "Connect your cloud provider with least-privilege read access.", focus: "Infrastructure, identity and audit signals" },
  identity: { next: "Connect your identity provider and authentication signals.", focus: "Users, roles, sessions and authentication" },
  business_software: { next: "Connect audit or activity logs.", focus: "Application activity and critical workflows" },
  database: { next: "Connect audit signals without collecting database passwords.", focus: "Data access and database activity" },
  ai_system: { next: "Map the model, data, tools and permissions.", focus: "AI behavior, data exposure and tool access" },
  ai_agent: { next: "Map tools, permissions, data access and autonomy.", focus: "Agent pathways and delegated actions" },
};

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [selectedType, setSelectedType] = useState("website");

  async function loadAssets() {
    setLoading(true);
    try {
      const response = await fetch("/api/security/assets", { cache: "no-store" });
      const data = await response.json();
      if (response.ok) setAssets(data.assets ?? []);
      else setMessage(data.error ?? "Unable to load assets.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadAssets();
  }, []);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setMessage("");

    const form = new FormData(event.currentTarget);

    try {
      const response = await fetch("/api/security/assets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: form.get("name"),
          assetType: form.get("assetType"),
          provider: form.get("provider"),
          environment: form.get("environment"),
          criticality: form.get("criticality"),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setMessage(data.error ?? "Unable to add asset.");
        return;
      }

      setMessage("Asset registered. SentinelX has generated the next security step from its type.");
      event.currentTarget.reset();
      setSelectedType("website");
      setOpen(false);
      await loadAssets();
    } finally {
      setSaving(false);
    }
  }

  const summary = useMemo(() => {
    const telemetryConnected = assets.filter(
      (asset) => asset.metadata?.onboarding?.state === "telemetry_connected"
    ).length;

    return {
      total: assets.length,
      telemetryConnected,
      awaitingTelemetry: Math.max(assets.length - telemetryConnected, 0),
    };
  }, [assets]);

  return (
    <main className="min-h-screen bg-[#071018] text-slate-100">
      <header className="border-b border-white/10 bg-[#071018]/95">
        <div className="mx-auto flex max-w-[1200px] items-center justify-between px-4 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <p className="font-semibold text-white">SentinelX</p>
              <p className="text-[11px] text-slate-500">Protected surfaces</p>
            </div>
          </div>
          <Link href="/" className="inline-flex items-center gap-2 rounded-xl border border-white/10 px-3 py-2 text-xs text-slate-400 hover:text-white">
            <ArrowLeft className="h-3.5 w-3.5" /> Command Center
          </Link>
        </div>
      </header>

      <div className="mx-auto max-w-[1200px] px-4 py-8 sm:px-6">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">Asset intelligence</p>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Your security surface</h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
              SentinelX does more than store an asset. It uses the asset type to determine the next evidence and telemetry needed.
            </p>
          </div>
          <button onClick={() => setOpen(true)} className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-300 px-4 py-3 text-sm font-semibold text-slate-950 hover:bg-cyan-200">
            <Plus className="h-4 w-4" /> Add protected surface
          </button>
        </div>

        <div className="mt-6 grid gap-3 sm:grid-cols-3">
          <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Registered</p>
            <p className="mt-2 text-2xl font-semibold text-white">{summary.total}</p>
            <p className="mt-1 text-xs text-slate-600">Known security surfaces</p>
          </div>
          <div className="rounded-2xl border border-cyan-400/10 bg-cyan-400/[0.03] p-4">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Telemetry connected</p>
            <p className="mt-2 text-2xl font-semibold text-cyan-200">{summary.telemetryConnected}</p>
            <p className="mt-1 text-xs text-slate-600">Evidence sources actually reporting</p>
          </div>
          <div className="rounded-2xl border border-amber-400/10 bg-amber-400/[0.03] p-4">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Awaiting evidence</p>
            <p className="mt-2 text-2xl font-semibold text-amber-200">{summary.awaitingTelemetry}</p>
            <p className="mt-1 text-xs text-slate-600">Registered, but not yet monitored</p>
          </div>
        </div>

        {message && (
          <div className="mt-5 rounded-xl border border-cyan-400/15 bg-cyan-400/[0.04] p-4 text-sm text-cyan-200">
            {message}
          </div>
        )}

        {loading ? (
          <div className="mt-8 flex items-center gap-2 text-sm text-slate-500"><Loader2 className="h-4 w-4 animate-spin" /> Loading verified assets...</div>
        ) : assets.length ? (
          <div className="mt-8 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {assets.map((asset) => {
              const plan = intelligence[asset.asset_type] ?? {
                next: asset.metadata?.onboarding?.next_step ?? "Define the next evidence source.",
                focus: "Security surface analysis",
              };

              return (
                <div key={asset.id} className="rounded-2xl border border-white/10 bg-white/[0.025] p-5">
                  <div className="flex items-start justify-between">
                    <div className="rounded-xl border border-white/10 bg-white/[0.04] p-2.5 text-cyan-300">
                      {asset.asset_type === "website" || asset.asset_type === "domain" ? <Globe2 className="h-5 w-5" /> : asset.asset_type === "identity" ? <KeyRound className="h-5 w-5" /> : <Boxes className="h-5 w-5" />}
                    </div>
                    <span className="rounded-full bg-emerald-400/10 px-2 py-1 text-[9px] uppercase tracking-wider text-emerald-300">{asset.status}</span>
                  </div>
                  <h2 className="mt-5 font-semibold text-white">{asset.name}</h2>
                  <p className="mt-1 text-xs capitalize text-slate-500">{asset.asset_type.replaceAll("_", " ")} · {asset.environment}</p>
                  <p className="mt-4 text-[11px] text-slate-600">Criticality: {asset.criticality}</p>

                  <div className="mt-4 rounded-xl border border-cyan-400/10 bg-cyan-400/[0.03] p-3">
                    <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-cyan-300">
                      <Sparkles className="h-3.5 w-3.5" /> SentinelX next step
                    </div>
                    <p className="mt-2 text-xs leading-5 text-slate-400">{plan.next}</p>
                    <p className="mt-2 text-[10px] text-slate-600">Focus: {plan.focus}</p>
                  </div>

                  <div className="mt-3 flex items-center gap-2 text-[10px] text-amber-300/80">
                    <CircleDashed className="h-3.5 w-3.5" />
                    {asset.metadata?.onboarding?.telemetry ?? "Telemetry not connected"}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="mt-8 rounded-3xl border border-dashed border-white/10 px-6 py-16 text-center">
            <Boxes className="mx-auto h-9 w-9 text-slate-700" />
            <h2 className="mt-4 font-semibold text-slate-300">No protected surfaces yet</h2>
            <p className="mx-auto mt-2 max-w-md text-xs leading-5 text-slate-600">
              Add your first authorized asset. SentinelX will turn it into the first node of the Security Graph and explain what evidence is missing.
            </p>
          </div>
        )}
      </div>

      {open && (
        <div className="fixed inset-0 z-50 flex items-end justify-center bg-black/70 p-3 backdrop-blur-sm sm:items-center">
          <div className="w-full max-w-lg rounded-3xl border border-white/10 bg-[#0b151f] p-6 shadow-2xl">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold text-white">Add protected surface</h2>
                <p className="mt-1 text-xs text-slate-500">SentinelX will determine the next security step automatically.</p>
              </div>
              <button onClick={() => setOpen(false)} className="rounded-lg p-2 text-slate-500 hover:text-white"><X className="h-5 w-5" /></button>
            </div>

            <form onSubmit={handleSubmit} className="mt-6 space-y-4">
              <input name="name" required placeholder="Asset name, e.g. company website" className="w-full rounded-xl border border-white/10 bg-black/20 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-600 focus:border-cyan-400/40" />
              <select
                name="assetType"
                required
                value={selectedType}
                onChange={(event) => setSelectedType(event.target.value)}
                className="w-full rounded-xl border border-white/10 bg-[#071018] px-4 py-3 text-sm text-white outline-none focus:border-cyan-400/40"
              >
                {types.map(([value, label, description]) => <option key={value} value={value}>{label} — {description}</option>)}
              </select>

              <div className="rounded-xl border border-cyan-400/10 bg-cyan-400/[0.03] p-3">
                <div className="flex items-center gap-2 text-xs font-medium text-cyan-200">
                  <Sparkles className="h-4 w-4" /> What SentinelX will look for
                </div>
                <p className="mt-2 text-xs leading-5 text-slate-500">
                  {intelligence[selectedType]?.next ?? "SentinelX will define the next evidence source after registration."}
                </p>
              </div>

              <input name="provider" placeholder="Provider (optional), e.g. Vercel, Cloudflare, Google" className="w-full rounded-xl border border-white/10 bg-black/20 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-600 focus:border-cyan-400/40" />
              <div className="grid gap-4 sm:grid-cols-2">
                <select name="environment" defaultValue="production" className="w-full rounded-xl border border-white/10 bg-[#071018] px-4 py-3 text-sm text-white outline-none">
                  <option value="production">Production</option>
                  <option value="staging">Staging</option>
                  <option value="development">Development</option>
                </select>
                <select name="criticality" defaultValue="medium" className="w-full rounded-xl border border-white/10 bg-[#071018] px-4 py-3 text-sm text-white outline-none">
                  <option value="low">Low criticality</option>
                  <option value="medium">Medium criticality</option>
                  <option value="high">High criticality</option>
                  <option value="critical">Critical</option>
                </select>
              </div>

              <div className="rounded-xl border border-white/10 bg-black/10 p-3 text-[10px] leading-5 text-slate-600">
                SentinelX does not ask for raw passwords here. Connections will use authorized integrations, delegated access, or API credentials where supported.
              </div>

              <button disabled={saving} className="flex w-full items-center justify-center gap-2 rounded-xl bg-cyan-300 px-4 py-3 text-sm font-semibold text-slate-950 disabled:opacity-50">
                {saving ? <><Loader2 className="h-4 w-4 animate-spin" /> Analyzing surface...</> : <><CheckCircle2 className="h-4 w-4" /> Register & analyze</>}
              </button>
            </form>
          </div>
        </div>
      )}
    </main>
  );
}
