"use client";

import { FormEvent, useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  CheckCircle2,
  Cloud,
  Database,
  KeyRound,
  Link2,
  Loader2,
  Plus,
  ShieldCheck,
  Sparkles,
  X,
} from "lucide-react";

type Integration = {
  id: string;
  provider: string;
  integration_type: string;
  display_name: string;
  status: string;
  scopes: string[];
  last_sync_at: string | null;
  created_at: string;
};

const catalog = [
  {
    provider: "Cloud",
    type: "cloud",
    title: "Cloud security",
    description: "Infrastructure inventory, audit activity and identity signals.",
    icon: Cloud,
    scopes: ["asset_inventory", "audit_logs", "identity_metadata"],
  },
  {
    provider: "Identity",
    type: "identity",
    title: "Identity provider",
    description: "Authentication, sessions, roles and access relationships.",
    icon: KeyRound,
    scopes: ["users", "roles", "authentication_events"],
  },
  {
    provider: "Application",
    type: "application",
    title: "Business application",
    description: "Authorized audit and activity signals from critical software.",
    icon: Link2,
    scopes: ["audit_logs", "activity_events"],
  },
  {
    provider: "Database",
    type: "database",
    title: "Database telemetry",
    description: "Read-only audit and access signals without collecting database passwords.",
    icon: Database,
    scopes: ["audit_logs", "access_events", "metadata"],
  },
];

export default function IntegrationsPage() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState(catalog[0]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");

  async function loadIntegrations() {
    setLoading(true);
    try {
      const response = await fetch("/api/security/integrations", { cache: "no-store" });
      const data = await response.json();
      if (response.ok) setIntegrations(data.integrations ?? []);
      else setMessage(data.error ?? "Unable to load integrations.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadIntegrations();
  }, []);

  async function registerIntegration(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setMessage("");

    try {
      const response = await fetch("/api/security/integrations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: selected.provider,
          integrationType: selected.type,
          displayName: selected.title,
          scopes: selected.scopes,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setMessage(data.error ?? "Unable to register integration.");
        return;
      }

      setMessage("Integration registered. SentinelX is ready for an authorized connection.");
      setOpen(false);
      await loadIntegrations();
    } finally {
      setSaving(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#071018] text-slate-100">
      <header className="border-b border-white/10 bg-[#071018]/95">
        <div className="mx-auto flex max-w-[1200px] items-center justify-between px-4 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
              <Link2 className="h-5 w-5" />
            </div>
            <div>
              <p className="font-semibold text-white">Security Integrations</p>
              <p className="text-[11px] text-slate-500">Authorized telemetry sources</p>
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
            <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">Evidence layer</p>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Connect real security signals</h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
              SentinelX registers the integration first. Connection methods will use authorized OAuth, delegated access, or scoped API credentials rather than raw passwords.
            </p>
          </div>
          <button onClick={() => setOpen(true)} className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-300 px-4 py-3 text-sm font-semibold text-slate-950">
            <Plus className="h-4 w-4" /> Register integration
          </button>
        </div>

        {message && (
          <div className="mt-5 rounded-xl border border-cyan-400/15 bg-cyan-400/[0.04] p-4 text-sm text-cyan-200">
            {message}
          </div>
        )}

        <section className="mt-8">
          <div className="mb-4 flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-cyan-300" />
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Integration catalog</p>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            {catalog.map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.type}
                  onClick={() => { setSelected(item); setOpen(true); }}
                  className="rounded-2xl border border-white/10 bg-white/[0.025] p-5 text-left transition hover:border-cyan-400/20 hover:bg-cyan-400/[0.03]"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="rounded-xl border border-white/10 bg-white/[0.04] p-2.5 text-cyan-300">
                      <Icon className="h-5 w-5" />
                    </div>
                    <span className="rounded-full bg-white/5 px-2 py-1 text-[9px] uppercase tracking-wider text-slate-500">Available</span>
                  </div>
                  <p className="mt-5 text-sm font-semibold text-white">{item.title}</p>
                  <p className="mt-2 text-xs leading-5 text-slate-500">{item.description}</p>
                  <div className="mt-4 flex flex-wrap gap-2">
                    {item.scopes.map((scope) => (
                      <span key={scope} className="rounded-full border border-white/10 px-2 py-1 text-[9px] text-slate-500">{scope.replaceAll("_", " ")}</span>
                    ))}
                  </div>
                </button>
              );
            })}
          </div>
        </section>

        <section className="mt-8">
          <div className="mb-4 flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-cyan-300" />
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Registered integrations</p>
          </div>

          {loading ? (
            <div className="flex items-center gap-2 text-sm text-slate-500"><Loader2 className="h-4 w-4 animate-spin" /> Loading integration state...</div>
          ) : integrations.length ? (
            <div className="space-y-3">
              {integrations.map((integration) => (
                <div key={integration.id} className="rounded-2xl border border-white/10 bg-white/[0.025] p-5">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <div>
                      <p className="font-semibold text-white">{integration.display_name}</p>
                      <p className="mt-1 text-xs text-slate-500">{integration.provider} · {integration.integration_type}</p>
                    </div>
                    <span className="inline-flex w-fit items-center gap-1 rounded-full bg-amber-400/10 px-2.5 py-1 text-[9px] font-semibold uppercase tracking-wider text-amber-300">
                      {integration.status}
                    </span>
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2">
                    {integration.scopes.map((scope) => (
                      <span key={scope} className="rounded-full border border-white/10 px-2 py-1 text-[9px] text-slate-500">{scope.replaceAll("_", " ")}</span>
                    ))}
                  </div>
                  <p className="mt-3 text-[10px] text-slate-600">
                    {integration.last_sync_at ? `Last sync: ${new Date(integration.last_sync_at).toLocaleString()}` : "Not connected · no telemetry is being claimed."}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-3xl border border-dashed border-white/10 px-6 py-14 text-center">
              <Link2 className="mx-auto h-8 w-8 text-slate-700" />
              <p className="mt-4 text-sm font-semibold text-slate-300">No telemetry integrations registered</p>
              <p className="mx-auto mt-2 max-w-md text-xs leading-5 text-slate-600">
                Register an integration to define the evidence SentinelX is authorized to receive.
              </p>
            </div>
          )}
        </section>
      </div>

      {open && (
        <div className="fixed inset-0 z-50 flex items-end justify-center bg-black/70 p-3 backdrop-blur-sm sm:items-center">
          <div className="w-full max-w-lg rounded-3xl border border-white/10 bg-[#0b151f] p-6 shadow-2xl">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold text-white">Register integration</h2>
                <p className="mt-1 text-xs text-slate-500">No credentials are requested at this stage.</p>
              </div>
              <button onClick={() => setOpen(false)} className="rounded-lg p-2 text-slate-500 hover:text-white"><X className="h-5 w-5" /></button>
            </div>

            <form onSubmit={registerIntegration} className="mt-6 space-y-4">
              <select
                value={selected.type}
                onChange={(event) => {
                  const next = catalog.find((item) => item.type === event.target.value);
                  if (next) setSelected(next);
                }}
                className="w-full rounded-xl border border-white/10 bg-[#071018] px-4 py-3 text-sm text-white"
              >
                {catalog.map((item) => <option key={item.type} value={item.type}>{item.title}</option>)}
              </select>

              <div className="rounded-2xl border border-cyan-400/10 bg-cyan-400/[0.03] p-4">
                <p className="text-xs font-semibold text-cyan-200">{selected.title}</p>
                <p className="mt-2 text-xs leading-5 text-slate-500">{selected.description}</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {selected.scopes.map((scope) => (
                    <span key={scope} className="rounded-full border border-white/10 px-2 py-1 text-[9px] text-slate-500">{scope.replaceAll("_", " ")}</span>
                  ))}
                </div>
              </div>

              <div className="rounded-xl border border-white/10 bg-black/10 p-3 text-[10px] leading-5 text-slate-600">
                The integration will remain <strong className="text-amber-300">planned</strong> until an authorized connection is completed. SentinelX will not fabricate telemetry, findings, or protection status.
              </div>

              <button disabled={saving} className="flex w-full items-center justify-center gap-2 rounded-xl bg-cyan-300 px-4 py-3 text-sm font-semibold text-slate-950 disabled:opacity-50">
                {saving ? <><Loader2 className="h-4 w-4 animate-spin" /> Registering...</> : <><CheckCircle2 className="h-4 w-4" /> Register integration</>}
              </button>
            </form>
          </div>
        </div>
      )}
    </main>
  );
}
