"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  CheckCircle2,
  KeyRound,
  LogOut,
  ShieldCheck,
  UserRound,
} from "lucide-react";
import { createClient } from "@/lib/supabase/client";

export default function SettingsPage() {
  const [email, setEmail] = useState("");
  const [signingOut, setSigningOut] = useState(false);

  useEffect(() => {
    let active = true;

    async function loadUser() {
      const supabase = createClient();
      const { data } = await supabase.auth.getUser();
      if (active) {
        setEmail(data.user?.email ?? "");
      }
    }

    void loadUser();

    return () => {
      active = false;
    };
  }, []);

  async function handleSignOut() {
    setSigningOut(true);
    const supabase = createClient();
    await supabase.auth.signOut();
    window.location.href = "/login";
  }

  return (
    <main className="min-h-screen bg-[#071018] px-4 py-6 text-slate-100 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-5xl">
        <header className="mb-8 flex items-center justify-between gap-4">
          <div>
            <Link
              href="/"
              className="mb-4 inline-flex items-center gap-2 text-xs font-medium text-slate-400 transition hover:text-white"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              Back to command center
            </Link>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <div>
                <h1 className="text-2xl font-semibold tracking-tight text-white">
                  Settings
                </h1>
                <p className="mt-1 text-sm text-slate-500">
                  Manage your Trinorin account and security workspace.
                </p>
              </div>
            </div>
          </div>
        </header>

        <section className="grid gap-4 md:grid-cols-2">
          <div className="rounded-2xl border border-white/10 bg-[#0b151f] p-5">
            <div className="flex items-center gap-3">
              <UserRound className="h-5 w-5 text-cyan-300" />
              <div>
                <h2 className="text-sm font-semibold text-white">Account</h2>
                <p className="text-xs text-slate-500">Authenticated Trinorin account</p>
              </div>
            </div>
            <div className="mt-5 rounded-xl border border-white/10 bg-black/10 p-4">
              <p className="text-[10px] uppercase tracking-wider text-slate-600">Email</p>
              <p className="mt-1 break-all text-sm text-slate-200">
                {email || "Authenticated account"}
              </p>
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 bg-[#0b151f] p-5">
            <div className="flex items-center gap-3">
              <KeyRound className="h-5 w-5 text-violet-300" />
              <div>
                <h2 className="text-sm font-semibold text-white">Authentication</h2>
                <p className="text-xs text-slate-500">Current session controls</p>
              </div>
            </div>
            <div className="mt-5 flex items-start gap-3 rounded-xl border border-emerald-400/10 bg-emerald-400/5 p-4">
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
              <p className="text-xs leading-5 text-slate-300">
                Your authenticated session is active. Trinorin does not expose
                security conclusions from this page; investigation controls remain
                in the intelligence workspace.
              </p>
            </div>
          </div>
        </section>

        <section className="mt-4 rounded-2xl border border-white/10 bg-[#0b151f] p-5">
          <h2 className="text-sm font-semibold text-white">Session</h2>
          <p className="mt-1 text-xs text-slate-500">
            Sign out of the current Trinorin session on this device.
          </p>
          <button
            type="button"
            onClick={handleSignOut}
            disabled={signingOut}
            className="mt-5 inline-flex items-center gap-2 rounded-xl border border-red-400/20 bg-red-400/5 px-4 py-2.5 text-xs font-semibold text-red-200 transition hover:bg-red-400/10 disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-300/60"
          >
            <LogOut className="h-4 w-4" />
            {signingOut ? "Signing out…" : "Sign out"}
          </button>
        </section>
      </div>
    </main>
  );
}
