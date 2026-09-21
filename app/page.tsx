"use client";

import { useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  LogOut,
  ShieldCheck,
  Settings,
  TrendingUp,
  UserRound,
} from "lucide-react";
import { createClient } from "@/lib/supabase/client";

export default function DashboardPage() {
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [signingOut, setSigningOut] = useState(false);

  useEffect(() => {
    const supabase = createClient();

    async function loadUser() {
      const {
        data: { user },
      } = await supabase.auth.getUser();

      if (!user) {
        return;
      }

      setEmail(user.email ?? "");

      const metadataName =
        typeof user.user_metadata?.full_name === "string"
          ? user.user_metadata.full_name.trim()
          : "";

      setDisplayName(metadataName);
    }

    loadUser();
  }, []);

  async function handleSignOut() {
    setSigningOut(true);

    try {
      const supabase = createClient();
      await supabase.auth.signOut();
    } finally {
      window.location.href = "/login";
    }
  }

  const operatorName = displayName || email || "Security operator";

  return (
    <main className="min-h-screen bg-slate-50 text-slate-950">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-slate-950 text-white">
              <ShieldCheck className="h-5 w-5" />
            </div>

            <div>
              <h1 className="text-lg font-bold tracking-tight">
                SentinelX
              </h1>
              <p className="text-xs text-slate-500">
                Security Intelligence Platform
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden items-center gap-2 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 sm:flex">
              <UserRound className="h-4 w-4 text-slate-500" />

              <div className="max-w-[180px]">
                <p className="truncate text-sm font-medium text-slate-800">
                  {operatorName}
                </p>

                {displayName && email && (
                  <p className="truncate text-xs text-slate-500">
                    {email}
                  </p>
                )}
              </div>
            </div>

            <button
              type="button"
              className="rounded-xl border border-slate-200 bg-white p-2.5 text-slate-600 transition hover:bg-slate-50 hover:text-slate-950"
              aria-label="Settings"
            >
              <Settings className="h-5 w-5" />
            </button>

            <button
              type="button"
              onClick={handleSignOut}
              disabled={signingOut}
              className="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm font-medium text-slate-700 transition hover:bg-slate-50 hover:text-slate-950 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <LogOut className="h-4 w-4" />

              <span className="hidden sm:inline">
                {signingOut ? "Signing out..." : "Sign out"}
              </span>
            </button>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-6 py-8">
        <section className="mb-8">
          <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-xs font-medium text-emerald-700">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  System operational
                </div>

                <h2 className="text-3xl font-bold tracking-tight text-slate-950">
                  Welcome back,{" "}
                  {displayName || "security operator"}.
                </h2>

                <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
                  Your security environment is being monitored.
                  Review threats, security events, and operational
                  indicators from your SentinelX dashboard.
                </p>
              </div>

              <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-2xl bg-slate-950 text-white">
                <ShieldCheck className="h-8 w-8" />
              </div>
            </div>
          </div>
        </section>

        <section className="grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium text-slate-500">
                Security Score
              </p>

              <div className="rounded-lg bg-emerald-50 p-2 text-emerald-600">
                <ShieldCheck className="h-5 w-5" />
              </div>
            </div>

            <p className="mt-4 text-3xl font-bold text-slate-950">
              94%
            </p>

            <div className="mt-2 flex items-center gap-1 text-xs font-medium text-emerald-600">
              <TrendingUp className="h-3.5 w-3.5" />
              +4.2% this month
            </div>
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium text-slate-500">
                Active Threats
              </p>

              <div className="rounded-lg bg-red-50 p-2 text-red-600">
                <AlertTriangle className="h-5 w-5" />
              </div>
            </div>

            <p className="mt-4 text-3xl font-bold text-slate-950">
              3
            </p>

            <p className="mt-2 text-xs font-medium text-red-600">
              Requires investigation
            </p>
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium text-slate-500">
                Protected Assets
              </p>

              <div className="rounded-lg bg-blue-50 p-2 text-blue-600">
                <CheckCircle2 className="h-5 w-5" />
              </div>
            </div>

            <p className="mt-4 text-3xl font-bold text-slate-950">
              128
            </p>

            <p className="mt-2 text-xs font-medium text-slate-500">
              Devices and services
            </p>
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium text-slate-500">
                Events Today
              </p>

              <div className="rounded-lg bg-amber-50 p-2 text-amber-600">
                <Clock3 className="h-5 w-5" />
              </div>
            </div>

            <p className="mt-4 text-3xl font-bold text-slate-950">
              1,284
            </p>

            <p className="mt-2 text-xs font-medium text-slate-500">
              Security events processed
            </p>
          </div>
        </section>

        <section className="mt-8 grid gap-6 lg:grid-cols-3">
          <div className="lg:col-span-2 rounded-2xl border border-slate-200 bg-white shadow-sm">
            <div className="border-b border-slate-200 px-6 py-5">
              <h3 className="text-base font-semibold text-slate-950">
                Recent Security Activity
              </h3>

              <p className="mt-1 text-sm text-slate-500">
                Latest events detected across the environment.
              </p>
            </div>

            <div className="divide-y divide-slate-100">
              <div className="flex items-center gap-4 px-6 py-5">
                <div className="rounded-full bg-emerald-50 p-2 text-emerald-600">
                  <CheckCircle2 className="h-4 w-4" />
                </div>

                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-slate-800">
                    Authentication monitoring active
                  </p>

                  <p className="mt-1 text-xs text-slate-500">
                    Identity systems are responding normally.
                  </p>
                </div>

                <span className="text-xs text-slate-400">
                  5 min ago
                </span>
              </div>

              <div className="flex items-center gap-4 px-6 py-5">
                <div className="rounded-full bg-amber-50 p-2 text-amber-600">
                  <AlertTriangle className="h-4 w-4" />
                </div>

                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-slate-800">
                    Suspicious login activity detected
                  </p>

                  <p className="mt-1 text-xs text-slate-500">
                    An unusual authentication event requires review.
                  </p>
                </div>

                <span className="text-xs text-slate-400">
                  18 min ago
                </span>
              </div>

              <div className="flex items-center gap-4 px-6 py-5">
                <div className="rounded-full bg-blue-50 p-2 text-blue-600">
                  <ShieldCheck className="h-4 w-4" />
                </div>

                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-slate-800">
                    Security policy scan completed
                  </p>

                  <p className="mt-1 text-xs text-slate-500">
                    Environment configuration was checked successfully.
                  </p>
                </div>

                <span className="text-xs text-slate-400">
                  42 min ago
                </span>
              </div>
            </div>
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">
            <div className="border-b border-slate-200 px-6 py-5">
              <h3 className="text-base font-semibold text-slate-950">
                Account
              </h3>

              <p className="mt-1 text-sm text-slate-500">
                Current authenticated operator.
              </p>
            </div>

            <div className="space-y-5 p-6">
              <div>
                <p className="text-xs font-medium uppercase tracking-wide text-slate-400">
                  Name
                </p>

                <p className="mt-1 text-sm font-medium text-slate-800">
                  {displayName || "Not provided"}
                </p>
              </div>

              <div>
                <p className="text-xs font-medium uppercase tracking-wide text-slate-400">
                  Email
                </p>

                <p className="mt-1 break-all text-sm font-medium text-slate-800">
                  {email || "Loading..."}
                </p>
              </div>

              <div>
                <p className="text-xs font-medium uppercase tracking-wide text-slate-400">
                  Access
                </p>

                <div className="mt-2 inline-flex items-center gap-2 rounded-full bg-emerald-50 px-3 py-1 text-xs font-medium text-emerald-700">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  Authenticated
                </div>
              </div>

              <button
                type="button"
                onClick={handleSignOut}
                disabled={signingOut}
                className="flex w-full items-center justify-center gap-2 rounded-xl bg-slate-950 px-4 py-3 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <LogOut className="h-4 w-4" />

                {signingOut ? "Signing out..." : "Sign out"}
              </button>
            </div>
          </div>
        </section>

        <footer className="mt-8 border-t border-slate-200 py-6">
          <div className="flex flex-col gap-2 text-xs text-slate-400 sm:flex-row sm:items-center sm:justify-between">
            <p>SentinelX Security Intelligence</p>

            <p>
              Dashboard data is currently configured as demonstration
              telemetry.
            </p>
          </div>
        </footer>
      </div>
    </main>
  );
}
