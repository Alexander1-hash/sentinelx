"use client";

import { FormEvent, useEffect, useState } from "react";
import Link from "next/link";
import { AlertCircle, CheckCircle2, Loader2, ShieldCheck } from "lucide-react";
import { createClient } from "@/lib/supabase/client";

export default function ResetPasswordPage() {
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [checkingSession, setCheckingSession] = useState(true);
  const [success, setSuccess] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    const supabase = createClient();

    async function checkSession() {
      const { data, error: sessionError } = await supabase.auth.getSession();

      if (sessionError || !data.session) {
        setError(
          "This password reset link is invalid or has expired. Please request a new reset link."
        );
      }

      setCheckingSession(false);
    }

    checkSession();
  }, []);

  async function handleReset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    setError("");
    setSuccess("");

    if (password.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);

    try {
      const supabase = createClient();

      const { error: updateError } = await supabase.auth.updateUser({
        password,
      });

      if (updateError) {
        setError(updateError.message);
        setLoading(false);
        return;
      }

      setSuccess(
        "Your password has been updated successfully. You can now sign in with your new password."
      );

      setPassword("");
      setConfirmPassword("");
      setLoading(false);
    } catch {
      setError(
        "Something went wrong while updating your password. Please try again."
      );
      setLoading(false);
    }
  }

  return (
    <main className="min-h-screen bg-slate-950 text-white">
      <div className="flex min-h-screen items-center justify-center px-6 py-12">
        <div className="w-full max-w-md">
          <div className="mb-8 text-center">
            <div className="mx-auto mb-5 flex h-14 w-14 items-center justify-center rounded-2xl bg-white text-slate-950 shadow-lg">
              <ShieldCheck className="h-7 w-7" />
            </div>

            <h1 className="text-3xl font-bold tracking-tight">
              Create a new password
            </h1>

            <p className="mt-2 text-sm text-slate-400">
              Choose a new password to secure your SentinelX account.
            </p>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">
            {checkingSession ? (
              <div className="flex flex-col items-center justify-center py-8 text-center">
                <Loader2 className="mb-4 h-6 w-6 animate-spin text-slate-300" />
                <p className="text-sm text-slate-400">
                  Verifying your reset link...
                </p>
              </div>
            ) : (
              <>
                {error && (
                  <div className="mb-5 flex gap-3 rounded-xl border border-red-900/50 bg-red-950/30 p-4 text-sm text-red-300">
                    <AlertCircle className="mt-0.5 h-5 w-5 shrink-0" />
                    <p>{error}</p>
                  </div>
                )}

                {success && (
                  <div className="mb-5 flex gap-3 rounded-xl border border-emerald-900/50 bg-emerald-950/30 p-4 text-sm text-emerald-300">
                    <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0" />
                    <p>{success}</p>
                  </div>
                )}

                <form onSubmit={handleReset} className="space-y-5">
                  <div>
                    <label
                      htmlFor="password"
                      className="mb-2 block text-sm font-medium text-slate-300"
                    >
                      New password
                    </label>

                    <input
                      id="password"
                      type="password"
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      placeholder="At least 8 characters"
                      required
                      minLength={8}
                      autoComplete="new-password"
                      disabled={Boolean(success)}
                      className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-white focus:ring-2 focus:ring-white/10 disabled:cursor-not-allowed disabled:opacity-60"
                    />
                  </div>

                  <div>
                    <label
                      htmlFor="confirmPassword"
                      className="mb-2 block text-sm font-medium text-slate-300"
                    >
                      Confirm new password
                    </label>

                    <input
                      id="confirmPassword"
                      type="password"
                      value={confirmPassword}
                      onChange={(event) =>
                        setConfirmPassword(event.target.value)
                      }
                      placeholder="Re-enter your new password"
                      required
                      minLength={8}
                      autoComplete="new-password"
                      disabled={Boolean(success)}
                      className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-white focus:ring-2 focus:ring-white/10 disabled:cursor-not-allowed disabled:opacity-60"
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={loading || Boolean(success) || Boolean(error)}
                    className="flex w-full items-center justify-center gap-2 rounded-xl bg-white px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-slate-200 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {loading ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Updating password...
                      </>
                    ) : (
                      "Update password"
                    )}
                  </button>
                </form>

                <div className="mt-6 border-t border-slate-800 pt-6 text-center">
                  <Link
                    href="/login"
                    className="text-sm font-medium text-slate-300 transition hover:text-white"
                  >
                    ← Back to sign in
                  </Link>
                </div>
              </>
            )}
          </div>

          <p className="mt-6 text-center text-xs text-slate-600">
            SentinelX Security Intelligence
          </p>
        </div>
      </div>
    </main>
  );
}
