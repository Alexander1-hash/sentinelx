"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, CheckCircle2, Clock3, Loader2, ShieldAlert, ShieldCheck, XCircle } from "lucide-react";

type Action = {
  id: string;
  finding_id: string | null;
  action_type: string;
  status: "pending" | "approved" | "executing" | "completed" | "failed" | "cancelled";
  target: Record<string, unknown>;
  authorization: Record<string, unknown>;
  result: Record<string, unknown>;
  created_at: string;
  executed_at: string | null;
};

const ACTION_LABELS: Record<string, string> = {
  investigate_asset: "Investigate asset",
  review_finding: "Review finding",
  contain_asset: "Contain asset",
  disable_integration: "Disable integration",
  revoke_access: "Revoke access",
  isolate_endpoint: "Isolate endpoint",
  block_indicator: "Block indicator",
};

export default function SecurityActionsPage() {
  const [actions, setActions] = useState<Action[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState("");
  const [message, setMessage] = useState("");
  const [outcomeActionId, setOutcomeActionId] = useState("");
  const [outcomeStatus, setOutcomeStatus] = useState<"completed" | "failed">("completed");
  const [executorType, setExecutorType] = useState("");
  const [executionReference, setExecutionReference] = useState("");
  const [outcomeEvidence, setOutcomeEvidence] = useState("");

  async function loadActions() {
    setLoading(true);
    try {
      const response = await fetch("/api/security/actions", { cache: "no-store" });
      const data = await response.json();

      if (!response.ok) {
        setMessage(data.error ?? "Unable to load security actions.");
        return;
      }

      setActions(data.actions ?? []);
    } catch {
      setMessage("Security actions could not be loaded.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadActions();
  }, []);

  async function recordOutcome(id: string) {
    setBusyId(id);
    setMessage("");

    try {
      const response = await fetch("/api/security/actions/outcome", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          actionId: id,
          status: outcomeStatus,
          executorType,
          executionReference,
          evidence: [
            {
              type: "executor_result",
              source: executorType,
              summary: outcomeEvidence,
              reference: executionReference,
            },
          ],
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setMessage(data.error ?? "Unable to record the execution outcome.");
        return;
      }

      setMessage(data.message ?? "Verified response outcome recorded.");
      setOutcomeActionId("");
      setExecutorType("");
      setExecutionReference("");
      setOutcomeEvidence("");
      await loadActions();
    } catch {
      setMessage("Unable to record the execution outcome.");
    } finally {
      setBusyId("");
    }
  }

  async function review(id: string, status: "approved" | "cancelled") {
    setBusyId(id);
    setMessage("");

    try {
      const response = await fetch("/api/security/actions", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, status }),
      });

      const data = await response.json();

      if (!response.ok) {
        setMessage(data.error ?? "Unable to update the action.");
        return;
      }

      setMessage(data.message ?? "Action updated.");
      await loadActions();
    } catch {
      setMessage("Unable to update the security action.");
    } finally {
      setBusyId("");
    }
  }

  const pending = actions.filter((action) => action.status === "pending");
  const approved = actions.filter((action) => action.status === "approved");
  const completed = actions.filter((action) => action.status === "completed");
  const cancelled = actions.filter((action) => action.status === "cancelled");

  return (
    <main className="min-h-screen bg-[#071018] text-slate-100">
      <header className="border-b border-white/10 bg-[#071018]/95">
        <div className="mx-auto flex max-w-[1100px] items-center justify-between gap-3 px-4 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div>
              <p className="font-semibold text-white">Security Actions</p>
              <p className="text-[11px] text-slate-500">Controlled response center</p>
            </div>
          </div>
          <Link href="/" className="inline-flex items-center gap-2 rounded-xl border border-white/10 px-3 py-2 text-xs text-slate-400 hover:text-white">
            <ArrowLeft className="h-3.5 w-3.5" /> Command Center
          </Link>
        </div>
      </header>

      <div className="mx-auto max-w-[1100px] px-4 py-8 sm:px-6">
        <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">Controlled response</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Decide before SentinelX acts</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
          Security actions are explicit, auditable, and authorization-gated. Approving an action here does not execute an external or destructive action until a provider-specific executor is intentionally connected.
        </p>

        <div className="mt-6 grid gap-3 sm:grid-cols-4">
          <Stat label="Pending review" value={pending.length} />
          <Stat label="Authorized" value={approved.length} />
          <Stat label="Completed" value={completed.length} />
          <Stat label="Cancelled" value={cancelled.length} />
        </div>

        {message && (
          <div className="mt-5 rounded-xl border border-cyan-400/10 bg-cyan-400/[0.03] p-4 text-sm text-cyan-200">
            {message}
          </div>
        )}

        <section className="mt-8 rounded-3xl border border-white/10 bg-white/[0.025] p-5 sm:p-6">
          <div className="flex items-center gap-2">
            <Clock3 className="h-4 w-4 text-amber-300" />
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Action queue</p>
          </div>

          {loading ? (
            <div className="mt-6 flex items-center gap-2 text-sm text-slate-500">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading action history...
            </div>
          ) : actions.length === 0 ? (
            <div className="mt-6 rounded-2xl border border-dashed border-white/10 p-8 text-center">
              <ShieldCheck className="mx-auto h-8 w-8 text-slate-700" />
              <p className="mt-3 text-sm font-medium text-slate-300">No security actions yet</p>
              <p className="mt-2 text-xs leading-5 text-slate-600">
                Recommendations created from Security Brain findings will appear here for explicit review.
              </p>
            </div>
          ) : (
            <div className="mt-5 space-y-3">
              {actions.map((action) => (
                <div key={action.id} className="rounded-2xl border border-white/10 bg-black/10 p-4">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div>
                      <p className="text-sm font-medium text-white">
                        {ACTION_LABELS[action.action_type] ?? action.action_type.replaceAll("_", " ")}
                      </p>
                      <p className="mt-1 text-[10px] text-slate-600">
                        Requested {new Date(action.created_at).toLocaleString()}
                      </p>
                    </div>
                    <StatusBadge status={action.status} />
                  </div>

                  <div className="mt-4 rounded-xl border border-white/10 bg-white/[0.02] p-3">
                    <p className="text-[9px] uppercase tracking-wider text-slate-600">Target context</p>
                    <p className="mt-1 break-words text-[11px] text-slate-400">
                      {Object.keys(action.target).length
                        ? JSON.stringify(action.target)
                        : "No target context supplied."}
                    </p>
                  </div>

                  {typeof action.result.response_plan === "object" && action.result.response_plan !== null ? (
                    <div className="mt-3 rounded-xl border border-orange-400/10 bg-orange-400/[0.025] p-3">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-orange-200">Response plan</p>
                      <p className="mt-2 text-[10px] leading-5 text-slate-400">
                        {String((action.result.response_plan as Record<string, unknown>).objective ?? "Evidence-grounded response recommendation.")}
                      </p>
                      <div className="mt-2 flex flex-wrap gap-2 text-[9px] text-slate-500">
                        <span>Severity: {String((action.result.response_plan as Record<string, unknown>).severity ?? "unknown")}</span>
                        <span>Action: {ACTION_LABELS[action.action_type] ?? action.action_type.replaceAll("_", " ")}</span>
                      </div>

                      {Array.isArray((action.result.response_plan as Record<string, unknown>).historicalResponseCycleContext) && (
                        <div className="mt-3 rounded-lg border border-white/10 bg-black/10 p-3">
                          <p className="text-[9px] font-semibold uppercase tracking-wider text-orange-200">Previous response history</p>
                          <p className="mt-1 text-[9px] leading-4 text-slate-600">
                            Prior operator decisions and explicit executor outcomes are context only; they do not establish the current security state.
                          </p>
                          <div className="mt-2 space-y-2">
                            {((action.result.response_plan as Record<string, unknown>).historicalResponseCycleContext as Array<Record<string, unknown>>).slice(0, 4).map((cycle, index) => (
                              <div key={String(cycle.memoryId ?? index)} className="rounded-lg border border-white/10 p-2">
                                <div className="flex flex-wrap items-center justify-between gap-2">
                                  <span className="text-[9px] font-medium text-slate-300">{String(cycle.title ?? "Recorded response event")}</span>
                                  <span className="text-[8px] uppercase tracking-wider text-slate-600">{String(cycle.state ?? "recorded")}</span>
                                </div>
                                <p className="mt-1 text-[8px] leading-4 text-slate-600">
                                  {String(cycle.actionType ?? action.action_type).replaceAll("_", " ")}
                                  {cycle.executorType ? ` · executor: ${String(cycle.executorType)}` : ""}
                                  {cycle.evidenceCount !== undefined ? ` · ${String(cycle.evidenceCount)} evidence` : ""}
                                </p>
                                {cycle.executionReference && (
                                  <p className="mt-1 break-words text-[8px] text-slate-700">Reference: {String(cycle.executionReference)}</p>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {Array.isArray((action.result.response_plan as Record<string, unknown>).historicalResponseCycleContext) &&
                        ((action.result.response_plan as Record<string, unknown>).historicalResponseCycleContext as unknown[]).length === 0 && (
                          <p className="mt-3 text-[9px] text-slate-600">No linked historical response outcome was found for this finding or asset.</p>
                        )}
                    </div>
                  ) : null}

                  <p className="mt-3 text-[10px] leading-5 text-slate-600">
                    {String(action.result.message ?? "Awaiting operator decision.")}
                  </p>

                  {action.status === "approved" && (
                    <div className="mt-4 rounded-xl border border-cyan-400/10 bg-cyan-400/[0.025] p-3">
                      <div className="flex items-center justify-between gap-2">
                        <div>
                          <p className="text-[9px] font-semibold uppercase tracking-wider text-cyan-200">Record executor outcome</p>
                          <p className="mt-1 text-[9px] leading-4 text-slate-600">
                            Record only an explicit result from the connected or manually operated executor. This does not trigger the external action.
                          </p>
                        </div>
                        <span className="rounded-full bg-cyan-400/10 px-2 py-1 text-[8px] uppercase tracking-wider text-cyan-200">Approved</span>
                      </div>

                      {outcomeActionId === action.id ? (
                        <div className="mt-3 space-y-2">
                          <select
                            value={outcomeStatus}
                            onChange={(event) => setOutcomeStatus(event.target.value as "completed" | "failed")}
                            className="w-full rounded-lg border border-white/10 bg-[#071018] px-3 py-2 text-[10px] text-white"
                          >
                            <option value="completed">Completed</option>
                            <option value="failed">Failed</option>
                          </select>
                          <input
                            value={executorType}
                            onChange={(event) => setExecutorType(event.target.value)}
                            placeholder="Executor type (e.g. manual_operator)"
                            className="w-full rounded-lg border border-white/10 bg-[#071018] px-3 py-2 text-[10px] text-white placeholder:text-slate-700"
                          />
                          <input
                            value={executionReference}
                            onChange={(event) => setExecutionReference(event.target.value)}
                            placeholder="Execution reference / ticket / run ID"
                            className="w-full rounded-lg border border-white/10 bg-[#071018] px-3 py-2 text-[10px] text-white placeholder:text-slate-700"
                          />
                          <textarea
                            value={outcomeEvidence}
                            onChange={(event) => setOutcomeEvidence(event.target.value)}
                            placeholder="What explicit evidence did the executor return?"
                            rows={3}
                            className="w-full resize-none rounded-lg border border-white/10 bg-[#071018] px-3 py-2 text-[10px] text-white placeholder:text-slate-700"
                          />
                          <div className="grid grid-cols-2 gap-2">
                            <button
                              disabled={busyId === action.id || !executorType.trim() || !executionReference.trim() || !outcomeEvidence.trim()}
                              onClick={() => void recordOutcome(action.id)}
                              className="rounded-lg bg-cyan-300 px-3 py-2 text-[10px] font-semibold text-slate-950 disabled:opacity-50"
                            >
                              {busyId === action.id ? "Recording..." : "Record outcome"}
                            </button>
                            <button
                              disabled={busyId === action.id}
                              onClick={() => setOutcomeActionId("")}
                              className="rounded-lg border border-white/10 px-3 py-2 text-[10px] text-slate-400"
                            >
                              Close
                            </button>
                          </div>
                        </div>
                      ) : (
                        <button
                          disabled={busyId === action.id}
                          onClick={() => {
                            setOutcomeActionId(action.id);
                            setOutcomeStatus("completed");
                          }}
                          className="mt-3 w-full rounded-lg border border-cyan-400/20 bg-cyan-400/10 px-3 py-2 text-[10px] font-semibold text-cyan-200 disabled:opacity-50"
                        >
                          Record explicit outcome
                        </button>
                      )}
                    </div>
                  )}

                  {action.status === "pending" && (
                    <div className="mt-4 grid grid-cols-2 gap-2">
                      <button
                        disabled={busyId === action.id}
                        onClick={() => void review(action.id, "approved")}
                        className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-300 px-3 py-3 text-[10px] font-semibold text-slate-950 disabled:opacity-50"
                      >
                        {busyId === action.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <CheckCircle2 className="h-3.5 w-3.5" />}
                        Authorize
                      </button>
                      <button
                        disabled={busyId === action.id}
                        onClick={() => void review(action.id, "cancelled")}
                        className="inline-flex items-center justify-center gap-2 rounded-xl border border-white/10 px-3 py-3 text-[10px] font-semibold text-slate-400 disabled:opacity-50"
                      >
                        <XCircle className="h-3.5 w-3.5" /> Cancel
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="mt-5 rounded-2xl border border-orange-400/10 bg-orange-400/[0.025] p-4">
          <p className="text-xs font-semibold text-orange-200">Safety boundary</p>
          <p className="mt-2 text-[11px] leading-5 text-slate-500">
            SentinelX does not silently isolate devices, revoke credentials, disable services, or block indicators. Those capabilities require an explicitly connected provider executor and an authorization policy.
          </p>
        </section>
      </div>

      <footer className="mx-auto max-w-[1100px] px-4 pb-8 text-[10px] text-slate-600 sm:px-6">
        <div className="flex items-center gap-2 border-t border-white/10 pt-6">
          <ShieldCheck className="h-3.5 w-3.5" /> Authorized systems only · Controlled response
        </div>
      </footer>
    </main>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
      <p className="text-[10px] uppercase tracking-wider text-slate-500">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-white">{value}</p>
    </div>
  );
}

function StatusBadge({ status }: { status: Action["status"] }) {
  const tone =
    status === "pending"
      ? "bg-amber-400/10 text-amber-200"
      : status === "approved"
        ? "bg-cyan-400/10 text-cyan-200"
        : status === "completed"
          ? "bg-emerald-400/10 text-emerald-200"
          : status === "cancelled"
            ? "bg-white/5 text-slate-500"
            : "bg-rose-400/10 text-rose-200";

  return (
    <span className={"w-fit rounded-full px-2 py-1 text-[9px] uppercase tracking-wider " + tone}>
      {status}
    </span>
  );
}
