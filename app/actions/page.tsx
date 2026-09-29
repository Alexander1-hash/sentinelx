"use client";

import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
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
  target_context?: {
    resourceName?: string;
    resourceType?: string;
    stableIdentifier?: string;
    ownership?: string;
    source?: string;
    evidence?: string;
    boundary?: string;
    unknowns?: string[];
  };
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

function SecurityActionsPageContent() {
  const searchParams = useSearchParams();
  const linkedFindingId = searchParams.get("findingId") ?? "";
  const linkedActionId = searchParams.get("actionId") ?? "";
  const [createType, setCreateType] = useState("review_finding");
  const [creating, setCreating] = useState(false);
  const [actions, setActions] = useState<Action[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState("");
  const [message, setMessage] = useState("");
  const [outcomeActionId, setOutcomeActionId] = useState("");
  const [outcomeStatus, setOutcomeStatus] = useState<"completed" | "failed">("completed");
  const [executorType, setExecutorType] = useState("");
  const [executionReference, setExecutionReference] = useState("");
  const [outcomeEvidence, setOutcomeEvidence] = useState("");
  const [verificationActionId, setVerificationActionId] = useState("");
  const [verificationState, setVerificationState] = useState<"resolved" | "persisting" | "returned" | "unknown">("resolved");
  const [verificationSummary, setVerificationSummary] = useState("");
  const [verificationEvidence, setVerificationEvidence] = useState("");
  const [verificationReference, setVerificationReference] = useState("");
  const [readiness, setReadiness] = useState<Record<string, {
    readiness?: string;
    connectedIntegrations?: Array<{ displayName: string; provider: string; integrationType: string; providerExecutionReady?: boolean }>;
    executorReady?: boolean;
    boundary?: string;
    preview?: { steps?: string[]; requiredIntegrationTypes?: string[] };
  }>>({});
  const [readinessLoading, setReadinessLoading] = useState(true);
  const [focusedDecision, setFocusedDecision] = useState<{ confidence?: string; contradictions?: string[]; nextEvidenceNeeded?: string[]; latestVerification?: { state: string; occurredAt: string } | null; responseLearning?: Array<{ occurred_at: string; action_type: string | null; state: string; summary: string }>; } | null>(null);

  const [focusedActionId, setFocusedActionId] = useState(linkedActionId);

  async function createAction() {
    if (!linkedFindingId) return;
    setCreating(true);
    setMessage("");
    try {
      const response = await fetch("/api/security/actions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          actionType: createType,
          findingId: linkedFindingId,
          reason: "Created from Security Analyst investigation context.",
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        setMessage(data.error ?? "Unable to create the security action.");
        return;
      }
      setMessage(data.message ?? "Security action created for operator review.");
      await loadActions();
    } catch {
      setMessage("Unable to create the security action.");
    } finally {
      setCreating(false);
    }
  }

  async function loadActions() {
    setLoading(true);
    try {
      const response = await fetch("/api/security/actions", { cache: "no-store" });
      const data = await response.json();

      if (!response.ok) {
        setMessage(data.error ?? "Unable to load security actions.");
        return;
      }

      const nextActions = data.actions ?? [];
      setActions(nextActions);
      if (linkedActionId && nextActions.some((action: Action) => action.id === linkedActionId)) {
        setFocusedActionId(linkedActionId);
      }
    } catch {
      setMessage("Security actions could not be loaded.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadActions();
  }, [linkedActionId]);

  useEffect(() => {
    if (!focusedActionId || loading) return;
    const timer = window.setTimeout(() => {
      document.getElementById(`action-${focusedActionId}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
    }, 150);
    return () => window.clearTimeout(timer);
  }, [focusedActionId, loading, actions.length]);

  useEffect(() => {
    async function loadReadiness() {
      try {
        const response = await fetch(`/api/security/actions/readiness${linkedFindingId ? `?findingId=${encodeURIComponent(linkedFindingId)}` : ""}`, { cache: "no-store" });
        const data = await response.json();
        if (!response.ok) return;
        const adaptive = data.adaptiveInvestigationContext;
        setFocusedDecision(adaptive ? { confidence: adaptive.confidence, contradictions: adaptive.contradictions ?? [], nextEvidenceNeeded: adaptive.nextEvidenceNeeded ?? [], latestVerification: adaptive.historicalState?.latestVerification ?? null, responseLearning: adaptive.responseLearning ?? [] } : null);

        const map: typeof readiness = {};
        for (const item of data.requirements ?? []) {
          map[item.actionType] = {
            readiness: item.readiness,
            connectedIntegrations: [],
            executorReady: item.executorReady,
            boundary: item.boundary,
            preview: item.preview,
          };
        }
        setReadiness(map);
      } finally {
        setReadinessLoading(false);
      }
    }

    void loadReadiness();
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

  async function executeProvider(id: string) {
    setBusyId(id);
    setMessage("");

    try {
      const response = await fetch("/api/security/actions/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ actionId: id }),
      });
      const data = await response.json();

      if (!response.ok) {
        setMessage(data.error ?? "Automated provider execution could not be completed.");
        return;
      }

      setMessage(
        data.message ??
          `Provider execution completed. Reference: ${data.executionReference ?? "recorded"}`,
      );
      await loadActions();
    } catch {
      setMessage("Automated provider execution could not be completed.");
    } finally {
      setBusyId("");
    }
  }

  async function recordVerification(id: string) {
    setBusyId(id);
    setMessage("");

    try {
      const response = await fetch("/api/security/actions/verification", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          actionId: id,
          state: verificationState,
          summary: verificationSummary,
          evidence: [
            {
              type: "post_response_verification",
              source: "operator_verification",
              summary: verificationEvidence,
              reference: verificationReference,
            },
          ],
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setMessage(data.error ?? "Unable to record post-response verification.");
        return;
      }

      setMessage(data.message ?? "Post-response verification recorded.");
      setVerificationActionId("");
      setVerificationSummary("");
      setVerificationEvidence("");
      setVerificationReference("");
      await loadActions();
    } catch {
      setMessage("Unable to record post-response verification.");
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
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Decide before Trinorin acts</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
          Security actions are explicit, auditable, and authorization-gated. Approving an action here does not execute an external or destructive action until a provider-specific executor is intentionally connected.
        </p>

        <div className="mt-6 grid gap-3 sm:grid-cols-4">
          <Stat label="Pending review" value={pending.length} />
          <Stat label="Authorized" value={approved.length} />
          <Stat label="Completed" value={completed.length} />
          <Stat label="Cancelled" value={cancelled.length} />
        </div>

        {linkedFindingId && (
          <section className="mt-6 rounded-3xl border border-cyan-400/10 bg-cyan-400/[0.025] p-5 sm:p-6">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <p className="text-xs font-semibold uppercase tracking-wider text-cyan-200">Finding in focus</p>
                <p className="mt-1 text-sm font-medium text-white">This decision workspace is scoped to the investigation you just reviewed.</p>
                <p className="mt-2 break-all text-[9px] text-slate-600">Finding ID: {linkedFindingId}</p>
              </div>
              <Link href={"/analyst?findingId="+encodeURIComponent(linkedFindingId)} className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl border border-white/10 px-3 py-2 text-[10px] font-semibold text-slate-300 hover:bg-white/5">
                Return to investigation
              </Link>
            </div>
            <div className="mt-4 grid gap-2 sm:grid-cols-3">
              <div className="rounded-xl border border-white/10 bg-black/10 p-3">
                <p className="text-[8px] uppercase tracking-wider text-slate-600">Decision scope</p>
                <p className="mt-1 text-[10px] text-slate-300">Evidence-backed finding</p>
              </div>
              <div className="rounded-xl border border-white/10 bg-black/10 p-3">
                <p className="text-[8px] uppercase tracking-wider text-slate-600">Authorization</p>
                <p className="mt-1 text-[10px] text-slate-300">Explicit operator approval</p>
              </div>
              <div className="rounded-xl border border-white/10 bg-black/10 p-3">
                <p className="text-[8px] uppercase tracking-wider text-slate-600">Execution</p>
                <p className="mt-1 text-[10px] text-slate-300">Provider executor required</p>
              </div>
            </div>
            <p className="mt-3 text-[9px] leading-4 text-slate-600">Trinorin does not silently execute, approve, or infer remediation. Current evidence and explicit authorization remain the decision boundary.</p>
            {linkedFindingId && (
              <div className="mt-4 rounded-2xl border border-violet-400/10 bg-violet-400/[0.025] p-4">
                <div className="flex items-center justify-between gap-2">
                  <p className="text-[9px] font-semibold uppercase tracking-wider text-violet-200">Adaptive decision context</p>
                  <span className="text-[8px] uppercase tracking-wider text-amber-200">Human decision required</span>
                </div>
                <div className="mt-3 grid gap-2 sm:grid-cols-2">
                  <div className="rounded-lg border border-white/10 bg-black/10 p-2">
                    <p className="text-[8px] uppercase tracking-wider text-slate-600">Evidence sufficiency</p>
                    <p className="mt-1 text-[10px] font-medium text-slate-300">{focusedDecision?.confidence ?? "loading"} adaptive confidence</p>
                  </div>
                  <div className="rounded-lg border border-white/10 bg-black/10 p-2">
                    <p className="text-[8px] uppercase tracking-wider text-slate-600">Authorization</p>
                    <p className="mt-1 text-[10px] font-medium text-slate-300">Not authorized</p>
                  </div>
                </div>
                {focusedDecision?.latestVerification && (
                  <p className="mt-3 text-[9px] text-slate-500">Latest verification: {focusedDecision.latestVerification.state}</p>
                )}
                {focusedDecision?.contradictions?.length ? (
                  <div className="mt-3 rounded-lg border border-amber-400/10 bg-amber-400/[0.02] p-2">
                    <p className="text-[8px] uppercase tracking-wider text-amber-200/70">Reconcile before decision</p>
                    <p className="mt-1 text-[9px] leading-4 text-slate-500">{focusedDecision.contradictions[0]}</p>
                  </div>
                ) : focusedDecision?.nextEvidenceNeeded?.length ? (
                  <div className="mt-3 rounded-lg border border-cyan-400/10 bg-cyan-400/[0.02] p-2">
                    <p className="text-[8px] uppercase tracking-wider text-cyan-200/70">Next evidence needed</p>
                    <p className="mt-1 text-[9px] leading-4 text-slate-500">{focusedDecision.nextEvidenceNeeded[0]}</p>
                  </div>
                ) : null}
                {focusedDecision?.responseLearning?.length ? (
                  <p className="mt-3 text-[9px] leading-4 text-slate-500">Response learning records available: {focusedDecision.responseLearning.length}</p>
                ) : null}
              </div>
            )}
            <div className="mt-4 flex flex-col gap-2 sm:flex-row">
              <select
                value={createType}
                onChange={(event) => setCreateType(event.target.value)}
                className="rounded-xl border border-white/10 bg-[#071018] px-3 py-3 text-xs text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/30"
              >
                {Object.entries(ACTION_LABELS).map(([value, label]) => (
                  <option key={value} value={value}>{label}</option>
                ))}
              </select>
              <button
                type="button"
                disabled={creating}
                onClick={() => void createAction()}
                className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-300 px-4 py-3 text-xs font-semibold text-slate-950 disabled:opacity-50"
              >
                {creating ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldAlert className="h-4 w-4" />}
                {creating ? "Creating…" : "Create pending action"}
              </button>
            </div>
            <p className="mt-3 text-[9px] leading-4 text-slate-600">
              Start with the least-committal option when you only want to preserve the investigation for review. Mutating actions still require a deterministic target, provider readiness, and explicit authorization.
            </p>
          </section>
        )}

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
                <div
                  key={action.id}
                  id={`action-${action.id}`}
                  className={`rounded-2xl border p-4 transition ${
                    focusedActionId === action.id
                      ? "border-cyan-400/30 bg-cyan-400/[0.04] ring-1 ring-cyan-400/20"
                      : "border-white/10 bg-black/10"
                  }`}
                >
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

                  <div className="mt-4 rounded-xl border border-cyan-400/10 bg-cyan-400/[0.025] p-3">
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-cyan-200">Target intelligence</p>
                      <span className="text-[8px] uppercase tracking-wider text-slate-600">
                        {action.target_context?.source ?? "operator supplied"}
                      </span>
                    </div>
                    <p className="mt-2 text-[11px] font-medium text-white">
                      {action.target_context?.resourceName ?? "Target identity not resolved"}
                    </p>
                    <p className="mt-1 text-[9px] text-slate-500">
                      {action.target_context?.resourceType
                        ? action.target_context.resourceType.replaceAll("_", " ")
                        : "Resource type not verified"}
                    </p>
                    <div className="mt-3 grid gap-2 sm:grid-cols-2">
                      <div className="rounded-lg border border-white/10 bg-black/10 p-2">
                        <p className="text-[8px] uppercase tracking-wider text-slate-600">Stable identifier</p>
                        <p className="mt-1 break-all text-[9px] text-slate-400">{action.target_context?.stableIdentifier ?? "Not verified"}</p>
                      </div>
                      <div className="rounded-lg border border-white/10 bg-black/10 p-2">
                        <p className="text-[8px] uppercase tracking-wider text-slate-600">Ownership</p>
                        <p className="mt-1 text-[9px] text-slate-400">{action.target_context?.ownership ?? "Not verified"}</p>
                      </div>
                    </div>
                    {action.target_context?.unknowns?.length ? (
                      <div className="mt-2 rounded-lg border border-amber-400/10 bg-amber-400/[0.02] p-2">
                        <p className="text-[8px] uppercase tracking-wider text-amber-200/70">Known unknowns</p>
                        <ul className="mt-1 space-y-1">
                          {action.target_context.unknowns.map((item) => (
                            <li key={item} className="text-[8px] leading-4 text-slate-600">• {item}</li>
                          ))}
                        </ul>
                      </div>
                    ) : null}
                    {action.target_context?.evidence && (
                      <p className="mt-2 text-[9px] leading-4 text-slate-500">
                        Why this target: {action.target_context.evidence}
                      </p>
                    )}
                    <p className="mt-2 break-words text-[8px] leading-4 text-slate-700">
                      {Object.keys(action.target).length
                        ? JSON.stringify(action.target)
                        : "No stable target identifier supplied."}
                    </p>
                    <p className="mt-2 text-[8px] leading-4 text-amber-200/70">
                      {action.target_context?.boundary ?? "Target identity must be verified before any external execution."}
                    </p>
                  </div>

                  <ResponseLifecycle action={action} />

                  {action.status === "pending" && (
                    <div className="mt-3 rounded-xl border border-cyan-400/10 bg-cyan-400/[0.02] p-3">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-[9px] font-semibold uppercase tracking-wider text-cyan-200">Decision readiness</p>
                        <span className="text-[8px] uppercase tracking-wider text-slate-600">Before authorization</span>
                      </div>
                      <div className="mt-3 grid gap-2 sm:grid-cols-3">
                        <div className="rounded-lg border border-white/10 bg-black/10 p-2">
                          <p className="text-[8px] uppercase tracking-wider text-slate-600">Current target</p>
                          <p className="mt-1 text-[9px] font-medium text-slate-300">
                            {action.target_context?.resourceName ?? "Not resolved"}
                          </p>
                          <p className="mt-1 text-[8px] leading-4 text-slate-600">
                            {action.target_context?.stableIdentifier ? "Stable identifier available." : "Stable identifier still needs verification."}
                          </p>
                        </div>
                        <div className="rounded-lg border border-white/10 bg-black/10 p-2">
                          <p className="text-[8px] uppercase tracking-wider text-slate-600">Execution path</p>
                          <p className="mt-1 text-[9px] font-medium text-slate-300">
                            {action.action_type === "review_finding"
                              ? "Review-only"
                              : readinessLoading
                                ? "Checking readiness…"
                                : readiness[action.action_type]?.executorReady
                                  ? "Executor path available"
                                  : "No provider executor configured"}
                          </p>
                          <p className="mt-1 text-[8px] leading-4 text-slate-600">Authorization remains separate from external execution.</p>
                        </div>
                        <div className="rounded-lg border border-white/10 bg-black/10 p-2">
                          <p className="text-[8px] uppercase tracking-wider text-slate-600">Historical context</p>
                          <p className="mt-1 text-[9px] font-medium text-slate-300">
                            {Array.isArray((action.result as Record<string, unknown>).historical_response_context)
                              ? `${((action.result as Record<string, unknown>).historical_response_context as unknown[]).length} prior outcome record${((action.result as Record<string, unknown>).historical_response_context as unknown[]).length === 1 ? "" : "s"}`
                              : "No correlated outcome history"}
                          </p>
                          <p className="mt-1 text-[8px] leading-4 text-slate-600">History is context only; current evidence remains authoritative.</p>
                        </div>
                      </div>
                      <p className="mt-3 text-[8px] leading-4 text-cyan-100/50">
                        Trinorin presents the evidence and known boundaries for an operator decision. It does not score or rank response choices, and historical outcomes do not prove current effectiveness.
                      </p>
                    </div>
                  )}

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
                                {cycle.executionReference !== undefined && cycle.executionReference !== null && (
                                  <p className="mt-1 break-words text-[8px] text-slate-700">Reference: {String(cycle.executionReference)}</p>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {Array.isArray((action.result as Record<string, unknown>).historical_pattern_context) && (
                        <div className="mt-3 rounded-lg border border-cyan-400/10 bg-cyan-400/[0.02] p-3">
                          <p className="text-[9px] font-semibold uppercase tracking-wider text-cyan-200">Finding-specific learned context</p>
                          <p className="mt-1 text-[9px] leading-4 text-slate-600">
                            Security patterns are deterministic signals from recorded memory. They are shown here because they relate to this finding, its affected asset, or its finding type.
                          </p>
                          <div className="mt-2 space-y-2">
                            {((action.result as Record<string, unknown>).historical_pattern_context as Array<Record<string, unknown>>).slice(0, 4).map((pattern, index) => (
                              <div key={String(pattern.id ?? index)} className="rounded-lg border border-white/10 p-2">
                                <div className="flex flex-wrap items-center justify-between gap-2">
                                  <span className="text-[9px] font-medium text-slate-300">{String(pattern.title ?? "Recorded security pattern")}</span>
                                  <div className="flex flex-wrap items-center gap-1.5">
                                    {pattern.actionType ? (
                                      <span className="rounded-full bg-violet-400/10 px-2 py-1 text-[8px] uppercase tracking-wider text-violet-200">
                                        {String(pattern.actionType).replaceAll("_", " ")}
                                      </span>
                                    ) : null}
                                    {pattern.outcomeState ? (
                                      <span className="rounded-full bg-amber-400/10 px-2 py-1 text-[8px] uppercase tracking-wider text-amber-200">
                                        {String(pattern.outcomeState).replaceAll("_", " ")}
                                      </span>
                                    ) : null}
                                    <span className="rounded-full bg-cyan-400/10 px-2 py-1 text-[8px] uppercase tracking-wider text-cyan-200">
                                      {String(pattern.confidence ?? "recorded")}
                                    </span>
                                  </div>
                                </div>
                                <p className="mt-1 text-[8px] leading-4 text-slate-600">
                                  {String(pattern.detail ?? "Recorded historical security pattern.")} · {Array.isArray(pattern.memoryIds) ? pattern.memoryIds.length : 0} linked memory record{Array.isArray(pattern.memoryIds) && pattern.memoryIds.length === 1 ? "" : "s"} · last observed {new Date(String(pattern.lastObserved)).toLocaleString()}
                                </p>
                                <p className="mt-1 text-[8px] leading-4 text-cyan-100/40">{String(pattern.boundary ?? "Pattern context does not establish current security state.")}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {Array.isArray((action.result as Record<string, unknown>).historical_response_context) && (
                        <div className="mt-3 rounded-lg border border-violet-400/10 bg-violet-400/[0.02] p-3">
                          <p className="text-[9px] font-semibold uppercase tracking-wider text-violet-200">Decision context from prior responses</p>
                          <p className="mt-1 text-[9px] leading-4 text-slate-600">
                            Historical outcomes are shown before authorization so the operator can consider relevant context. They do not establish that a response will work now.
                          </p>
                          <div className="mt-2 space-y-2">
                            {((action.result as Record<string, unknown>).historical_response_context as Array<Record<string, unknown>>).slice(0, 4).map((item, index) => (
                              <div key={String(item.memoryId ?? index)} className="rounded-lg border border-white/10 p-2">
                                <div className="flex flex-wrap items-center justify-between gap-2">
                                  <span className="text-[9px] font-medium text-slate-300">{String(item.actionType ?? "Recorded response").replaceAll("_", " ")}</span>
                                  <span className="rounded-full bg-violet-400/10 px-2 py-1 text-[8px] uppercase tracking-wider text-violet-200">
                                    {String(item.matchContext ?? "historical")}
                                  </span>
                                </div>
                                <p className="mt-1 text-[8px] leading-4 text-slate-600">
                                  {String(item.state ?? "recorded")} · {String(item.evidenceCount ?? 0)} evidence record{String(item.evidenceCount ?? 0) === "1" ? "" : "s"} · {new Date(String(item.occurredAt)).toLocaleString()}
                                </p>
                                <p className="mt-1 text-[8px] leading-4 text-slate-600">{String(item.summary ?? item.title ?? "Recorded response outcome.")}</p>
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

                  {(action.status === "completed" || action.status === "failed") && (
                    <div className="mt-4 rounded-xl border border-emerald-400/10 bg-emerald-400/[0.025] p-3">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-[9px] font-semibold uppercase tracking-wider text-emerald-200">Post-response verification</p>
                        <span className="text-[8px] uppercase tracking-wider text-slate-600">Explicit evidence required</span>
                      </div>
                      <p className="mt-1 text-[9px] leading-4 text-slate-500">
                        Execution outcome is not remediation proof. Record what the current security evidence actually shows after the response.
                      </p>
                      {verificationActionId === action.id ? (
                        <div className="mt-3 space-y-2">
                          <div className="grid gap-2 sm:grid-cols-3">
                            <select
                              value={verificationState}
                              onChange={(event) => setVerificationState(event.target.value as typeof verificationState)}
                              className="rounded-lg border border-white/10 bg-[#071018] px-2 py-2 text-[10px] text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-300/30"
                            >
                              <option value="resolved">Resolved</option>
                              <option value="persisting">Persisting</option>
                              <option value="returned">Returned</option>
                              <option value="unknown">Unknown</option>
                            </select>
                            <input
                              value={verificationReference}
                              onChange={(event) => setVerificationReference(event.target.value)}
                              placeholder="Evidence reference"
                              className="rounded-lg border border-white/10 bg-[#071018] px-2 py-2 text-[10px] text-white placeholder:text-slate-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-300/30"
                            />
                            <Link
                              href={action.finding_id ? "/analyst?findingId=" + encodeURIComponent(action.finding_id) : "/analyst"}
                              className="inline-flex items-center justify-center rounded-lg border border-white/10 px-2 py-2 text-[10px] text-slate-400 hover:text-white"
                            >
                              Open current evidence
                            </Link>
                          </div>
                          <textarea
                            value={verificationSummary}
                            onChange={(event) => setVerificationSummary(event.target.value)}
                            placeholder="Verification summary: what does the current security state show?"
                            rows={2}
                            className="w-full rounded-lg border border-white/10 bg-[#071018] px-2 py-2 text-[10px] text-white placeholder:text-slate-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-300/30"
                          />
                          <textarea
                            value={verificationEvidence}
                            onChange={(event) => setVerificationEvidence(event.target.value)}
                            placeholder="Explicit evidence observed after the response"
                            rows={2}
                            className="w-full rounded-lg border border-white/10 bg-[#071018] px-2 py-2 text-[10px] text-white placeholder:text-slate-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-300/30"
                          />
                          <div className="grid grid-cols-2 gap-2">
                            <button
                              type="button"
                              disabled={busyId === action.id || !verificationSummary.trim() || !verificationEvidence.trim()}
                              onClick={() => void recordVerification(action.id)}
                              className="rounded-lg bg-emerald-300 px-3 py-2 text-[10px] font-semibold text-slate-950 disabled:opacity-50"
                            >
                              {busyId === action.id ? "Recording..." : "Record verification"}
                            </button>
                            <button
                              type="button"
                              disabled={busyId === action.id}
                              onClick={() => setVerificationActionId("")}
                              className="rounded-lg border border-white/10 px-3 py-2 text-[10px] text-slate-400"
                            >
                              Close
                            </button>
                          </div>
                        </div>
                      ) : (
                        <button
                          type="button"
                          disabled={busyId === action.id}
                          onClick={() => {
                            setVerificationActionId(action.id);
                            setVerificationState("resolved");
                          }}
                          className="mt-3 inline-flex items-center gap-2 rounded-lg border border-emerald-400/20 bg-emerald-400/10 px-3 py-2 text-[10px] font-semibold text-emerald-200 disabled:opacity-50"
                        >
                          <ShieldCheck className="h-3.5 w-3.5" /> Record explicit verification
                        </button>
                      )}
                      <p className="mt-2 text-[8px] leading-4 text-slate-600">
                        Resolution is never inferred from missing telemetry. Unknown remains unknown until explicit evidence supports another state.
                      </p>
                    </div>
                  )}

                  {action.status === "approved" && (
                    <div className="mt-3 rounded-xl border border-amber-400/10 bg-amber-400/[0.025] p-3">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-amber-200">Executor readiness</p>
                      <p className="mt-1 text-[9px] leading-4 text-slate-500">
                        {readinessLoading
                          ? "Checking configured executor readiness..."
                          : readiness[action.action_type]?.executorReady
                            ? "A provider-backed execution path is configured. The action remains blocked until explicit operator authorization and target validation are satisfied."
                            : "No provider-backed execution endpoint is configured for this action. Approval alone does not execute it."}
                      </p>
                      {!readinessLoading &&
                        readiness[action.action_type]?.executorReady &&
                        ["contain_asset", "disable_integration", "revoke_access", "isolate_endpoint", "block_indicator"].includes(action.action_type) && (
                          <button
                            type="button"
                            disabled={busyId === action.id}
                            onClick={() => void executeProvider(action.id)}
                            className="mt-3 inline-flex items-center gap-2 rounded-lg border border-emerald-400/20 bg-emerald-400/10 px-3 py-2 text-[10px] font-semibold text-emerald-200 transition hover:bg-emerald-400/15 disabled:opacity-50"
                          >
                            {busyId === action.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                            Execute through provider
                          </button>
                        )}
                      <p className="mt-2 text-[8px] leading-4 text-slate-600">
                        {readiness[action.action_type]?.boundary ?? "Executor readiness is separate from authorization and telemetry connectivity."}
                      </p>
                      {readiness[action.action_type]?.preview?.steps?.length ? (
                        <div className="mt-3 rounded-lg border border-white/10 bg-black/10 p-3">
                          <p className="text-[8px] font-semibold uppercase tracking-wider text-slate-500">Execution preview</p>
                          <ol className="mt-2 space-y-1.5">
                            {readiness[action.action_type]?.preview?.steps?.map((step, index) => (
                              <li key={step} className="text-[8px] leading-4 text-slate-600">
                                {index + 1}. {step}
                              </li>
                            ))}
                          </ol>
                          <p className="mt-2 text-[8px] leading-4 text-slate-700">Preview only. No provider API is called from this plan.</p>
                        </div>
                      ) : null}
                    </div>
                  )}

                  {action.status === "approved" && (
                    <div className="mt-4 rounded-xl border border-cyan-400/10 bg-cyan-400/[0.025] p-3">
                      <div className="flex items-center justify-between gap-2">
                        <div>
                          <p className="text-[9px] font-semibold uppercase tracking-wider text-cyan-200">Record executor outcome</p>
                          <p className="mt-1 text-[9px] leading-4 text-slate-600">
                            Record only an explicit result from a provider or manual operator. Automated provider execution is available above when a configured provider executor is ready.
                          </p>
                        </div>
                        <span className="rounded-full bg-cyan-400/10 px-2 py-1 text-[8px] uppercase tracking-wider text-cyan-200">Approved</span>
                      </div>

                      {outcomeActionId === action.id ? (
                        <div className="mt-3 space-y-2">
                          <select
                            value={outcomeStatus}
                            onChange={(event) => setOutcomeStatus(event.target.value as "completed" | "failed")}
                            className="w-full rounded-lg border border-white/10 bg-[#071018] px-3 py-2 text-[10px] text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/30"
                          >
                            <option value="completed">Completed</option>
                            <option value="failed">Failed</option>
                          </select>
                          <input
                            value={executorType}
                            onChange={(event) => setExecutorType(event.target.value)}
                            placeholder="Executor type (e.g. manual_operator)"
                            className="w-full rounded-lg border border-white/10 bg-[#071018] px-3 py-2 text-[10px] text-white placeholder:text-slate-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/30"
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
                            className="w-full resize-none rounded-lg border border-white/10 bg-[#071018] px-3 py-2 text-[10px] text-white placeholder:text-slate-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/30"
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
                    <div className="mt-4 rounded-xl border border-amber-400/10 bg-amber-400/[0.025] p-3">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-[9px] font-semibold uppercase tracking-wider text-amber-200">Pre-authorization checklist</p>
                        <span className="text-[8px] uppercase tracking-wider text-slate-600">Review before approval</span>
                      </div>
                      <div className="mt-3 space-y-2">
                        <ApprovalCheck
                          ok={Boolean(action.target_context?.resourceName)}
                          label={action.target_context?.resourceName ? "Target identified" : "Target identity needs review"}
                          detail={action.target_context?.resourceType
                            ? action.target_context.resourceType.replaceAll("_", " ")
                            : "No verified Trinorin resource"}
                        />
                        <ApprovalCheck
                          ok={Boolean(action.finding_id)}
                          label={action.finding_id ? "Finding linked" : "No finding linked"}
                          detail={action.finding_id ? "Approval will revalidate the finding and target." : "Operator-supplied action context."}
                        />
                        <ApprovalCheck
                          ok={action.target_context?.source !== "operator supplied"}
                          label={action.target_context?.source !== "operator supplied" ? "Organization resource resolved" : "Resource ownership not resolved"}
                          detail={action.target_context?.source ?? "Operator supplied"}
                        />
                        <ApprovalCheck
                          ok={action.action_type === "review_finding" || readinessLoading || readiness[action.action_type]?.executorReady === true}
                          label={readinessLoading
                            ? "Checking executor readiness..."
                            : readiness[action.action_type]?.executorReady
                              ? "Executor readiness available"
                              : action.action_type === "review_finding"
                                ? "No external executor required"
                                : "Provider executor not configured"}
                          detail={readiness[action.action_type]?.boundary ?? "Executor capability is separate from authorization."}
                        />
                        <ApprovalCheck
                          ok={true}
                          label="Approval-time revalidation enabled"
                          detail="Trinorin will re-check the target and organization ownership when you authorize."
                        />
                      </div>
                      <p className="mt-3 text-[8px] leading-4 text-slate-600">
                        Unknowns remain unknown. Authorization does not prove compromise, remediation, or external execution.
                      </p>
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
            Trinorin does not silently isolate devices, revoke credentials, disable services, or block indicators. Those capabilities require an explicitly connected provider executor and an authorization policy.
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


export default function SecurityActionsPage() {
  return (
    <Suspense
      fallback={
        <main className="min-h-screen bg-[#071018] text-slate-100">
          <div className="mx-auto flex min-h-screen max-w-[1100px] items-center justify-center px-4">
            <p className="text-sm text-slate-500">Loading Security Actions…</p>
          </div>
        </main>
      }
    >
      <SecurityActionsPageContent />
    </Suspense>
  );
}

function ApprovalCheck({
  ok,
  label,
  detail,
}: {
  ok: boolean;
  label: string;
  detail: string;
}) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-white/10 bg-black/10 p-2">
      {ok ? (
        <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-emerald-300" />
      ) : (
        <ShieldAlert className="mt-0.5 h-3 w-3 shrink-0 text-amber-300" />
      )}
      <div className="min-w-0">
        <p className="text-[9px] font-medium text-slate-300">{label}</p>
        <p className="mt-0.5 text-[8px] leading-4 text-slate-600">{detail}</p>
      </div>
    </div>
  );
}

function ResponseLifecycle({ action }: { action: Action }) {
  const responseRecorded = ["approved", "executing", "completed", "failed"].includes(action.status);
  const outcomeRecorded = action.status === "completed" || action.status === "failed";
  const stages = [
    { label: "Finding", state: action.finding_id ? "recorded" : "pending", href: action.finding_id ? `/analyst?findingId=${encodeURIComponent(action.finding_id)}` : "/analyst" },
    { label: "Decide", state: action.status === "pending" ? "current" : "recorded", href: action.finding_id ? `/actions?findingId=${encodeURIComponent(action.finding_id)}` : "/actions" },
    { label: "Respond", state: responseRecorded ? "recorded" : "pending", href: "/actions" },
    { label: "Verify", state: action.result?.verification ? "recorded" : outcomeRecorded ? "current" : "pending", href: action.finding_id ? `/analyst?findingId=${encodeURIComponent(action.finding_id)}` : "/analyst" },
    { label: "Learn", state: action.result?.verification ? "recorded" : "pending", href: "/brain" },
  ] as const;

  return (
    <div className="mt-3 rounded-xl border border-violet-400/10 bg-violet-400/[0.02] p-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[9px] font-semibold uppercase tracking-wider text-violet-200">Defense lifecycle</p>
        <Link
          href={action.finding_id ? `/analyst?findingId=${encodeURIComponent(action.finding_id)}` : "/analyst"}
          className="text-[8px] uppercase tracking-wider text-slate-500 hover:text-white"
        >
          Verify in Analyst
        </Link>
      </div>
      <div className="mt-3 grid grid-cols-5 gap-1.5">
        {stages.map((stage) => (
          <Link href={stage.href} key={stage.label} className="rounded-lg border border-white/10 bg-black/10 p-2 transition hover:border-white/20">
            <p className="text-[8px] font-medium text-slate-300">{stage.label}</p>
            <span className={
              stage.state === "recorded"
                ? "mt-1 inline-flex rounded-full bg-emerald-400/10 px-1.5 py-0.5 text-[7px] uppercase tracking-wider text-emerald-200"
                : stage.state === "current"
                  ? "mt-1 inline-flex rounded-full bg-cyan-400/10 px-1.5 py-0.5 text-[7px] uppercase tracking-wider text-cyan-200"
                  : "mt-1 inline-flex rounded-full bg-amber-400/10 px-1.5 py-0.5 text-[7px] uppercase tracking-wider text-amber-200"
            }>
              {stage.state}
            </span>
          </Link>
        ))}
      </div>
      <p className="mt-2 text-[8px] leading-4 text-slate-600">
        A recorded execution is not treated as verified remediation. Verification still depends on post-response evidence and current finding state.
      </p>
    </div>
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