import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

type Memory = {
  id: string;
  memory_type: string;
  subject_id: string | null;
  title: string;
  summary: string;
  state: string;
  data: Record<string, unknown>;
  occurred_at: string;
};

type Change = {
  id: string;
  kind: string;
  title: string;
  detail: string;
  observedAt: string;
  state: "new" | "changed" | "remembered" | "resolved";
  href: string;
  verificationState?: "improved" | "observed" | "uncertain" | "awaiting_evidence";
};

function sameFindingState(memory: Memory, finding: {
  id: string;
  severity: string;
  status: string;
}) {
  const dataFindingId = typeof memory.data.finding_id === "string"
    ? memory.data.finding_id
    : null;

  return (
    memory.memory_type === "finding_state" &&
    (memory.subject_id === finding.id || dataFindingId === finding.id) &&
    memory.state === finding.status &&
    memory.data.severity === finding.severity
  );
}

export async function GET(request: Request) {
  try {
    const supabase = await createClient();
    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const findingIdFilter = new URL(request.url).searchParams.get("findingId");

    const { data: profile } = await supabase
      .from("profiles")
      .select("organization_id")
      .eq("id", user.id)
      .maybeSingle();

    if (!profile?.organization_id) {
      return NextResponse.json({
        changes: [],
        summary: { new: 0, changed: 0, remembered: 0, resolved: 0 },
      });
    }

    const [
      memoryResult,
      findingResult,
      evidenceResult,
      actionResult,
    ] = await Promise.all([
      supabase
        .from("security_memory")
        .select("id,memory_type,subject_id,title,summary,state,data,occurred_at")
        .eq("organization_id", profile.organization_id)
        .order("occurred_at", { ascending: false })
        .limit(200),
      supabase
        .from("security_findings")
        .select("id,title,finding_type,severity,status,summary,updated_at,detected_at")
        .eq("organization_id", profile.organization_id)
        .order("updated_at", { ascending: false })
        .limit(100),
      supabase
        .from("security_evidence")
        .select("id,asset_id,title,evidence_type,source,summary,observed_at,created_at")
        .eq("organization_id", profile.organization_id)
        .order("observed_at", { ascending: false })
        .limit(100),
      supabase
        .from("security_actions")
        .select("id,finding_id,action_type,status,target,result,created_at,executed_at")
        .eq("organization_id", profile.organization_id)
        .order("created_at", { ascending: false })
        .limit(100),
    ]);

    const error =
      memoryResult.error ??
      findingResult.error ??
      evidenceResult.error ??
      actionResult.error;

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    const memories = (memoryResult.data ?? []) as Memory[];
    const changes: Change[] = [];

    for (const memory of memories) {
      if (memory.memory_type !== "evidence_change") continue;

      const rawChangeType =
        typeof memory.data.change_type === "string"
          ? memory.data.change_type
          : "new";

      if (
        rawChangeType !== "new" &&
        rawChangeType !== "changed" &&
        rawChangeType !== "resolved"
      ) {
        continue;
      }

      const changeType: "new" | "changed" | "resolved" = rawChangeType;

      const evidenceId =
        typeof memory.data.evidence_id === "string"
          ? memory.data.evidence_id
          : memory.subject_id ?? memory.id;

      const source =
        typeof memory.data.source === "string"
          ? memory.data.source
          : "recorded evidence";

      changes.push({
        id: `evidence-${evidenceId}`,
        kind: "evidence",
        title: changeType === "changed"
          ? memory.title.replace(/^Evidence changed:\s*/i, "Changed: ")
          : changeType === "resolved"
            ? memory.title.replace(/^Evidence resolved:\s*/i, "Resolved: ")
            : memory.title.replace(/^New evidence:\s*/i, "New evidence: "),
        detail: changeType === "changed"
          ? `${source} reported a different recorded evidence state.`
          : changeType === "resolved"
            ? `${source} explicitly reported a cleared or resolved state.`
            : `${source} reported a new evidence pattern.`,
        observedAt: memory.occurred_at,
        state: changeType,
        href: "/brain",
      });
    }

    for (const finding of findingResult.data ?? []) {
      const known = memories.some((memory) => sameFindingState(memory, finding));

      if (!known) {
        changes.push({
          id: `finding-${finding.id}`,
          kind: "finding",
          title: `Changed: ${finding.title}`,
          detail: `Current state is ${finding.status} with ${finding.severity} severity.`,
          observedAt: finding.updated_at ?? finding.detected_at,
          state: "changed",
          href: "/brain",
        });
      } else {
        changes.push({
          id: `remembered-${finding.id}`,
          kind: "memory",
          title: `Remembered: ${finding.title}`,
          detail: "SentinelX has historical context for this finding.",
          observedAt: finding.updated_at ?? finding.detected_at,
          state: "remembered",
          href: "/brain",
        });
      }
    }

    const evidenceMemoryIds = new Set(
      memories
        .filter((memory) => memory.memory_type === "evidence_change")
        .map((memory) =>
          typeof memory.data.evidence_id === "string"
            ? memory.data.evidence_id
            : memory.subject_id
        )
        .filter((value): value is string => Boolean(value))
    );

    for (const evidence of evidenceResult.data ?? []) {
      if (evidenceMemoryIds.has(evidence.id)) continue;

      changes.push({
        id: `unremembered-evidence-${evidence.id}`,
        kind: "evidence",
        title: `New evidence: ${evidence.title}`,
        detail: `${evidence.source} · ${evidence.evidence_type}`,
        observedAt: evidence.observed_at ?? evidence.created_at,
        state: "new",
        href: "/brain",
      });
    }

    for (const action of actionResult.data ?? []) {
      const known = memories.some(
        (memory) =>
          memory.memory_type === "operator_decision" &&
          memory.subject_id === action.id
      );

      if (
        !known &&
        ["approved", "cancelled", "completed", "failed"].includes(action.status)
      ) {
        changes.push({
          id: `action-${action.id}`,
          kind: "decision",
          title: `Action changed: ${action.action_type}`,
          detail: `Operator action is now ${action.status}.`,
          observedAt: action.executed_at ?? action.created_at,
          state: "changed",
          href: "/actions",
        });
      }

      if (
        action.finding_id &&
        action.executed_at &&
        ["completed", "failed"].includes(action.status)
      ) {
        const postResponseEvidence = (evidenceResult.data ?? []).filter((evidence) => {
          if (!evidence.observed_at) return false;
          return new Date(evidence.observed_at).getTime() >= new Date(action.executed_at!).getTime();
        });

        const linkedEvidence = postResponseEvidence.filter((evidence) => {
          const target =
            (action.target as Record<string, unknown> | null) ?? {};

          const targetAssetId =
            typeof target.assetId === "string"
              ? target.assetId
              : target.resourceType === "asset" && typeof target.resourceId === "string"
                ? target.resourceId
                : null;

          return evidence.asset_id === targetAssetId;
        });

        const evidenceCount = linkedEvidence.length;
        const currentFinding = (findingResult.data ?? []).find(
          (finding) => finding.id === action.finding_id
        );
        const preResponseFindingState = [...memories]
          .filter(
            (memory) =>
              memory.memory_type === "finding_state" &&
              (memory.subject_id === action.finding_id ||
                memory.data.finding_id === action.finding_id) &&
              new Date(memory.occurred_at).getTime() <= new Date(action.executed_at!).getTime()
          )
          .sort(
            (a, b) =>
              new Date(b.occurred_at).getTime() - new Date(a.occurred_at).getTime()
          )[0];

        const resolvedStatuses = new Set(["resolved", "closed", "cleared", "healthy"]);
        const severityRank: Record<string, number> = {
          critical: 4,
          high: 3,
          medium: 2,
          low: 1,
          info: 0,
        };
        const baselineSeverity =
          typeof preResponseFindingState?.data.severity === "string"
            ? preResponseFindingState.data.severity
            : null;
        const currentSeverity = currentFinding?.severity ?? null;
        const severityImproved =
          baselineSeverity !== null &&
          currentSeverity !== null &&
          severityRank[currentSeverity] < severityRank[baselineSeverity];

        const stateImproved =
          Boolean(currentFinding && resolvedStatuses.has(currentFinding.status)) ||
          severityImproved;

        const stateUnchanged = Boolean(
          currentFinding &&
          preResponseFindingState &&
          currentFinding.status === preResponseFindingState.state &&
          currentFinding.severity === baselineSeverity
        );

        const verificationState =
          action.status === "failed"
            ? "uncertain"
            : stateImproved
              ? "improved"
              : evidenceCount > 0
                ? "observed"
                : "awaiting_evidence";

        const verificationDetail =
          verificationState === "improved"
            ? `Current finding state provides a post-response improvement signal${severityImproved ? " through lower recorded severity" : ""}.`
            : verificationState === "observed"
              ? `${evidenceCount} evidence record(s) were observed at or after execution, but the finding state is not independently resolved.`
              : verificationState === "uncertain"
                ? "The recorded response failed; current security state still requires independent evidence."
                : stateUnchanged
                  ? "The response was recorded, but the finding state remains unchanged and no post-response evidence is available."
                  : "The response was recorded, but no post-response evidence is available yet.";

        changes.push({
          id: `verification-${action.id}`,
          kind: "verification",
          title: `Response verification: ${action.action_type}`,
          detail: verificationDetail,
          observedAt: action.executed_at,
          state: "changed",
          verificationState,
          href: action.finding_id
            ? `/analyst?findingId=${encodeURIComponent(action.finding_id)}`
            : "/analyst",
        });
      }
    }

    const filtered = findingIdFilter
      ? changes.filter(
          (change) =>
            change.href.includes(encodeURIComponent(findingIdFilter)) ||
            change.id === `verification-${findingIdFilter}`
        )
      : changes;

    const deduplicated = Array.from(
      new Map(filtered.map((change) => [change.id, change])).values()
    );

    deduplicated.sort(
      (a, b) =>
        new Date(b.observedAt).getTime() - new Date(a.observedAt).getTime()
    );

    const visible = deduplicated.slice(0, 20);

    return NextResponse.json({
      changes: visible,
      summary: {
        new: visible.filter((item) => item.state === "new").length,
        changed: visible.filter((item) => item.state === "changed").length,
        remembered: visible.filter((item) => item.state === "remembered").length,
        resolved: visible.filter((item) => item.state === "resolved").length,
      },
      boundary:
        "Change intelligence compares recorded evidence and current security state with SentinelX security memory. Unchanged telemetry is suppressed. Resolved is shown only when an authorized source explicitly reports a cleared, resolved, or healthy state after an active/degraded state. Silence or missing telemetry is never treated as resolution. A change alone is not proof of compromise.",
    });
  } catch {
    return NextResponse.json(
      { error: "Change intelligence could not be generated." },
      { status: 500 }
    );
  }
}
