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

export async function GET() {
  try {
    const supabase = await createClient();
    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

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
        .select("id,finding_id,action_type,status,result,created_at")
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

    // Evidence Change Intelligence v2:
    // only new or changed evidence is surfaced as a change. Unchanged
    // telemetry is intentionally quiet so repeated heartbeats do not create noise.
    for (const memory of memories) {
      if (memory.memory_type !== "evidence_change") continue;

      const changeType =
        typeof memory.data.change_type === "string"
          ? memory.data.change_type
          : "new";

      if (!["new", "changed", "resolved"].includes(changeType)) continue;

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

    // Evidence without a corresponding memory record is still surfaced as
    // new so operators can see ingestion that predates or bypasses memory.
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
          observedAt: action.created_at,
          state: "changed",
          href: "/actions",
        });
      }
    }

    const deduplicated = Array.from(
      new Map(changes.map((change) => [change.id, change])).values()
    );

    deduplicated.sort(
      (a, b) =>
        new Date(b.observedAt).getTime() -
        new Date(a.observedAt).getTime()
    );

    const visible = deduplicated.slice(0, 20);

    return NextResponse.json({
      changes: visible,
      summary: {
        new: visible.filter((item) => item.state === "new").length,
        changed: visible.filter((item) => item.state === "changed").length,
        remembered: visible.filter((item) => item.state === "remembered").length,
        // Resolved state requires a recorded disappearance/state-transition
        // model. SentinelX deliberately does not infer resolution from silence.
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
