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

function fingerprint(memory: Memory) {
  return JSON.stringify({
    type: memory.memory_type,
    subject: memory.subject_id,
    title: memory.title,
    state: memory.state,
    data: memory.data,
  });
}

export async function GET() {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
    if (!profile?.organization_id) return NextResponse.json({ changes: [], summary: { new: 0, changed: 0, remembered: 0 } });

    const [memoryResult, findingResult, evidenceResult, actionResult] = await Promise.all([
      supabase.from("security_memory").select("id,memory_type,subject_id,title,summary,state,data,occurred_at").eq("organization_id", profile.organization_id).order("occurred_at", { ascending: false }).limit(200),
      supabase.from("security_findings").select("id,title,finding_type,severity,status,summary,updated_at,detected_at").eq("organization_id", profile.organization_id).order("updated_at", { ascending: false }).limit(100),
      supabase.from("security_evidence").select("id,title,evidence_type,source,summary,observed_at,created_at").eq("organization_id", profile.organization_id).order("observed_at", { ascending: false }).limit(100),
      supabase.from("security_actions").select("id,finding_id,action_type,status,result,created_at").eq("organization_id", profile.organization_id).order("created_at", { ascending: false }).limit(100),
    ]);

    const error = memoryResult.error ?? findingResult.error ?? evidenceResult.error ?? actionResult.error;
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    const memories = (memoryResult.data ?? []) as Memory[];
    const memoryFingerprints = new Set(memories.map(fingerprint));
    const changes: Array<{ id: string; kind: string; title: string; detail: string; observedAt: string; state: "new" | "changed" | "remembered"; href: string }> = [];

    for (const finding of findingResult.data ?? []) {
      const title = `Finding state: ${finding.title}`;
      const data = { finding_id: finding.id, severity: finding.severity, status: finding.status };
      const memory: Memory = { id: finding.id, memory_type: "finding_state", subject_id: finding.id, title, summary: finding.summary ?? `Finding is currently ${finding.status} at ${finding.severity} severity.`, state: finding.status, data, occurred_at: finding.updated_at ?? finding.detected_at };
      const known = memories.some((item) => item.memory_type === "finding_state" && item.subject_id === finding.id && item.state === finding.status && JSON.stringify(item.data) === JSON.stringify(data));
      if (!known) {
        changes.push({ id: finding.id, kind: "finding", title: `Changed: ${finding.title}`, detail: `Current state is ${finding.status} with ${finding.severity} severity.`, observedAt: finding.updated_at ?? finding.detected_at, state: "changed", href: "/brain" });
      } else if (memoryFingerprints.has(fingerprint(memory))) {
        changes.push({ id: `remembered-${finding.id}`, kind: "memory", title: `Remembered: ${finding.title}`, detail: "SentinelX has historical context for this finding.", observedAt: finding.updated_at ?? finding.detected_at, state: "remembered", href: "/brain" });
      }
    }

    for (const evidence of evidenceResult.data ?? []) {
      const known = memories.some((item) => item.memory_type === "evidence_change" && item.subject_id === evidence.id);
      if (!known) changes.push({ id: evidence.id, kind: "evidence", title: `New evidence: ${evidence.title}`, detail: `${evidence.source} · ${evidence.evidence_type}`, observedAt: evidence.observed_at ?? evidence.created_at, state: "new", href: "/brain" });
    }

    for (const action of actionResult.data ?? []) {
      const known = memories.some((item) => item.memory_type === "operator_decision" && item.subject_id === action.id);
      if (!known && ["approved", "cancelled", "completed", "failed"].includes(action.status)) {
        changes.push({ id: action.id, kind: "decision", title: `Action changed: ${action.action_type}`, detail: `Operator action is now ${action.status}.`, observedAt: action.created_at, state: "changed", href: "/actions" });
      }
    }

    changes.sort((a, b) => new Date(b.observedAt).getTime() - new Date(a.observedAt).getTime());

    return NextResponse.json({
      changes: changes.slice(0, 20),
      summary: {
        new: changes.filter((item) => item.state === "new").length,
        changed: changes.filter((item) => item.state === "changed").length,
        remembered: changes.filter((item) => item.state === "remembered").length,
      },
      boundary: "Change intelligence compares recorded current state with SentinelX security memory. It does not infer compromise from change alone.",
    });
  } catch {
    return NextResponse.json({ error: "Change intelligence could not be generated." }, { status: 500 });
  }
}
