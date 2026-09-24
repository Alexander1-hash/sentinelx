import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

type AttentionItem = {
  id: string;
  kind: "finding" | "event" | "action";
  priority: "high" | "medium";
  title: string;
  detail: string;
  observedAt: string;
  href: string;
};

export async function GET() {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
    const organizationId = profile?.organization_id;
    if (!organizationId) return NextResponse.json({ items: [], summary: { high: 0, medium: 0 } });

    const [findingsResult, eventsResult, actionsResult] = await Promise.all([
      supabase.from("security_findings")
        .select("id,title,severity,summary,detected_at")
        .eq("organization_id", organizationId)
        .in("status", ["open", "acknowledged"])
        .in("severity", ["high", "critical"])
        .order("detected_at", { ascending: false })
        .limit(10),
      supabase.from("security_events")
        .select("id,title,severity,description,observed_at")
        .eq("organization_id", organizationId)
        .in("severity", ["high", "critical"])
        .order("observed_at", { ascending: false })
        .limit(10),
      supabase.from("security_actions")
        .select("id,action_type,status,created_at")
        .eq("organization_id", organizationId)
        .eq("status", "pending")
        .order("created_at", { ascending: false })
        .limit(10),
    ]);

    const error = findingsResult.error ?? eventsResult.error ?? actionsResult.error;
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    const items: AttentionItem[] = [
      ...(findingsResult.data ?? []).map((item) => ({
        id: item.id,
        kind: "finding" as const,
        priority: "high" as const,
        title: item.title,
        detail: item.summary ?? "Open high-impact security finding requires review.",
        observedAt: item.detected_at,
        href: "/brain",
      })),
      ...(eventsResult.data ?? []).map((item) => ({
        id: item.id,
        kind: "event" as const,
        priority: "high" as const,
        title: item.title,
        detail: item.description ?? "High-impact telemetry event observed.",
        observedAt: item.observed_at,
        href: "/analyst",
      })),
      ...(actionsResult.data ?? []).map((item) => ({
        id: item.id,
        kind: "action" as const,
        priority: "medium" as const,
        title: "Operator review required",
        detail: `${item.action_type.replaceAll("_", " ")} is waiting for an explicit decision.`,
        observedAt: item.created_at,
        href: "/actions",
      })),
    ]
      .sort((a, b) => new Date(b.observedAt).getTime() - new Date(a.observedAt).getTime())
      .slice(0, 12);

    return NextResponse.json({
      items,
      summary: {
        high: items.filter((item) => item.priority === "high").length,
        medium: items.filter((item) => item.priority === "medium").length,
      },
      boundary: "Attention items are derived from recorded findings, telemetry, and pending operator actions. They are not proof of compromise.",
    });
  } catch {
    return NextResponse.json({ error: "Security attention data could not be loaded." }, { status: 500 });
  }
}
