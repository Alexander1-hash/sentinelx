import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import {
  buildSecurityPatterns,
  summarizeSecurityPatterns,
  type SecurityPatternMemory,
} from "@/lib/security/patterns";

export async function GET(request: Request) {
  const findingId = new URL(request.url).searchParams.get("findingId");
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

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
        patterns: [],
        summary: {
          total: 0,
          recurrence: 0,
          reopened: 0,
          evidence: 0,
          ai: 0,
          response: 0,
        },
      });
    }

    const { data, error } = await supabase
      .from("security_memory")
      .select("id,memory_type,subject_id,title,summary,state,data,occurred_at")
      .eq("organization_id", profile.organization_id)
      .order("occurred_at", { ascending: false })
      .limit(300);

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    let memories = (data ?? []) as SecurityPatternMemory[];

    if (findingId) {
      const { data: finding, error: findingError } = await supabase
        .from("security_findings")
        .select("id,asset_id,finding_type")
        .eq("id", findingId)
        .eq("organization_id", profile.organization_id)
        .maybeSingle();

      if (findingError) {
        return NextResponse.json({ error: findingError.message }, { status: 500 });
      }

      if (!finding) {
        return NextResponse.json({ patterns: [], summary: { total: 0, recurrence: 0, reopened: 0, evidence: 0, ai: 0, response: 0, sequences: 0 } });
      }

      memories = memories.filter((memory) => {
        const memoryFindingId =
          typeof memory.data.finding_id === "string"
            ? memory.data.finding_id
            : memory.memory_type === "finding_state"
              ? memory.subject_id
              : null;
        const memoryAssetId =
          typeof memory.data.asset_id === "string"
            ? memory.data.asset_id
            : typeof memory.data.affected_asset_id === "string"
              ? memory.data.affected_asset_id
              : null;
        const memoryFindingType =
          typeof memory.data.finding_type === "string"
            ? memory.data.finding_type
            : null;

        return (
          memoryFindingId === finding.id ||
          (Boolean(finding.asset_id) && memoryAssetId === finding.asset_id) ||
          (Boolean(finding.finding_type) && memoryFindingType === finding.finding_type)
        );
      });
    }

    const patterns = buildSecurityPatterns(memories);

    return NextResponse.json({
      patterns,
      summary: summarizeSecurityPatterns(patterns),
      boundary:
        "Security Pattern Intelligence identifies deterministic patterns in recorded Trinorin memory. Patterns are investigation signals, not proof of compromise, attribution, or current security state.",
    });
  } catch {
    return NextResponse.json(
      { error: "Security patterns could not be generated." },
      { status: 500 },
    );
  }
}
