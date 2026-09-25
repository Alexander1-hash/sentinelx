import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import {
  buildSecurityPatterns,
  summarizeSecurityPatterns,
  type SecurityPatternMemory,
} from "@/lib/security/patterns";

export async function GET() {
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

    const memories = (data ?? []) as SecurityPatternMemory[];
    const patterns = buildSecurityPatterns(memories);

    return NextResponse.json({
      patterns,
      summary: summarizeSecurityPatterns(patterns),
      boundary:
        "Security Pattern Intelligence identifies deterministic patterns in recorded SentinelX memory. Patterns are investigation signals, not proof of compromise, attribution, or current security state.",
    });
  } catch {
    return NextResponse.json(
      { error: "Security patterns could not be generated." },
      { status: 500 },
    );
  }
}
