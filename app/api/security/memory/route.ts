import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET() {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
    if (!profile?.organization_id) return NextResponse.json({ memories: [] });

    const { data, error } = await supabase.from("security_memory")
      .select("id,memory_type,subject_id,title,summary,state,data,occurred_at,created_at")
      .eq("organization_id", profile.organization_id)
      .order("occurred_at", { ascending: false }).limit(50);
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });
    return NextResponse.json({ memories: data ?? [] });
  } catch {
    return NextResponse.json({ error: "Security memory could not be loaded." }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const { data: profile } = await supabase.from("profiles").select("organization_id").eq("id", user.id).maybeSingle();
    if (!profile?.organization_id) return NextResponse.json({ error: "Organization is required." }, { status: 400 });

    const body = await request.json() as {
      memoryType?: string; subjectId?: string | null; title?: string; summary?: string; state?: string; data?: Record<string, unknown>;
    };
    if (!body.memoryType || !body.title?.trim() || !body.summary?.trim()) {
      return NextResponse.json({ error: "memoryType, title and summary are required." }, { status: 400 });
    }
    const { data, error } = await supabase.from("security_memory").insert({
      organization_id: profile.organization_id,
      memory_type: body.memoryType,
      subject_id: body.subjectId ?? null,
      title: body.title.trim(),
      summary: body.summary.trim(),
      state: body.state?.trim() || "active",
      data: body.data ?? {},
    }).select("id,memory_type,subject_id,title,summary,state,data,occurred_at,created_at").single();
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });
    return NextResponse.json({ memory: data }, { status: 201 });
  } catch {
    return NextResponse.json({ error: "Security memory could not be recorded." }, { status: 500 });
  }
}
