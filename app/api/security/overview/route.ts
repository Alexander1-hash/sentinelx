import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET() {
  try {
    const supabase = await createClient();

    const {
      data: { user },
      error: authError,
    } = await supabase.auth.getUser();

    if (authError || !user) {
      return NextResponse.json(
        { error: "Unauthorized" },
        { status: 401 }
      );
    }

    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .select("organization_id")
      .eq("id", user.id)
      .maybeSingle();

    if (profileError) {
      return NextResponse.json(
        { error: profileError.message },
        { status: 500 }
      );
    }

    if (!profile?.organization_id) {
      return NextResponse.json({
        connected: false,
        organizationId: null,
        metrics: {
          protectedAssets: 0,
          openFindings: 0,
          securityEvents: 0,
          attackPaths: 0,
          aiSystems: 0,
          aiAgents: 0,
        },
        latestEvents: [],
      });
    }

    const organizationId = profile.organization_id;

    const [
      assetsResult,
      findingsResult,
      eventsResult,
      relationshipsResult,
      aiSystemsResult,
      aiAgentsResult,
      latestEventsResult,
    ] = await Promise.all([
      supabase
        .from("security_assets")
        .select("id", { count: "exact", head: true })
        .eq("organization_id", organizationId),

      supabase
        .from("security_findings")
        .select("id", { count: "exact", head: true })
        .eq("organization_id", organizationId)
        .in("status", ["open", "acknowledged"]),

      supabase
        .from("security_events")
        .select("id", { count: "exact", head: true })
        .eq("organization_id", organizationId),

      supabase
        .from("security_asset_relationships")
        .select("id", { count: "exact", head: true })
        .eq("organization_id", organizationId),

      supabase
        .from("ai_security_systems")
        .select("id", { count: "exact", head: true })
        .eq("organization_id", organizationId),

      supabase
        .from("ai_security_agents")
        .select("id", { count: "exact", head: true })
        .eq("organization_id", organizationId),

      supabase
        .from("security_events")
        .select(
          "id,event_type,severity,source,title,description,observed_at,asset_id"
        )
        .eq("organization_id", organizationId)
        .order("observed_at", { ascending: false })
        .limit(10),
    ]);

    const queryErrors = [
      assetsResult.error,
      findingsResult.error,
      eventsResult.error,
      relationshipsResult.error,
      aiSystemsResult.error,
      aiAgentsResult.error,
      latestEventsResult.error,
    ].filter(Boolean);

    if (queryErrors.length > 0) {
      return NextResponse.json(
        { error: queryErrors[0]?.message ?? "Security data query failed" },
        { status: 500 }
      );
    }

    const protectedAssets = assetsResult.count ?? 0;
    const securityEvents = eventsResult.count ?? 0;

    return NextResponse.json({
      connected: protectedAssets > 0 || securityEvents > 0,
      organizationId,
      metrics: {
        protectedAssets,
        openFindings: findingsResult.count ?? 0,
        securityEvents,
        attackPaths: relationshipsResult.count ?? 0,
        aiSystems: aiSystemsResult.count ?? 0,
        aiAgents: aiAgentsResult.count ?? 0,
      },
      latestEvents: latestEventsResult.data ?? [],
    });
  } catch (error) {
    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : "Unexpected security overview error",
      },
      { status: 500 }
    );
  }
}
