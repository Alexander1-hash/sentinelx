import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

const allowedStatuses = ["planned", "pending", "connected", "paused", "error"] as const;

async function getContext() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) return { supabase, user: null, organizationId: null };

  const { data: profile } = await supabase
    .from("profiles")
    .select("organization_id")
    .eq("id", user.id)
    .maybeSingle();

  return {
    supabase,
    user,
    organizationId: profile?.organization_id ?? null,
  };
}

export async function GET() {
  try {
    const { supabase, user, organizationId } = await getContext();

    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    if (!organizationId) return NextResponse.json({ integrations: [] });

    const { data, error } = await supabase
      .from("security_integrations")
      .select("id,provider,integration_type,display_name,status,scopes,last_sync_at,created_at")
      .eq("organization_id", organizationId)
      .order("created_at", { ascending: false });

    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    return NextResponse.json({ integrations: data ?? [] });
  } catch {
    return NextResponse.json({ error: "Unable to load security integrations." }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const { supabase, user, organizationId } = await getContext();

    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    if (!organizationId) {
      return NextResponse.json(
        { error: "Your account is not connected to an organization yet." },
        { status: 409 }
      );
    }

    const body = await request.json();
    const provider = typeof body.provider === "string" ? body.provider.trim() : "";
    const integrationType = typeof body.integrationType === "string" ? body.integrationType.trim() : "";
    const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
    const scopes = Array.isArray(body.scopes)
      ? body.scopes.filter((scope: unknown): scope is string => typeof scope === "string").slice(0, 50)
      : [];

    if (!provider || !integrationType || !displayName) {
      return NextResponse.json(
        { error: "Provider, integration type, and display name are required." },
        { status: 400 }
      );
    }

    const { data: existing } = await supabase
      .from("security_integrations")
      .select("id")
      .eq("organization_id", organizationId)
      .eq("provider", provider)
      .eq("integration_type", integrationType)
      .maybeSingle();

    if (existing) {
      return NextResponse.json(
        { error: "This integration is already registered for your organization." },
        { status: 409 }
      );
    }

    const { data, error } = await supabase
      .from("security_integrations")
      .insert({
        organization_id: organizationId,
        provider,
        integration_type: integrationType,
        display_name,
        status: "planned",
        scopes,
        configuration: {
          connection_state: "not_connected",
          credential_storage: "not_configured",
        },
      })
      .select("id,provider,integration_type,display_name,status,scopes,last_sync_at,created_at")
      .single();

    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    return NextResponse.json({
      integration: data,
      message: "Integration registered. Connection credentials have not been requested or stored.",
    }, { status: 201 });
  } catch {
    return NextResponse.json({ error: "Invalid integration request." }, { status: 400 });
  }
}
