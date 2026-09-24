import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

const allowedTypes = [
  "website",
  "domain",
  "cloud",
  "identity",
  "endpoint",
  "email",
  "business_software",
  "database",
  "ai_system",
  "ai_agent",
  "api",
  "other",
] as const;

type AssetType = (typeof allowedTypes)[number];

const onboardingMap: Record<AssetType, {
  nextStep: string;
  telemetry: string;
  recommendedIntegrations: string[];
}> = {
  website: {
    nextStep: "Connect HTTP, DNS, and application telemetry.",
    telemetry: "HTTP/DNS telemetry not connected",
    recommendedIntegrations: ["DNS", "HTTP monitoring", "Application logs"],
  },
  domain: {
    nextStep: "Verify DNS ownership and connect DNS telemetry.",
    telemetry: "DNS telemetry not connected",
    recommendedIntegrations: ["DNS provider", "Certificate monitoring"],
  },
  cloud: {
    nextStep: "Connect the cloud provider with least-privilege read access.",
    telemetry: "Cloud telemetry not connected",
    recommendedIntegrations: ["Cloud provider", "Audit logs"],
  },
  identity: {
    nextStep: "Connect the identity provider and authentication signals.",
    telemetry: "Identity telemetry not connected",
    recommendedIntegrations: ["Identity provider", "Authentication logs"],
  },
  endpoint: {
    nextStep: "Enroll an authorized endpoint security source.",
    telemetry: "Endpoint telemetry not connected",
    recommendedIntegrations: ["Endpoint security", "Device inventory"],
  },
  email: {
    nextStep: "Connect mail security and account activity signals.",
    telemetry: "Email telemetry not connected",
    recommendedIntegrations: ["Mail provider", "Mail security"],
  },
  business_software: {
    nextStep: "Connect the application's audit or activity logs.",
    telemetry: "Application telemetry not connected",
    recommendedIntegrations: ["Audit logs", "Application API"],
  },
  database: {
    nextStep: "Connect database audit signals without collecting database passwords.",
    telemetry: "Database telemetry not connected",
    recommendedIntegrations: ["Database audit logs", "Read-only monitoring"],
  },
  ai_system: {
    nextStep: "Map the model, data classification, tools, and permissions.",
    telemetry: "AI security telemetry not connected",
    recommendedIntegrations: ["Model/provider logs", "AI gateway", "Tool activity"],
  },
  ai_agent: {
    nextStep: "Map tools, permissions, data access, and autonomy level.",
    telemetry: "Agent telemetry not connected",
    recommendedIntegrations: ["Agent logs", "Tool activity", "Permission inventory"],
  },
  api: {
    nextStep: "Connect request telemetry and authentication signals.",
    telemetry: "API telemetry not connected",
    recommendedIntegrations: ["API gateway", "Request logs"],
  },
  other: {
    nextStep: "Define the asset's telemetry source and relationships.",
    telemetry: "Telemetry not connected",
    recommendedIntegrations: ["Telemetry source"],
  },
};

export async function GET() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { data, error } = await supabase
    .from("security_assets")
    .select("id,name,asset_type,provider,environment,criticality,status,metadata,last_seen_at,created_at")
    .order("created_at", { ascending: false });

  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  return NextResponse.json({ assets: data ?? [] });
}

export async function POST(request: Request) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .select("organization_id")
      .eq("id", user.id)
      .maybeSingle();

    if (profileError) return NextResponse.json({ error: profileError.message }, { status: 500 });
    if (!profile?.organization_id) {
      return NextResponse.json({ error: "Your account is not connected to an organization yet." }, { status: 409 });
    }

    const body = await request.json();
    const name = typeof body.name === "string" ? body.name.trim() : "";
    const assetType = body.assetType as AssetType;
    const provider = typeof body.provider === "string" ? body.provider.trim() || null : null;
    const environment = typeof body.environment === "string" ? body.environment : "production";
    const criticality = typeof body.criticality === "string" ? body.criticality : "medium";

    if (!name) return NextResponse.json({ error: "Asset name is required." }, { status: 400 });
    if (!allowedTypes.includes(assetType)) return NextResponse.json({ error: "Invalid asset type." }, { status: 400 });
    if (!["development", "staging", "production"].includes(environment)) {
      return NextResponse.json({ error: "Invalid environment." }, { status: 400 });
    }
    if (!["low", "medium", "high", "critical"].includes(criticality)) {
      return NextResponse.json({ error: "Invalid criticality." }, { status: 400 });
    }

    const intelligence = onboardingMap[assetType];

    const { data, error } = await supabase
      .from("security_assets")
      .insert({
        organization_id: profile.organization_id,
        name,
        asset_type: assetType,
        provider,
        environment,
        criticality,
        status: "active",
        metadata: {
          onboarding: {
            state: "registered",
            next_step: intelligence.nextStep,
            telemetry: intelligence.telemetry,
            recommended_integrations: intelligence.recommendedIntegrations,
          },
        },
      })
      .select("id,name,asset_type,provider,environment,criticality,status,metadata,last_seen_at,created_at")
      .single();

    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    return NextResponse.json({
      asset: data,
      intelligence: intelligence,
    }, { status: 201 });
  } catch {
    return NextResponse.json({ error: "Invalid request." }, { status: 400 });
  }
}
