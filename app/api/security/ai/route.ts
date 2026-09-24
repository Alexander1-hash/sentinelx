import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

type JsonRecord = Record<string, unknown>;

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

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asObject(value: unknown): JsonRecord {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as JsonRecord
    : {};
}

function indicator(label: string, state: "observed" | "potential" | "unknown", detail: string) {
  return { label, state, detail };
}

export async function GET() {
  try {
    const { supabase, user, organizationId } = await getContext();

    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    if (!organizationId) {
      return NextResponse.json({
        systems: [],
        agents: [],
        events: [],
        indicators: [],
        graphPaths: [],
        summary: {
          systems: 0,
          agents: 0,
          activeAgents: 0,
          autonomousAgents: 0,
          highImpactEvents: 0,
          connectedSystems: 0,
        },
      });
    }

    const [systemsResult, agentsResult, eventsResult, relationshipsResult, assetsResult] = await Promise.all([
      supabase
        .from("ai_security_systems")
        .select("id,asset_id,name,provider,model,system_type,environment,data_classification,status,capabilities,permissions,metadata,created_at,updated_at")
        .eq("organization_id", organizationId)
        .order("updated_at", { ascending: false })
        .limit(500),
      supabase
        .from("ai_security_agents")
        .select("id,system_id,name,purpose,autonomy_level,tools,permissions,data_access,status,created_at,updated_at")
        .eq("organization_id", organizationId)
        .order("updated_at", { ascending: false })
        .limit(500),
      supabase
        .from("ai_security_events")
        .select("id,system_id,agent_id,event_type,severity,title,description,observed_at,evidence")
        .eq("organization_id", organizationId)
        .order("observed_at", { ascending: false })
        .limit(100),
      supabase
        .from("security_asset_relationships")
        .select("id,source_asset_id,target_asset_id,relationship_type,confidence,status,evidence_source")
        .eq("organization_id", organizationId)
        .eq("status", "confirmed")
        .limit(500),
      supabase
        .from("security_assets")
        .select("id,name,asset_type,criticality,status")
        .eq("organization_id", organizationId)
        .limit(500),
    ]);

    const error = systemsResult.error ?? agentsResult.error ?? eventsResult.error ?? relationshipsResult.error ?? assetsResult.error;
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    const systems = systemsResult.data ?? [];
    const agents = agentsResult.data ?? [];
    const events = eventsResult.data ?? [];
    const relationships = relationshipsResult.data ?? [];
    const assets = assetsResult.data ?? [];
    const assetMap = new Map(assets.map((asset) => [asset.id, asset]));

    const graphPaths = systems.flatMap((system) => {\n      if (!system.asset_id) return [];\n      return relationships\n        .filter((edge) => edge.source_asset_id === system.asset_id || edge.target_asset_id === system.asset_id)\n        .map((edge) => ({\n          ...edge,\n          system_name: system.name,\n          source_name: assetMap.get(edge.source_asset_id)?.name ?? "Unknown asset",\n          target_name: assetMap.get(edge.target_asset_id)?.name ?? "Unknown asset",\n        }));\n    });\n\n    const indicators = [
      ...agents
        .filter((agent) => agent.autonomy_level === "autonomous")
        .map((agent) =>
          indicator(
            "Autonomous agent",
            "observed",
            agent.name + " is registered with autonomous execution capability."
          )
        ),
      ...agents
        .filter((agent) => asArray(agent.tools).length > 0)
        .map((agent) =>
          indicator(
            "Tool access",
            "observed",
            agent.name + " has " + asArray(agent.tools).length + " registered tool capability" + (asArray(agent.tools).length === 1 ? "" : "ies") + "."
          )
        ),
      ...agents
        .filter((agent) => asArray(agent.data_access).length > 0)
        .map((agent) =>
          indicator(
            "Data access",
            "observed",
            agent.name + " has registered data-access declarations."
          )
        ),
      ...systems
        .filter((system) => system.data_classification === "confidential" || system.data_classification === "restricted")
        .map((system) =>
          indicator(
            "Sensitive AI data",
            "observed",
            system.name + " is registered with " + system.data_classification + " data classification."
          )
        ),
      ...events
        .filter((event) => event.severity === "high" || event.severity === "critical")
        .map((event) =>
          indicator(
            event.event_type,
            "observed",
            event.title + " was recorded as " + event.severity + " severity."
          )
        ),
    ].slice(0, 40);

    return NextResponse.json({
      systems,
      agents,
      events,
      indicators,
      summary: {
        systems: systems.length,
        agents: agents.length,
        activeAgents: agents.filter((agent) => agent.status === "active").length,
        autonomousAgents: agents.filter((agent) => agent.autonomy_level === "autonomous").length,
        highImpactEvents: events.filter((event) => event.severity === "high" || event.severity === "critical").length,
        connectedSystems: systems.filter((system) => Boolean(system.asset_id)).length,
      },
      boundary: "Inventory and indicators are derived only from registered AI security records and observed AI security events. Missing telemetry is unknown, not safe.",
    });
  } catch {
    return NextResponse.json({ error: "Unable to load AI Security Center." }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const { supabase, user, organizationId } = await getContext();

    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    if (!organizationId) return NextResponse.json({ error: "No organization is connected." }, { status: 400 });

    const body = await request.json();
    const kind = body?.kind;\n\n    if (kind === "analyze") {\n      const [systemsResult, agentsResult, eventsResult, evidenceResult, relationshipsResult] = await Promise.all([\n        supabase.from("ai_security_systems").select("id,name,asset_id,data_classification,status").eq("organization_id", organizationId),\n        supabase.from("ai_security_agents").select("id,name,system_id,autonomy_level,tools,permissions,data_access,status").eq("organization_id", organizationId),\n        supabase.from("ai_security_events").select("id,agent_id,system_id,event_type,severity,title,observed_at,evidence").eq("organization_id", organizationId).order("observed_at", { ascending: false }).limit(200),\n        supabase.from("security_evidence").select("id,asset_id,evidence_type,title,summary,data,observed_at").eq("organization_id", organizationId).order("observed_at", { ascending: false }).limit(200),\n        supabase.from("security_asset_relationships").select("source_asset_id,target_asset_id,relationship_type,confidence,status").eq("organization_id", organizationId).eq("status", "confirmed").limit(500),\n      ]);\n      const error = systemsResult.error ?? agentsResult.error ?? eventsResult.error ?? evidenceResult.error ?? relationshipsResult.error;\n      if (error) return NextResponse.json({ error: error.message }, { status: 500 });\n      const systems = systemsResult.data ?? [];\n      const agents = agentsResult.data ?? [];\n      const events = eventsResult.data ?? [];\n      const evidence = evidenceResult.data ?? [];\n      const relationships = relationshipsResult.data ?? [];\n      const observations = [];\n      for (const agent of agents) {\n        const tools = asArray(agent.tools);\n        const dataAccess = asArray(agent.data_access);\n        if (agent.autonomy_level === "autonomous" && (tools.length || dataAccess.length)) {\n          observations.push({ state: "potential", title: "Autonomous capability requires review", detail: agent.name + " is autonomous and has " + tools.length + " declared tool(s) plus " + dataAccess.length + " declared data scope(s). This is an observed configuration, not proof of unsafe behavior." });\n        }\n        if (!agent.system_id) observations.push({ state: "unknown", title: "Agent system relationship unknown", detail: agent.name + " is registered without a linked AI system." });\n      }\n      for (const system of systems) {\n        if ((system.data_classification === "confidential" || system.data_classification === "restricted") && !system.asset_id) {\n          observations.push({ state: "potential", title: "Sensitive AI system is not graph linked", detail: system.name + " is registered with " + system.data_classification + " data classification but has no linked security asset." });\n        }\n      }\n      const highImpact = events.filter((event) => event.severity === "high" || event.severity === "critical");\n      for (const event of highImpact.slice(0, 20)) observations.push({ state: "observed", title: event.title, detail: "Recorded as " + event.severity + " AI security telemetry." });\n      const sensitiveEvidence = evidence.filter((item) => ["confidential", "restricted"].includes(String(item.data?.data_classification)));\n      const connectedAiEdges = relationships.filter((edge) => ["calls", "reads_from", "writes_to", "uses"].includes(edge.relationship_type));\n      return NextResponse.json({\n        analyzed: true,\n        observations: observations.slice(0, 50),\n        summary: {\n          systems: systems.length, agents: agents.length, highImpactEvents: highImpact.length, sensitiveEvidence: sensitiveEvidence.length, confirmedAiRelevantEdges: connectedAiEdges.length,\n        },\n        boundary: "This posture analysis reports observed configuration, telemetry and confirmed graph relationships. Potential means a condition deserves review; it does not mean compromise or malicious behavior was established.",\n      });\n    }

    if (kind === "system") {
      const name = typeof body.name === "string" ? body.name.trim() : "";
      if (!name) return NextResponse.json({ error: "AI system name is required." }, { status: 400 });

      const { data, error } = await supabase
        .from("ai_security_systems")
        .insert({
          organization_id: organizationId,
          name,
          provider: typeof body.provider === "string" ? body.provider.trim() || null : null,
          model: typeof body.model === "string" ? body.model.trim() || null : null,
          system_type: typeof body.systemType === "string" ? body.systemType : "application",
          environment: typeof body.environment === "string" ? body.environment : "production",
          data_classification: typeof body.dataClassification === "string" ? body.dataClassification : "unknown",
          status: "active",
          capabilities: Array.isArray(body.capabilities) ? body.capabilities : [],
          permissions: asObject(body.permissions),
          metadata: { registration_source: "sentinelx_ai_security_center" },
        })
        .select("id,name,provider,model,system_type,environment,data_classification,status,capabilities,permissions,metadata,created_at,updated_at")
        .single();

      if (error) return NextResponse.json({ error: error.message }, { status: 500 });
      return NextResponse.json({ system: data }, { status: 201 });
    }

    if (kind === "agent") {
      const name = typeof body.name === "string" ? body.name.trim() : "";
      if (!name) return NextResponse.json({ error: "AI agent name is required." }, { status: 400 });

      const { data, error } = await supabase
        .from("ai_security_agents")
        .insert({
          organization_id: organizationId,
          system_id: typeof body.systemId === "string" ? body.systemId : null,
          name,
          purpose: typeof body.purpose === "string" ? body.purpose.trim() || null : null,
          autonomy_level: typeof body.autonomyLevel === "string" ? body.autonomyLevel : "assisted",
          tools: Array.isArray(body.tools) ? body.tools : [],
          permissions: asObject(body.permissions),
          data_access: Array.isArray(body.dataAccess) ? body.dataAccess : [],
          status: "active",
        })
        .select("id,system_id,name,purpose,autonomy_level,tools,permissions,data_access,status,created_at,updated_at")
        .single();

      if (error) return NextResponse.json({ error: error.message }, { status: 500 });
      return NextResponse.json({ agent: data }, { status: 201 });
    }

    return NextResponse.json({ error: "Unsupported AI security registration type." }, { status: 400 });
  } catch {
    return NextResponse.json({ error: "AI security registration failed." }, { status: 500 });
  }
}
