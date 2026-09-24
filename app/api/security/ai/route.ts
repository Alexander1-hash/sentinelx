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

  return { supabase, user, organizationId: profile?.organization_id ?? null };
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

function textValue(value: unknown): string {
  return typeof value === "string" ? value.toLowerCase() : "";
}

function detectThreats(events: any[], agents: any[], systems: any[], evidence: any[]) {
  const detections: Array<{
    state: "observed" | "potential";
    category: string;
    title: string;
    detail: string;
    evidenceIds: string[];
    eventIds: string[];
    recommendedNextStep: string;
  }> = [];

  const push = (item: typeof detections[number]) => {
    if (detections.length < 60) detections.push(item);
  };

  for (const event of events) {
    const eventType = textValue(event.event_type);
    const title = textValue(event.title);
    const description = textValue(event.description);
    const evidenceText = JSON.stringify(event.evidence ?? {}).toLowerCase();
    const combined = eventType + " " + title + " " + description + " " + evidenceText;
    const eventIds = [event.id];
    const evidenceIds = Array.isArray(event.evidence?.evidence_ids) ? event.evidence.evidence_ids.filter((id: unknown) => typeof id === "string") : [];

    if (/(prompt.?injection|jailbreak|instruction.?override|indirect.?prompt)/.test(combined)) {
      push({
        state: "observed",
        category: "Prompt injection",
        title: event.title,
        detail: "Recorded AI telemetry contains an explicit prompt-injection or instruction-override indicator. This establishes an observed indicator, not successful compromise.",
        evidenceIds,
        eventIds,
        recommendedNextStep: "Review the event payload, affected agent context and any tool/data activity immediately following it.",
      });
    }

    if (/(credential.?exposure|secret.?exposure|api.?key|token.?leak|credential.?leak)/.test(combined)) {
      push({
        state: "observed",
        category: "Credential exposure",
        title: event.title,
        detail: "Recorded AI telemetry contains an explicit credential or secret exposure indicator. The record does not by itself establish whether the credential was successfully used.",
        evidenceIds,
        eventIds,
        recommendedNextStep: "Validate the exposed secret, identify its scope and rotate or revoke it through an authorized control if exposure is confirmed.",
      });
    }

    if (/(sensitive.?data|data.?exfiltration|restricted.?data|confidential.?data|data.?leak)/.test(combined)) {
      push({
        state: "observed",
        category: "Sensitive-data activity",
        title: event.title,
        detail: "Recorded AI telemetry explicitly references sensitive-data access, transfer or leakage. Further evidence is required to determine whether unauthorized disclosure occurred.",
        evidenceIds,
        eventIds,
        recommendedNextStep: "Inspect the affected data scope, destination and authorization context before taking containment action.",
      });
    }

    if (/(tool.?call|function.?call|plugin.?call|mcp)/.test(eventType + " " + title)) {
      push({
        state: "observed",
        category: "Tool activity",
        title: event.title,
        detail: "AI telemetry records tool, function, plugin or MCP-style activity. Tool activity is not inherently malicious; review the target, authorization and resulting data access.",
        evidenceIds,
        eventIds,
        recommendedNextStep: "Review the called tool, target, agent authorization and downstream effects.",
      });
    }

    if (/(permission.?escalation|privilege.?escalation|excessive.?permission|unauthorized.?access|access.?denied)/.test(combined)) {
      push({
        state: "observed",
        category: "Access-control indicator",
        title: event.title,
        detail: "Recorded telemetry contains an explicit access-control or privilege indicator. The record does not establish that privilege escalation succeeded.",
        evidenceIds,
        eventIds,
        recommendedNextStep: "Verify the requested permission against the agent's authorized scope and review the resulting identity activity.",
      });
    }
  }

  for (const agent of agents) {
    const tools = asArray(agent.tools);
    const dataAccess = asArray(agent.data_access);
    if (agent.autonomy_level === "autonomous" && tools.length > 0 && dataAccess.length > 0) {
      push({
        state: "potential",
        category: "Autonomous capability",
        title: agent.name + " has autonomous tool and data capability",
        detail: "The registered configuration gives this agent autonomous execution capability together with declared tools and data scopes. This is a review condition, not proof of unsafe behavior.",
        evidenceIds: [],
        eventIds: [],
        recommendedNextStep: "Validate least privilege, tool allowlists, data scopes and human approval requirements for high-impact operations.",
      });
    }
  }

  for (const system of systems) {
    if ((system.data_classification === "confidential" || system.data_classification === "restricted") && !system.asset_id) {
      push({
        state: "potential",
        category: "AI asset visibility",
        title: system.name + " is not graph linked",
        detail: "A sensitive AI system is registered without a linked security asset. SentinelX cannot establish its confirmed relationship to infrastructure or data from this record alone.",
        evidenceIds: [],
        eventIds: [],
        recommendedNextStep: "Link the AI system to the correct authorized security asset and connect telemetry.",
      });
    }
  }

  const explicitShadow = evidence.filter((item) => {
    const combined = (textValue(item.evidence_type) + " " + textValue(item.title) + " " + textValue(item.summary) + " " + JSON.stringify(item.data ?? {}).toLowerCase());
    return /shadow.?ai|unregistered.?ai|unknown.?ai/.test(combined);
  });
  for (const item of explicitShadow.slice(0, 10)) {
    push({
      state: "observed",
      category: "Shadow AI",
      title: item.title,
      detail: "Evidence explicitly identifies unregistered or unknown AI activity. This does not identify the operator or prove malicious intent.",
      evidenceIds: [item.id],
      eventIds: [],
      recommendedNextStep: "Identify the authorized owner, data scope and provider before deciding whether the system should be approved or contained.",
    });
  }

  return detections;
}

export async function GET() {
  try {
    const { supabase, user, organizationId } = await getContext();
    if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    if (!organizationId) return NextResponse.json({
      systems: [], agents: [], events: [], indicators: [], graphPaths: [],
      summary: { systems: 0, agents: 0, activeAgents: 0, autonomousAgents: 0, highImpactEvents: 0, connectedSystems: 0 },
    });

    const [systemsResult, agentsResult, eventsResult, relationshipsResult, assetsResult] = await Promise.all([
      supabase.from("ai_security_systems").select("id,asset_id,name,provider,model,system_type,environment,data_classification,status,capabilities,permissions,metadata,created_at,updated_at").eq("organization_id", organizationId).order("updated_at", { ascending: false }).limit(500),
      supabase.from("ai_security_agents").select("id,system_id,name,purpose,autonomy_level,tools,permissions,data_access,status,created_at,updated_at").eq("organization_id", organizationId).order("updated_at", { ascending: false }).limit(500),
      supabase.from("ai_security_events").select("id,system_id,agent_id,event_type,severity,title,description,observed_at,evidence").eq("organization_id", organizationId).order("observed_at", { ascending: false }).limit(100),
      supabase.from("security_asset_relationships").select("id,source_asset_id,target_asset_id,relationship_type,confidence,status,evidence_source").eq("organization_id", organizationId).eq("status", "confirmed").limit(500),
      supabase.from("security_assets").select("id,name,asset_type,criticality,status").eq("organization_id", organizationId).limit(500),
    ]);

    const error = systemsResult.error ?? agentsResult.error ?? eventsResult.error ?? relationshipsResult.error ?? assetsResult.error;
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    const systems = systemsResult.data ?? [];
    const agents = agentsResult.data ?? [];
    const events = eventsResult.data ?? [];
    const relationships = relationshipsResult.data ?? [];
    const assets = assetsResult.data ?? [];
    const assetMap = new Map(assets.map((asset) => [asset.id, asset]));

    const graphPaths = systems.flatMap((system) => {
      if (!system.asset_id) return [];
      return relationships.filter((edge) => edge.source_asset_id === system.asset_id || edge.target_asset_id === system.asset_id).map((edge) => ({
        ...edge,
        system_name: system.name,
        source_name: assetMap.get(edge.source_asset_id)?.name ?? "Unknown asset",
        target_name: assetMap.get(edge.target_asset_id)?.name ?? "Unknown asset",
      }));
    });

    const indicators = [
      ...agents.filter((agent) => agent.autonomy_level === "autonomous").map((agent) => indicator("Autonomous agent", "observed", agent.name + " is registered with autonomous execution capability.")),
      ...agents.filter((agent) => asArray(agent.tools).length > 0).map((agent) => indicator("Tool access", "observed", agent.name + " has " + asArray(agent.tools).length + " registered tool capability" + (asArray(agent.tools).length === 1 ? "" : "ies") + ".")),
      ...agents.filter((agent) => asArray(agent.data_access).length > 0).map((agent) => indicator("Data access", "observed", agent.name + " has registered data-access declarations.")),
      ...systems.filter((system) => system.data_classification === "confidential" || system.data_classification === "restricted").map((system) => indicator("Sensitive AI data", "observed", system.name + " is registered with " + system.data_classification + " data classification.")),
      ...events.filter((event) => event.severity === "high" || event.severity === "critical").map((event) => indicator(event.event_type, "observed", event.title + " was recorded as " + event.severity + " severity.")),
    ].slice(0, 40);

    return NextResponse.json({
      systems, agents, events, indicators, graphPaths,
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
    const kind = body?.kind;

    if (kind === "detect") {
      const [systemsResult, agentsResult, eventsResult, evidenceResult] = await Promise.all([
        supabase.from("ai_security_systems").select("id,name,asset_id,data_classification,status").eq("organization_id", organizationId),
        supabase.from("ai_security_agents").select("id,name,system_id,autonomy_level,tools,permissions,data_access,status").eq("organization_id", organizationId),
        supabase.from("ai_security_events").select("id,agent_id,system_id,event_type,severity,title,description,observed_at,evidence").eq("organization_id", organizationId).order("observed_at", { ascending: false }).limit(300),
        supabase.from("security_evidence").select("id,evidence_type,title,summary,data,observed_at").eq("organization_id", organizationId).order("observed_at", { ascending: false }).limit(300),
      ]);
      const error = systemsResult.error ?? agentsResult.error ?? eventsResult.error ?? evidenceResult.error;
      if (error) return NextResponse.json({ error: error.message }, { status: 500 });

      const systems = systemsResult.data ?? [];
      const agents = agentsResult.data ?? [];
      const events = eventsResult.data ?? [];
      const evidence = evidenceResult.data ?? [];
      const detections = detectThreats(events, agents, systems, evidence);

      return NextResponse.json({
        detected: true,
        detections,
        summary: {
          total: detections.length,
          observed: detections.filter((item) => item.state === "observed").length,
          potential: detections.filter((item) => item.state === "potential").length,
        },
        boundary: "Detections are derived from explicit registered configuration, telemetry and evidence. Potential indicates a condition for review; it is not proof of compromise or malicious behavior. No response action is executed by detection.",
      });
    }

    if (kind === "analyze") {
      const [systemsResult, agentsResult, eventsResult, evidenceResult, relationshipsResult] = await Promise.all([
        supabase.from("ai_security_systems").select("id,name,asset_id,data_classification,status").eq("organization_id", organizationId),
        supabase.from("ai_security_agents").select("id,name,system_id,autonomy_level,tools,permissions,data_access,status").eq("organization_id", organizationId),
        supabase.from("ai_security_events").select("id,agent_id,system_id,event_type,severity,title,observed_at,evidence").eq("organization_id", organizationId).order("observed_at", { ascending: false }).limit(200),
        supabase.from("security_evidence").select("id,asset_id,evidence_type,title,summary,data,observed_at").eq("organization_id", organizationId).order("observed_at", { ascending: false }).limit(200),
        supabase.from("security_asset_relationships").select("source_asset_id,target_asset_id,relationship_type,confidence,status").eq("organization_id", organizationId).eq("status", "confirmed").limit(500),
      ]);
      const error = systemsResult.error ?? agentsResult.error ?? eventsResult.error ?? evidenceResult.error ?? relationshipsResult.error;
      if (error) return NextResponse.json({ error: error.message }, { status: 500 });
      const systems = systemsResult.data ?? [];
      const agents = agentsResult.data ?? [];
      const events = eventsResult.data ?? [];
      const evidence = evidenceResult.data ?? [];
      const relationships = relationshipsResult.data ?? [];
      const observations: Array<{ state: string; title: string; detail: string }> = [];
      for (const agent of agents) {
        const tools = asArray(agent.tools);
        const dataAccess = asArray(agent.data_access);
        if (agent.autonomy_level === "autonomous" && (tools.length || dataAccess.length)) observations.push({ state: "potential", title: "Autonomous capability requires review", detail: agent.name + " is autonomous and has " + tools.length + " declared tool(s) plus " + dataAccess.length + " declared data scope(s). This is an observed configuration, not proof of unsafe behavior." });
        if (!agent.system_id) observations.push({ state: "unknown", title: "Agent system relationship unknown", detail: agent.name + " is registered without a linked AI system." });
      }
      for (const system of systems) if ((system.data_classification === "confidential" || system.data_classification === "restricted") && !system.asset_id) observations.push({ state: "potential", title: "Sensitive AI system is not graph linked", detail: system.name + " is registered with " + system.data_classification + " data classification but has no linked security asset." });
      const highImpact = events.filter((event) => event.severity === "high" || event.severity === "critical");
      for (const event of highImpact.slice(0, 20)) observations.push({ state: "observed", title: event.title, detail: "Recorded as " + event.severity + " AI security telemetry." });
      const sensitiveEvidence = evidence.filter((item) => ["confidential", "restricted"].includes(String(item.data?.data_classification)));
      const connectedAiEdges = relationships.filter((edge) => ["calls", "reads_from", "writes_to", "uses"].includes(edge.relationship_type));
      return NextResponse.json({
        analyzed: true,
        observations: observations.slice(0, 50),
        summary: { systems: systems.length, agents: agents.length, highImpactEvents: highImpact.length, sensitiveEvidence: sensitiveEvidence.length, confirmedAiRelevantEdges: connectedAiEdges.length },
        boundary: "This posture analysis reports observed configuration, telemetry and confirmed graph relationships. Potential means a condition deserves review; it does not mean compromise or malicious behavior was established.",
      });
    }

    if (kind === "system") {
      const name = typeof body.name === "string" ? body.name.trim() : "";
      if (!name) return NextResponse.json({ error: "AI system name is required." }, { status: 400 });
      const { data, error } = await supabase.from("ai_security_systems").insert({
        organization_id: organizationId, name,
        provider: typeof body.provider === "string" ? body.provider.trim() || null : null,
        model: typeof body.model === "string" ? body.model.trim() || null : null,
        system_type: typeof body.systemType === "string" ? body.systemType : "application",
        environment: typeof body.environment === "string" ? body.environment : "production",
        data_classification: typeof body.dataClassification === "string" ? body.dataClassification : "unknown",
        status: "active", capabilities: Array.isArray(body.capabilities) ? body.capabilities : [],
        permissions: asObject(body.permissions), metadata: { registration_source: "sentinelx_ai_security_center" },
      }).select("id,name,provider,model,system_type,environment,data_classification,status,capabilities,permissions,metadata,created_at,updated_at").single();
      if (error) return NextResponse.json({ error: error.message }, { status: 500 });
      return NextResponse.json({ system: data }, { status: 201 });
    }

    if (kind === "agent") {
      const name = typeof body.name === "string" ? body.name.trim() : "";
      if (!name) return NextResponse.json({ error: "AI agent name is required." }, { status: 400 });
      const { data, error } = await supabase.from("ai_security_agents").insert({
        organization_id: organizationId, system_id: typeof body.systemId === "string" ? body.systemId : null,
        name, purpose: typeof body.purpose === "string" ? body.purpose.trim() || null : null,
        autonomy_level: typeof body.autonomyLevel === "string" ? body.autonomyLevel : "assisted",
        tools: Array.isArray(body.tools) ? body.tools : [], permissions: asObject(body.permissions),
        data_access: Array.isArray(body.dataAccess) ? body.dataAccess : [], status: "active",
      }).select("id,system_id,name,purpose,autonomy_level,tools,permissions,data_access,status,created_at,updated_at").single();
      if (error) return NextResponse.json({ error: error.message }, { status: 500 });
      return NextResponse.json({ agent: data }, { status: 201 });
    }

    return NextResponse.json({ error: "Unsupported AI security registration type." }, { status: 400 });
  } catch {
    return NextResponse.json({ error: "AI security operation failed." }, { status: 500 });
  }
}
