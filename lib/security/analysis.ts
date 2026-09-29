import { createClient } from "@/lib/supabase/server";

type SecurityEvent = {
  id: string;
  asset_id: string | null;
  event_type: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  source: string;
  title: string;
  description: string | null;
  observed_at: string;
  evidence: Record<string, unknown>;
};

type AiSecurityEvent = {
  id: string;
  system_id: string | null;
  agent_id: string | null;
  event_type: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  title: string;
  description: string | null;
  observed_at: string;
  evidence: Record<string, unknown>;
};

type AssetRecord = {
  id: string;
  name: string;
  asset_type: string;
};

type AiAgentRecord = {
  id: string;
  system_id: string | null;
  name: string;
};

type AiSystemRecord = {
  id: string;
  asset_id: string | null;
  name: string;
};

type EvidenceRecord = {
  id: string;
  asset_id: string | null;
  evidence_type: string;
  source: string;
  title: string;
  summary: string | null;
  data: Record<string, unknown>;
  observed_at: string;
};

const severeLevels = new Set(["high", "critical"]);

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

async function collectAnalysisContext(supabase: Awaited<ReturnType<typeof createClient>>, organizationId: string) {
  const [eventsResult, aiEventsResult, evidenceResult, relationshipsResult, findingsResult, assetsResult, agentsResult, systemsResult] = await Promise.all([
    supabase
      .from("security_events")
      .select("id,asset_id,event_type,severity,source,title,description,observed_at,evidence")
      .eq("organization_id", organizationId)
      .order("observed_at", { ascending: false })
      .limit(200),
    supabase
      .from("ai_security_events")
      .select("id,system_id,agent_id,event_type,severity,title,description,observed_at,evidence")
      .eq("organization_id", organizationId)
      .order("observed_at", { ascending: false })
      .limit(200),
    supabase
      .from("security_evidence")
      .select("id,asset_id,evidence_type,source,title,summary,data,observed_at")
      .eq("organization_id", organizationId)
      .order("observed_at", { ascending: false })
      .limit(200),
    supabase
      .from("security_asset_relationships")
      .select("id,source_asset_id,target_asset_id,relationship_type,confidence,status,evidence,evidence_source")
      .eq("organization_id", organizationId)
      .eq("status", "confirmed")
      .limit(500),
    supabase
      .from("security_findings")
      .select("id,title,finding_type,severity,status,evidence")
      .eq("organization_id", organizationId)
      .limit(500),
    supabase
      .from("security_assets")
      .select("id,name,asset_type")
      .eq("organization_id", organizationId)
      .limit(500),
    supabase
      .from("ai_security_agents")
      .select("id,system_id,name")
      .eq("organization_id", organizationId)
      .limit(500),
    supabase
      .from("ai_security_systems")
      .select("id,asset_id,name")
      .eq("organization_id", organizationId)
      .limit(500),
  ]);

  const error = eventsResult.error ?? aiEventsResult.error ?? evidenceResult.error ?? relationshipsResult.error ?? findingsResult.error ?? assetsResult.error ?? agentsResult.error ?? systemsResult.error;
  if (error) throw new Error(error.message);

  const allFindings = findingsResult.data ?? [];
  const openFindings = allFindings.filter((finding) => finding.status === "open" || finding.status === "acknowledged");

  return {
    events: (eventsResult.data ?? []) as SecurityEvent[],
    aiEvents: (aiEventsResult.data ?? []) as AiSecurityEvent[],
    evidence: (evidenceResult.data ?? []) as EvidenceRecord[],
    relationships: relationshipsResult.data ?? [],
    openFindings,
    allFindings,
    assets: (assetsResult.data ?? []) as AssetRecord[],
    agents: (agentsResult.data ?? []) as AiAgentRecord[],
    systems: (systemsResult.data ?? []) as AiSystemRecord[],
  };
}



export async function runSecurityAnalysis(
  supabase: Awaited<ReturnType<typeof createClient>>,
  organizationId: string
) {
    const context = await collectAnalysisContext(supabase, organizationId);

    const severeEvents = context.events.filter((event) => severeLevels.has(event.severity));
    const severeAiEvents = context.aiEvents.filter((event) => severeLevels.has(event.severity));

    const assetMap = new Map(context.assets.map((asset) => [asset.id, asset]));
    const agentMap = new Map(context.agents.map((agent) => [agent.id, agent]));
    const evidenceByAsset = new Map<string, EvidenceRecord[]>();
    for (const item of context.evidence) {
      if (!item.asset_id) continue;
      const existing = evidenceByAsset.get(item.asset_id) ?? [];
      existing.push(item);
      evidenceByAsset.set(item.asset_id, existing);
    }

    const systemMap = new Map(context.systems.map((system) => [system.id, system]));

    const nearbyEvidenceForAsset = (assetId: string | null, observedAt: string) => {
      if (!assetId) return [];

      const eventTime = new Date(observedAt).getTime();
      if (Number.isNaN(eventTime)) return [];

      return (evidenceByAsset.get(assetId) ?? [])
        .filter((item) => {
          const evidenceTime = new Date(item.observed_at).getTime();
          if (Number.isNaN(evidenceTime)) return false;
          return Math.abs(eventTime - evidenceTime) <= 24 * 60 * 60 * 1000;
        })
        .slice(0, 8);
    };

    const explicitAiIndicatorCandidates = context.aiEvents
      .filter((event) => !severeLevels.has(event.severity))
      .flatMap((event) => {
        const combined = [
          event.event_type,
          event.title,
          event.description ?? "",
          JSON.stringify(event.evidence ?? {}),
        ].join(" ").toLowerCase();

        const indicatorDefinitions = [
          {
            matches: /prompt.?injection|jailbreak|instruction.?override|indirect.?prompt/,
            type: "ai_prompt_injection_indicator",
            summary: "AI telemetry contains an explicit prompt-injection or instruction-override indicator. The record establishes an observed indicator, not successful compromise.",
            remediation: "Review the event payload, affected agent context, authorization boundary, and any tool or data activity that followed.",
          },
          {
            matches: /credential.?exposure|secret.?exposure|api.?key|token.?leak|credential.?leak/,
            type: "ai_credential_exposure_indicator",
            summary: "AI telemetry contains an explicit credential or secret exposure indicator. The record does not establish whether the exposed credential was used.",
            remediation: "Validate the exposed secret, identify its scope, and rotate or revoke it through an authorized control if exposure is confirmed.",
          },
          {
            matches: /sensitive.?data|data.?exfiltration|restricted.?data|confidential.?data|data.?leak/,
            type: "ai_sensitive_data_indicator",
            summary: "AI telemetry explicitly references sensitive-data access, transfer, or leakage. Further evidence is required to determine whether unauthorized disclosure occurred.",
            remediation: "Inspect the affected data scope, destination, and authorization context before taking containment action.",
          },
          {
            matches: /permission.?escalation|privilege.?escalation|excessive.?permission|unauthorized.?access|access.?denied/,
            type: "ai_access_control_indicator",
            summary: "AI telemetry contains an explicit access-control or privilege indicator. The record does not establish successful privilege escalation or unauthorized access.",
            remediation: "Review the requested capability, identity or agent authorization, and resulting access before changing permissions.",
          },
        ].filter((indicator) => indicator.matches.test(combined));

        const assetId = event.system_id ? systemMap.get(event.system_id)?.asset_id ?? null : null;

        return indicatorDefinitions.map((indicator) => {
          const correlationKey = "ai-indicator:" + event.id + ":" + indicator.type;

          return {
            correlationKey,
            sourceEventId: event.id,
            assetId,
            title: event.title,
            findingType: indicator.type,
            severity: event.severity,
            summary: indicator.summary,
            remediation: indicator.remediation,
            evidence: {
              source: "ai_security_indicator",
              source_event_id: event.id,
              correlation_key: correlationKey,
              system_id: event.system_id,
              agent_id: event.agent_id,
              event_type: event.event_type,
              observed_at: event.observed_at,
              evidence: event.evidence,
              analysis_boundary: "explicit_ai_indicator",
            },
          };
        });
      });

    const existingKeys = new Set(
      context.allFindings.flatMap((finding) => {
        const evidence = finding.evidence as Record<string, unknown> | null;
        const keys: string[] = [];
        if (typeof evidence?.source_event_id === "string") keys.push(evidence.source_event_id);
        if (typeof evidence?.correlation_key === "string") keys.push(evidence.correlation_key);
        return keys;
      })
    );

    const confirmedRelationships = context.relationships as Array<{
      id: string;
      source_asset_id: string;
      target_asset_id: string;
      relationship_type: string;
      confidence: number | null;
      evidence: Record<string, unknown>;
      evidence_source: string;
    }>;

    // Index confirmed graph edges once so each severe AI event can traverse
    // the same graph without repeatedly scanning the full relationship set.
    const relationshipsBySource = new Map<string, typeof confirmedRelationships>();
    for (const relationship of confirmedRelationships) {
      const existing = relationshipsBySource.get(relationship.source_asset_id) ?? [];
      existing.push(relationship);
      relationshipsBySource.set(relationship.source_asset_id, existing);
    }

    const correlatedCandidates = context.aiEvents
      .filter((event) => severeLevels.has(event.severity) && event.agent_id)
      .flatMap((event) => {
        const agent = event.agent_id ? agentMap.get(event.agent_id) : null;
        const system = agent?.system_id ? systemMap.get(agent.system_id) : null;
        const systemAssetId = system?.asset_id ?? null;
        if (!agent || !systemAssetId) return [];

        const agentCalls = (relationshipsBySource.get(systemAssetId) ?? []).filter(
          (relationship) => relationship.relationship_type === "calls"
        );

        const paths = agentCalls.flatMap((agentCall) =>
          (relationshipsBySource.get(agentCall.target_asset_id) ?? [])
            .filter(
              (relationship) =>
                relationship.relationship_type === "reads_from" ||
                relationship.relationship_type === "writes_to"
            )
            .map((dataEdge) => ({ agentCall, dataEdge }))
        );

        if (!paths.length) return [];

        const dataAssetIds = new Set(
          paths
            .map(({ dataEdge }) => dataEdge.target_asset_id)
            .filter((assetId) => assetMap.has(assetId))
        );

        const sensitiveEvidence = Array.from(dataAssetIds).flatMap((assetId) => {
          const nearbyEvidence = nearbyEvidenceForAsset(assetId, event.observed_at);

          return nearbyEvidence.filter((item) => {
            const severity = item.data?.severity;
            const classification = item.data?.data_classification;
            return (
              severity === "high" ||
              severity === "critical" ||
              classification === "confidential" ||
              classification === "restricted"
            );
          });
        });

        const pathKey = paths
          .map(({ agentCall, dataEdge }) => agentCall.target_asset_id + ":" + dataEdge.target_asset_id + ":" + dataEdge.relationship_type)
          .sort()
          .join("|");
        const correlationKey = "ai-path:" + event.id + ":" + pathKey;
        const firstPath = paths[0];
        const apiAsset = assetMap.get(firstPath.agentCall.target_asset_id);
        const dataAsset = assetMap.get(firstPath.dataEdge.target_asset_id);

        return [{
          correlationKey,
          sourceEventId: event.id,
          assetId: systemAssetId,
          title: agent.name + " activity reaches a connected data path",
          findingType: "ai_attack_path_correlation",
          severity: event.severity,
          summary: event.title + " was observed on " + agent.name + ", and the confirmed Security Graph shows a path through " + (apiAsset?.name ?? "a connected API") + " to " + (dataAsset?.name ?? "a connected data asset") + "." + (sensitiveEvidence.length ? " Sensitive or high-impact evidence is also associated with the downstream data asset." : ""),
          remediation: "Review the agent event, validate the confirmed path, inspect the downstream data access, and restrict or revoke unauthorized capability only after authorized review.",
          evidence: {
            source: "security_brain_correlation",
            correlation_key: correlationKey,
            source_event_id: event.id,
            agent_id: agent.id,
            system_id: system?.id ?? null,
            confirmed_path: paths.slice(0, 10).map(({ agentCall, dataEdge }) => ({
              agent_asset_id: systemAssetId,
              api_asset_id: agentCall.target_asset_id,
              data_asset_id: dataEdge.target_asset_id,
              api_relationship: agentCall.relationship_type,
              data_relationship: dataEdge.relationship_type,
              confidence: Math.min(agentCall.confidence ?? 0, dataEdge.confidence ?? 0),
            })),
            sensitive_evidence_ids: sensitiveEvidence.map((item) => item.id),
            analysis_boundary: "correlated_observed_event_with_confirmed_graph",
          },
        }];
      })
      .filter((candidate) => !existingKeys.has(candidate.correlationKey));

    const candidates = [
      ...correlatedCandidates,
      ...explicitAiIndicatorCandidates,
      ...severeEvents.map((event) => {
        const nearbyEvidence = nearbyEvidenceForAsset(event.asset_id, event.observed_at);

        return {
          sourceEventId: event.id,
          assetId: event.asset_id,
          title: event.title,
          findingType: `security_event:${event.event_type}`,
          severity: event.severity,
          summary:
            (event.description ?? "A high-impact security event was observed and requires investigation.") +
            (nearbyEvidence.length
              ? ` Trinorin also found ${nearbyEvidence.length} evidence record(s) on the affected asset within 24 hours of this event; this is supporting context, not proof of causation.`
              : ""),
          remediation: "Review the source evidence, validate the affected asset, and apply an authorized remediation appropriate to the event.",
          evidence: {
            source: "security_event",
            source_event_id: event.id,
            event_type: event.event_type,
            event_source: event.source,
            observed_at: event.observed_at,
            evidence: event.evidence,
            nearby_evidence: nearbyEvidence.map((item) => ({
              id: item.id,
              evidence_type: item.evidence_type,
              source: item.source,
              title: item.title,
              observed_at: item.observed_at,
            })),
            analysis_boundary: "observed_event_with_temporal_evidence_context",
          },
        };
      }),
      ...severeAiEvents.map((event) => {
        const assetId = event.system_id ? systemMap.get(event.system_id)?.asset_id ?? null : null;
        const nearbyEvidence = nearbyEvidenceForAsset(assetId, event.observed_at);

        return {
          sourceEventId: event.id,
          assetId,
          title: event.title,
          findingType: `ai_security_event:${event.event_type}`,
          severity: event.severity,
          summary:
            (event.description ?? "A high-impact AI security event was observed and requires investigation.") +
            (nearbyEvidence.length
              ? ` Trinorin also found ${nearbyEvidence.length} evidence record(s) on the affected AI asset within 24 hours of this event; this is supporting context, not proof of causation.`
              : ""),
          remediation: "Review the AI system or agent evidence, validate the behavior, and apply an authorized remediation appropriate to the event.",
          evidence: {
            source: "ai_security_event",
            source_event_id: event.id,
            system_id: event.system_id,
            agent_id: event.agent_id,
            event_type: event.event_type,
            observed_at: event.observed_at,
            evidence: event.evidence,
            nearby_evidence: nearbyEvidence.map((item) => ({
              id: item.id,
              evidence_type: item.evidence_type,
              source: item.source,
              title: item.title,
              observed_at: item.observed_at,
            })),
            analysis_boundary: "observed_ai_event_with_temporal_evidence_context",
          },
        };
      }),
    ].filter((candidate) => {
      const candidateKey =
        "correlationKey" in candidate && typeof candidate.correlationKey === "string"
          ? candidate.correlationKey
          : candidate.sourceEventId;
      return !existingKeys.has(candidateKey);
    });

    const uniqueCandidates = Array.from(
      new Map(
        candidates.map((candidate) => {
          const candidateKey =
            "correlationKey" in candidate && typeof candidate.correlationKey === "string"
              ? candidate.correlationKey
              : `${candidate.findingType}:${candidate.sourceEventId}:${candidate.assetId ?? "none"}`;

          return [candidateKey, candidate] as const;
        })
      ).values()
    );

    let findingsCreated = 0;
    const createdFindings: Array<{ id: string; title: string; severity: string }> = [];

    for (const candidate of uniqueCandidates) {
      const { data: createdFinding, error } = await supabase
        .from("security_findings")
        .insert({
          organization_id: organizationId,
          asset_id: candidate.assetId,
          title: candidate.title,
          finding_type: candidate.findingType,
          severity: candidate.severity,
          status: "open",
          summary: candidate.summary,
          evidence: candidate.evidence,
          remediation: candidate.remediation,
          detected_at: new Date().toISOString(),
        })
        .select("id")
        .single();

      if (error || !createdFinding?.id) {
        throw new Error(error?.message ?? "Finding could not be created.");
      }

      findingsCreated += 1;
      createdFindings.push({ id: createdFinding.id, title: candidate.title, severity: candidate.severity });

      const { error: memoryError } = await supabase.from("security_memory").insert({
        organization_id: organizationId,
        memory_type: "finding_state",
        subject_id: createdFinding.id,
        title: `New finding: ${candidate.title}`,
        summary: candidate.summary,
        state: "open",
        data: {
          finding_id: createdFinding.id,
          finding_type: candidate.findingType,
          severity: candidate.severity,
          source_event_id: candidate.sourceEventId,
          asset_id: candidate.assetId,
          evidence: candidate.evidence,
          memory_reason: "finding_created_from_evidence",
        },
      });

      if (memoryError) {
        throw new Error(memoryError.message);
      }
    }

    const highImpactEvidence = context.evidence.filter((item) => item.data?.severity === "high" || item.data?.severity === "critical").length;

    return {
      analyzed: true,
      findingsCreated,
      findings: createdFindings,
      context: {
        securityEvents: context.events.length,
        highImpactSecurityEvents: severeEvents.length,
        aiSecurityEvents: context.aiEvents.length,
        highImpactAiSecurityEvents: severeAiEvents.length,
        evidenceRecords: context.evidence.length,
        highImpactEvidenceRecords: highImpactEvidence,
        confirmedRelationships: context.relationships.length,
      },
      message: findingsCreated
        ? `${findingsCreated} evidence-backed finding${findingsCreated === 1 ? "" : "s"} created from observed high-impact events or explicit AI security indicators. Unverified relationships and missing telemetry were excluded.`
        : "Analysis completed. No new evidence-backed high-impact findings were created.",
    };
}
