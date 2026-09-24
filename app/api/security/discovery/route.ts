import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

type Asset = {
  id: string;
  name: string;
  asset_type: string;
  provider: string | null;
  environment: string | null;
  criticality: string | null;
  metadata: Record<string, unknown> | null;
};

type Candidate = {
  sourceAssetId: string;
  targetAssetId: string;
  relationshipType: string;
  confidence: number;
  reason: string;
  rule: string;
};

const pairRules: Array<{
  source: string;
  target: string;
  relationshipType: string;
  confidence: number;
  rule: string;
  reason: string;
}> = [
  {
    source: "website",
    target: "domain",
    relationshipType: "resolves_to",
    confidence: 0.95,
    rule: "website_domain_pair",
    reason: "A registered website and domain form a deterministic application-to-domain relationship candidate.",
  },
  {
    source: "domain",
    target: "website",
    relationshipType: "hosts",
    confidence: 0.9,
    rule: "domain_website_pair",
    reason: "A registered domain and website form a deterministic domain-to-application relationship candidate.",
  },
  {
    source: "ai_system",
    target: "ai_agent",
    relationshipType: "uses",
    confidence: 0.9,
    rule: "ai_system_agent_pair",
    reason: "An AI system and AI agent registered in the same security surface are a candidate for an AI system-to-agent relationship.",
  },
  {
    source: "ai_agent",
    target: "ai_system",
    relationshipType: "part_of",
    confidence: 0.85,
    rule: "ai_agent_system_pair",
    reason: "An AI agent can be part of a registered AI system; SentinelX keeps this as a reviewable candidate.",
  },
  {
    source: "ai_agent",
    target: "api",
    relationshipType: "calls",
    confidence: 0.8,
    rule: "ai_agent_api_pair",
    reason: "AI agents commonly invoke APIs, but SentinelX requires evidence or operator confirmation before treating the relationship as confirmed.",
  },
  {
    source: "api",
    target: "database",
    relationshipType: "reads_from",
    confidence: 0.75,
    rule: "api_database_pair",
    reason: "An API and database can form a read path, but telemetry is required to establish the actual data flow.",
  },
  {
    source: "api",
    target: "database",
    relationshipType: "writes_to",
    confidence: 0.7,
    rule: "api_database_write_pair",
    reason: "An API and database can form a write path, but telemetry is required to establish the actual data flow.",
  },
  {
    source: "identity",
    target: "ai_agent",
    relationshipType: "authenticates_to",
    confidence: 0.7,
    rule: "identity_ai_agent_pair",
    reason: "Identity systems may authenticate AI agents or their operators; SentinelX keeps this as a candidate until evidence is available.",
  },
  {
    source: "cloud",
    target: "endpoint",
    relationshipType: "managed_by",
    confidence: 0.65,
    rule: "cloud_endpoint_pair",
    reason: "Cloud management and endpoint inventory can be related, but provider telemetry is needed for confirmation.",
  },
  {
    source: "cloud",
    target: "database",
    relationshipType: "hosts",
    confidence: 0.65,
    rule: "cloud_database_pair",
    reason: "Cloud infrastructure may host a database, but infrastructure telemetry is required for confirmation.",
  },
];

function pairKey(sourceAssetId: string, targetAssetId: string, relationshipType: string) {
  return `${sourceAssetId}:${targetAssetId}:${relationshipType}`;
}

function buildCandidates(assets: Asset[]): Candidate[] {
  const candidates: Candidate[] = [];
  const seen = new Set<string>();

  for (const rule of pairRules) {
    const sources = assets.filter((asset) => asset.asset_type === rule.source);
    const targets = assets.filter((asset) => asset.asset_type === rule.target);

    for (const source of sources) {
      for (const target of targets) {
        if (source.id === target.id) continue;

        const key = pairKey(source.id, target.id, rule.relationshipType);
        if (seen.has(key)) continue;

        seen.add(key);
        candidates.push({
          sourceAssetId: source.id,
          targetAssetId: target.id,
          relationshipType: rule.relationshipType,
          confidence: rule.confidence,
          reason: rule.reason,
          rule: rule.rule,
        });
      }
    }
  }

  return candidates;
}

export async function POST() {
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

    const organizationId = profile?.organization_id ?? null;

    if (!organizationId) {
      return NextResponse.json(
        { error: "Your account is not connected to an organization yet." },
        { status: 409 }
      );
    }

    const { data: assets, error: assetsError } = await supabase
      .from("security_assets")
      .select("id,name,asset_type,provider,environment,criticality,metadata")
      .eq("organization_id", organizationId);

    if (assetsError) {
      return NextResponse.json({ error: assetsError.message }, { status: 500 });
    }

    const typedAssets = (assets ?? []) as Asset[];
    const candidates = buildCandidates(typedAssets);

    if (!candidates.length) {
      return NextResponse.json({
        scannedAssets: typedAssets.length,
        candidatesCreated: 0,
        message: "No deterministic relationship candidates were found from the registered asset types.",
      });
    }

    const { data: existing, error: existingError } = await supabase
      .from("security_asset_relationships")
      .select("source_asset_id,target_asset_id,relationship_type,status")
      .eq("organization_id", organizationId);

    if (existingError) {
      return NextResponse.json({ error: existingError.message }, { status: 500 });
    }

    const existingKeys = new Set(
      (existing ?? []).map((item) =>
        pairKey(item.source_asset_id, item.target_asset_id, item.relationship_type)
      )
    );

    const newCandidates = candidates.filter(
      (candidate) =>
        !existingKeys.has(
          pairKey(candidate.sourceAssetId, candidate.targetAssetId, candidate.relationshipType)
        )
    );

    if (!newCandidates.length) {
      return NextResponse.json({
        scannedAssets: typedAssets.length,
        candidatesCreated: 0,
        candidatesEvaluated: candidates.length,
        message: "The Security Brain already has records for all currently discoverable relationships.",
      });
    }

    const now = new Date().toISOString();

    const rows = newCandidates.map((candidate) => ({
      organization_id: organizationId,
      source_asset_id: candidate.sourceAssetId,
      target_asset_id: candidate.targetAssetId,
      relationship_type: candidate.relationshipType,
      confidence: candidate.confidence,
      status: "proposed",
      evidence_source: "deterministic_discovery",
      discovered_at: now,
      evidence: {
        source: "deterministic_discovery",
        rule: candidate.rule,
        reason: candidate.reason,
        generated_at: now,
        boundary: "candidate_only",
      },
    }));

    const { data: created, error: insertError } = await supabase
      .from("security_asset_relationships")
      .insert(rows)
      .select("id,source_asset_id,target_asset_id,relationship_type,status,confidence,evidence_source");

    if (insertError) {
      return NextResponse.json({ error: insertError.message }, { status: 500 });
    }

    return NextResponse.json({
      scannedAssets: typedAssets.length,
      candidatesEvaluated: candidates.length,
      candidatesCreated: created?.length ?? 0,
      candidates: created ?? [],
      message: "Deterministic relationship candidates were created for Security Brain review. No relationship was auto-confirmed.",
    }, { status: 201 });
  } catch {
    return NextResponse.json(
      { error: "Unable to run Security Brain relationship discovery." },
      { status: 500 }
    );
  }
}
