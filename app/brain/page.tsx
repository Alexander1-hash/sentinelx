"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Boxes, BrainCircuit, CircleDashed, GitBranch, History, Loader2, ShieldCheck, Sparkles, MessageSquare } from "lucide-react";

type Asset = {
  id: string;
  name: string;
  asset_type: string;
  provider: string | null;
  environment: string;
  criticality: string;
  status: string;
  metadata: { onboarding?: { telemetry?: string } } | null;
};

type Finding = {
  id: string;
  asset_id: string | null;
  title: string;
  finding_type: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "open" | "acknowledged" | "resolved" | "dismissed";
  summary: string | null;
  remediation: string | null;
  detected_at: string;
};

type Relationship = {
  id: string;
  source_asset_id: string;
  target_asset_id: string;
  relationship_type: string;
  confidence: number | null;
  status: "proposed" | "confirmed" | "rejected";
  evidence: Record<string, unknown>;
  evidence_source: string;
  created_at: string;
};

type AttackPathHop = {
  asset: {
    id: string;
    name: string;
    asset_type: string;
    criticality: string;
  };
  relationship: string;
  confidence: number | null;
};

type AttackPath = {
  id: string;
  source: AttackPathHop["asset"];
  target: AttackPathHop["asset"];
  hops: AttackPathHop[];
  confidence: number;
  rationale: string;
};

export default function SecurityBrainPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [relationships, setRelationships] = useState<Relationship[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");
  const [reviewingId, setReviewingId] = useState("");
  const [discovering, setDiscovering] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [attackPathLoading, setAttackPathLoading] = useState(true);
  const [patterns, setPatterns] = useState<Array<{ id: string; pattern: string; title: string; detail: string; confidence: string; memoryIds: string[]; firstObserved: string; lastObserved: string; boundary: string; sequence?: string[] }>>([]);
  const [patternLoading, setPatternLoading] = useState(true);
  const [copilotFindingId, setCopilotFindingId] = useState("");
  const [copilotAnswer, setCopilotAnswer] = useState("");
  const [copilotResultFindingId, setCopilotResultFindingId] = useState("");
  const [responsePlanFindingId, setResponsePlanFindingId] = useState("");
  const [copilotInvestigation, setCopilotInvestigation] = useState<{
    affectedAsset: { name: string; asset_type: string; criticality: string | null; status: string } | null;
    blastRadius: Array<{ asset: { name: string; asset_type: string; criticality: string | null; status: string }; hops: number; confidence: number; chain: string[] }>;
    supportingEvidence: Array<{ id: string; title: string; source: string; summary: string | null; observed_at: string }>;
    unknowns: string[];
    memory: Array<{ memory_type: string; title: string; summary: string; state: string; occurred_at: string }>;
    responseOutcomes: Array<{
      occurred_at: string;
      title: string;
      summary: string;
      state: string;
      action_id: string | null;
      action_type: string | null;
      executor_type: string | null;
      execution_reference: string | null;
      evidence: unknown[];
    }>;
  } | null>(null);

  const [verificationLoading, setVerificationLoading] = useState(false);
  const [verificationChanges, setVerificationChanges] = useState<Array<{
    id: string;
    title: string;
    detail: string;
    observedAt: string;
    verificationState?: "improved" | "observed" | "uncertain" | "awaiting_evidence";
  }>>([]);
  const [verificationFindingId, setVerificationFindingId] = useState("");

  useEffect(() => {
    const findingId = new URLSearchParams(window.location.search).get("findingId");
    if (!findingId) return;

    setVerificationFindingId(findingId);
    setVerificationLoading(true);

    void fetch("/api/security/changes?findingId=" + encodeURIComponent(findingId), { cache: "no-store" })
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.error ?? "Unable to load response verification.");
        setVerificationChanges(
          Array.isArray(data.changes)
            ? data.changes
                .filter((change: { kind?: string }) => change.kind === "verification")
                .map((change: { id: string; title: string; detail: string; observedAt: string; verificationState?: "improved" | "observed" | "uncertain" | "awaiting_evidence" }) => ({
                  id: change.id,
                  title: change.title,
                  detail: change.detail,
                  observedAt: change.observedAt,
                  verificationState: change.verificationState,
                }))
            : []
        );
      })
      .catch(() => setMessage("Response verification is temporarily unavailable."))
      .finally(() => setVerificationLoading(false));
  }, []);

  const [sourceAssetId, setSourceAssetId] = useState("");
  const [targetAssetId, setTargetAssetId] = useState("");
  const [relationshipType, setRelationshipType] = useState("depends_on");
  const [addingRelationship, setAddingRelationship] = useState(false);

  async function loadGraph() {
    setLoading(true);
    try {
      const [assetsResponse, relationshipsResponse, findingsResponse, attackPathsResponse, patternsResponse] = await Promise.all([
        fetch("/api/security/assets", { cache: "no-store" }),
        fetch("/api/security/relationships", { cache: "no-store" }),
        fetch("/api/security/analysis", { cache: "no-store" }),
        fetch("/api/security/attack-paths", { cache: "no-store" }),
        fetch("/api/security/patterns", { cache: "no-store" }),
      ]);

      const assetsData = await assetsResponse.json();
      const relationshipsData = await relationshipsResponse.json();
      const findingsData = await findingsResponse.json();
      const attackPathsData = await attackPathsResponse.json();
      const patternsData = await patternsResponse.json();

      if (!assetsResponse.ok) {
        setMessage(assetsData.error ?? "Unable to load assets.");
        return;
      }

      if (!relationshipsResponse.ok) {
        setMessage(relationshipsData.error ?? "Unable to load relationships.");
        return;
      }

      setAssets(assetsData.assets ?? []);
      setRelationships(relationshipsData.relationships ?? []);
      setFindings(findingsData.findings ?? []);
      setAttackPaths(attackPathsData.paths ?? []);
      setAttackPathLoading(false);
      setPatterns(patternsData.patterns ?? []);
      setPatternLoading(false);
      if (!attackPathsResponse.ok) {
        setMessage(attackPathsData.error ?? "Attack path intelligence is temporarily unavailable.");
      }
    } catch {
      setMessage("Security Graph could not be loaded.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadGraph();
  }, []);
