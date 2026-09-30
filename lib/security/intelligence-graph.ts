import type { AdaptiveInvestigationContext } from "@/lib/security/adaptive-context";

export type IntelligenceGraphNodeType =
  | "signal"
  | "evidence"
  | "event"
  | "finding"
  | "hypothesis"
  | "contradiction"
  | "decision"
  | "response"
  | "verification"
  | "learned_state"
  | "asset";

export type IntelligenceGraphEdgeType =
  | "supports"
  | "contradicts"
  | "temporally_precedes"
  | "verifies"
  | "related_to"
  | "requires"
  | "targets"
  | "learns_from";

export type IntelligenceGraphNode = {
  id: string;
  type: IntelligenceGraphNodeType;
  label: string;
  sourceIds: string[];
};

export type IntelligenceGraphEdge = {
  id: string;
  from: string;
  to: string;
  type: IntelligenceGraphEdgeType;
  rationale: string;
};

export type IntelligenceGraphResult = {
  nodes: IntelligenceGraphNode[];
  edges: IntelligenceGraphEdge[];
  nodeCount: number;
  edgeCount: number;
  isolatedNodeIds: string[];
  rationale: string[];
};

/**
 * Builds an inspectable relationship graph from records already present in the
 * adaptive investigation context. This layer creates relationships; it does
 * not invent unsupported security facts.
 */
export function buildIntelligenceGraph(
  context: AdaptiveInvestigationContext,
): IntelligenceGraphResult {
  const nodes = new Map<string, IntelligenceGraphNode>();
  const edges = new Map<string, IntelligenceGraphEdge>();

  const addNode = (
    id: string,
    type: IntelligenceGraphNodeType,
    label: string,
    sourceIds: string[] = [],
  ) => {
    if (!id || nodes.has(id)) return;
    nodes.set(id, { id, type, label, sourceIds: [...new Set(sourceIds)].slice(0, 20) });
  };

  const addEdge = (
    from: string,
    to: string,
    type: IntelligenceGraphEdgeType,
    rationale: string,
  ) => {
    if (!nodes.has(from) || !nodes.has(to) || from === to) return;
    const id = `${type}:${from}:${to}`;
    if (edges.has(id)) return;
    edges.set(id, { id, from, to, type, rationale });
  };

  addNode(
    "finding",
    "finding",
    `Finding: ${context.currentState.findingStatus} / ${context.currentState.severity}`,
  );

  if (context.currentState.affectedAsset) {
    addNode(
      `asset:${context.currentState.affectedAsset.id}`,
      "asset",
      context.currentState.affectedAsset.name,
      [context.currentState.affectedAsset.id],
    );
    addEdge(
      "finding",
      `asset:${context.currentState.affectedAsset.id}`,
      "targets",
      "The finding is linked to the affected asset.",
    );
  }

  for (const profile of context.currentState.correlatedEvidenceProfiles) {
    const id = `evidence:${profile.id}`;
    addNode(id, "evidence", profile.evidenceType, [profile.id]);
    addEdge(id, "finding", "supports", "The evidence is correlated with the finding context.");

    if (context.currentState.affectedAsset) {
      addEdge(
        id,
        `asset:${context.currentState.affectedAsset.id}`,
        "related_to",
        "The evidence is part of the finding's asset-correlated evidence set.",
      );
    }
  }

  for (const eventId of context.currentState.correlatedEventIds.slice(0, 100)) {
    const id = `event:${eventId}`;
    addNode(id, "event", "Correlated security event", [eventId]);
    addEdge(id, "finding", "supports", "The event is correlated with the finding context.");
  }

  if (context.currentState.affectedAsset) {
    for (const reachable of context.confirmedReachability.slice(0, 25)) {
      const id = `asset:${reachable.asset.id}`;
      addNode(id, "asset", reachable.asset.name, [reachable.asset.id]);
      addEdge(
        `asset:${context.currentState.affectedAsset.id}`,
        id,
        "related_to",
        `Confirmed relationship chain: ${reachable.chain.join(" → ") || "connected"}.`,
      );
    }
  }

  const verification = context.historicalState.latestVerification;
  if (verification) {
    const id = `verification:${verification.id}`;
    addNode(id, "verification", `Verification: ${verification.state}`, [verification.id]);
    addEdge(
      id,
      "finding",
      "verifies",
      "The verification is an explicit historical verification associated with the investigation.",
    );

    if (verification.state === "resolved") {
      addEdge(
        "finding",
        id,
        "contradicts",
        "The finding remains active while the latest verification reports resolution.",
      );
    }
  }

  if (context.learningState.state) {
    const id = `learned-state:${context.learningState.state}`;
    addNode(id, "learned_state", `Learned state: ${context.learningState.state}`);
    if (verification) {
      addEdge(
        `verification:${verification.id}`,
        id,
        "learns_from",
        "The learned state is derived from the latest explicit verification.",
      );
    }
  }

  if (context.learningState.state === "persisting" || context.learningState.state === "returned") {
    const id = `hypothesis:response-${context.learningState.state}`;
    addNode(
      id,
      "hypothesis",
      context.learningState.state === "persisting"
        ? "Hypothesis: condition persists"
        : "Hypothesis: condition returned",
    );
    if (verification) {
      addEdge(
        `verification:${verification.id}`,
        id,
        "supports",
        "The explicit verification state supports this bounded hypothesis.",
      );
    }
    addEdge(
      id,
      "finding",
      "related_to",
      "The hypothesis concerns the current finding state.",
    );
  }

  if (context.confirmedReachability.length > 0) {
    const id = "hypothesis:connected-impact";
    addNode(
      id,
      "hypothesis",
      "Hypothesis: investigate connected assets",
    );
    addEdge(
      "finding",
      id,
      "requires",
      "Confirmed asset relationships justify investigation, not a conclusion of compromise or impact.",
    );
    for (const reachable of context.confirmedReachability.slice(0, 10)) {
      addEdge(
        id,
        `asset:${reachable.asset.id}`,
        "related_to",
        "The hypothesis is bounded to investigating a confirmed reachable asset.",
      );
    }
  }

  for (const contradiction of context.contradictions.slice(0, 20)) {
    const id = `contradiction:${nodes.size + 1}`;
    addNode(id, "contradiction", contradiction);
    addEdge(
      id,
      "finding",
      "contradicts",
      "The adaptive context explicitly recorded this contradiction.",
    );
  }

  const responseLearning = context.responseLearning.slice(0, 20);
  responseLearning.forEach((learning, index) => {
    const id = `response:${index + 1}:${learning.action_type ?? "unknown"}`;
    addNode(id, "response", learning.action_type ?? "Recorded response", []);
    addEdge(
      id,
      "finding",
      "related_to",
      "The response record is part of the investigation's response-learning history.",
    );
    if (verification) {
      addEdge(
        id,
        `verification:${verification.id}`,
        "verifies",
        "The response is linked to the latest available verification context.",
      );
    }
  });

  const nodesList = [...nodes.values()].slice(0, 200);
  const allowed = new Set(nodesList.map((node) => node.id));
  const edgesList = [...edges.values()]
    .filter((edge) => allowed.has(edge.from) && allowed.has(edge.to))
    .slice(0, 400);

  const connected = new Set<string>();
  for (const edge of edgesList) {
    connected.add(edge.from);
    connected.add(edge.to);
  }

  const isolatedNodeIds = nodesList
    .filter((node) => !connected.has(node.id))
    .map((node) => node.id)
    .slice(0, 20);

  const rationale = [
    `Graph construction produced ${nodesList.length} node(s) and ${edgesList.length} typed edge(s).`,
    "Edges are created only from relationships explicitly represented in the adaptive context.",
    "Correlated evidence and events are connected to the finding without treating correlation as proof of compromise or causation.",
    context.contradictions.length
      ? `${context.contradictions.length} explicit contradiction(s) were represented as graph nodes.`
      : "No explicit contradiction node was required.",
    isolatedNodeIds.length
      ? "Some nodes remain isolated because the available records do not establish a safe relationship."
      : "All generated nodes participate in at least one relationship.",
  ];

  return {
    nodes: nodesList,
    edges: edgesList,
    nodeCount: nodesList.length,
    edgeCount: edgesList.length,
    isolatedNodeIds,
    rationale,
  };
}
