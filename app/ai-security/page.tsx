"use client";

import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Bot,
  BrainCircuit,
  ChevronRight,
  Database,
  Eye,
  KeyRound,
  Network,
  Plus,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Wrench,
  X,
} from "lucide-react";

type AiSystem = {
  id: string;
  asset_id: string | null;
  name: string;
  provider: string | null;
  model: string | null;
  system_type: string;
  environment: string;
  data_classification: string;
  status: string;
  capabilities: unknown[];
  permissions: Record<string, unknown>;
};

type AiAgent = {
  id: string;
  system_id: string | null;
  name: string;
  purpose: string | null;
  autonomy_level: string;
  tools: unknown[];
  permissions: Record<string, unknown>;
  data_access: unknown[];
  status: string;
};

type AiEvent = {
  id: string;
  system_id: string | null;
  agent_id: string | null;
  event_type: string;
  severity: string;
  title: string;
  description: string | null;
  observed_at: string;
};

type SecurityFinding = {
  id: string;
  asset_id: string | null;
  title: string;
  finding_type: string;
  severity: string;
  status: string;
  summary: string | null;
  remediation: string | null;
  detected_at: string;
};

type CenterData = {
  systems: AiSystem[];
  agents: AiAgent[];
  events: AiEvent[];
  indicators: Array<{ label: string; state: string; detail: string }>;
  graphPaths: Array<{ id: string; source_asset_id: string; target_asset_id: string; relationship_type: string; confidence: number | null; status: string; evidence_source: string; system_name: string; source_name: string; target_name: string }>;
  summary: {
    systems: number;
    agents: number;
    activeAgents: number;
    autonomousAgents: number;
    highImpactEvents: number;
    connectedSystems: number;
  };
};

const emptyData: CenterData = {
  systems: [],
  agents: [],
  events: [],
  indicators: [],
  graphPaths: [],
  summary: { systems: 0, agents: 0, activeAgents: 0, autonomousAgents: 0, highImpactEvents: 0, connectedSystems: 0 },
};

function badgeTone(value: string) {
  if (value === "critical" || value === "high" || value === "autonomous") return "border-red-400/20 bg-red-400/10 text-red-300";
  if (value === "medium" || value === "supervised") return "border-amber-400/20 bg-amber-400/10 text-amber-300";
  if (value === "active" || value === "observed") return "border-emerald-400/20 bg-emerald-400/10 text-emerald-300";
  return "border-white/10 bg-white/[0.04] text-slate-400";
}

export default function AiSecurityCenterPage() {
  const [data, setData] = useState<CenterData>(emptyData);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [modal, setModal] = useState<"system" | "agent" | null>(null);
  const [form, setForm] = useState({ name: "", provider: "", model: "", purpose: "", systemId: "", autonomyLevel: "assisted", dataClassification: "unknown" });
  const [message, setMessage] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [posture, setPosture] = useState<{ observations: Array<{ state: string; title: string; detail: string }>; summary: { systems: number; agents: number; highImpactEvents: number; sensitiveEvidence: number; confirmedAiRelevantEdges: number } } | null>(null);
  const [detecting, setDetecting] = useState(false);
  const [detections, setDetections] = useState<Array<{ state: string; category: string; title: string; detail: string; evidenceIds: string[]; eventIds: string[]; recommendedNextStep: string }>>([]);
  const [detectionSummary, setDetectionSummary] = useState<{ total: number; observed: number; potential: number } | null>(null);
  const [attackPaths, setAttackPaths] = useState<Array<{ id: string; source: { name: string; asset_type: string }; target: { name: string; asset_type: string }; hops: Array<{ asset: { name: string; asset_type: string }; relationship: string; confidence: number | null }>; confidence: number; rationale: string }>>([]);
  const [pathsLoading, setPathsLoading] = useState(false);
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [creatingFindings, setCreatingFindings] = useState(false);

  async function load() {
    const response = await fetch("/api/security/ai", { cache: "no-store" });
    if (response.ok) setData((await response.json()) as CenterData);
    setLoading(false);
    setRefreshing(false);
  }

  async function loadFindings() {
    setFindingsLoading(true);
    const response = await fetch("/api/security/analysis", { cache: "no-store" });
    if (response.ok) {
      const result = await response.json();
      setFindings(result.findings ?? []);
    }
    setFindingsLoading(false);
  }

  useEffect(() => {
    void load();
    void loadAttackPaths();
    void loadFindings();
  }, []);

  async function loadAttackPaths() {
    setPathsLoading(true);
    const response = await fetch("/api/security/attack-paths", { cache: "no-store" });
    if (response.ok) {
      const result = await response.json();
      setAttackPaths(result.paths ?? []);
    }
    setPathsLoading(false);
  }

  async function analyzePosture() {
    setAnalyzing(true);
    setMessage("");
    const response = await fetch("/api/security/ai", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind: "analyze" }),
    });
    const result = await response.json();
    if (response.ok) {
      setPosture(result);
    } else {
      setMessage(result.error ?? "AI posture analysis failed.");
    }
    setAnalyzing(false);
  }

  async function detectThreats() {
    setDetecting(true);
    setMessage("");
    const response = await fetch("/api/security/ai", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ kind: "detect" }) });
    const result = await response.json();
    if (response.ok) { setDetections(result.detections ?? []); setDetectionSummary(result.summary ?? null); }
    else setMessage(result.error ?? "Threat detection failed.");
    setDetecting(false);
  }

  async function createFindings() {
    setCreatingFindings(true);
    setMessage("");
    const response = await fetch("/api/security/analysis", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    const result = await response.json();
    if (response.ok) {
      setMessage(result.message ?? "Security findings analysis completed.");
      await loadFindings();
    } else {
      setMessage(result.error ?? "Security findings analysis failed.");
    }
    setCreatingFindings(false);
  }

  async function submit() {
    setMessage("");
    const payload = modal === "system"
      ? { kind: "system", name: form.name, provider: form.provider, model: form.model, dataClassification: form.dataClassification }
      : { kind: "agent", name: form.name, purpose: form.purpose, systemId: form.systemId || null, autonomyLevel: form.autonomyLevel };

    const response = await fetch("/api/security/ai", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const result = await response.json();
    if (!response.ok) {
      setMessage(result.error ?? "Registration failed.");
      return;
    }

    setMessage(modal === "system" ? "AI system registered." : "AI agent registered.");
    setModal(null);
    setForm({ name: "", provider: "", model: "", purpose: "", systemId: "", autonomyLevel: "assisted", dataClassification: "unknown" });
    setRefreshing(true);
    await load();
  }

  const systemName = useMemo(() => new Map(data.systems.map((system) => [system.id, system.name])), [data.systems]);

  return (
    <main className="min-h-screen bg-[#071018] text-slate-100">
      <header className="sticky top-0 z-50 border-b border-white/10 bg-[#071018]/90 backdrop-blur-xl">
        <div className="mx-auto flex max-w-[1500px] items-center justify-between px-4 py-3 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div><p className="text-sm font-semibold text-white">SentinelX</p><p className="text-[11px] text-slate-500">AI Security Center</p></div>
          </div>
          <a href="/" className="rounded-xl border border-white/10 px-3 py-2 text-xs font-medium text-slate-400 hover:bg-white/5 hover:text-white">Command Center</a>
        </div>
      </header>

      <div className="mx-auto max-w-[1500px] px-4 py-6 sm:px-6 sm:py-8">
        <section className="grid gap-5 xl:grid-cols-[1.5fr_0.5fr]">
          <div className="relative overflow-hidden rounded-3xl border border-cyan-400/15 bg-gradient-to-br from-cyan-400/[0.08] via-white/[0.03] to-transparent p-6 sm:p-8">
            <div className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full bg-cyan-400/10 blur-3xl" />
            <div className="relative">
              <div className="inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-cyan-300"><Bot className="h-3.5 w-3.5" /> AI security layer</div>
              <h1 className="mt-5 max-w-3xl text-3xl font-semibold tracking-tight text-white sm:text-5xl">Understand what your AI can do.</h1>
              <p className="mt-4 max-w-2xl text-sm leading-6 text-slate-400 sm:text-base">SentinelX treats AI systems and agents as first-class security assets. Inventory their providers, models, autonomy, tools, permissions and data access before reasoning about what their behavior means.</p>
              <div className="mt-7 flex flex-wrap gap-3">
                <button onClick={() => setModal("system")} className="inline-flex items-center gap-2 rounded-xl bg-cyan-300 px-4 py-3 text-sm font-semibold text-slate-950 hover:bg-cyan-200"><Plus className="h-4 w-4" /> Register AI system</button>
                <button onClick={() => setModal("agent")} className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm font-semibold text-white hover:bg-white/[0.08]"><Bot className="h-4 w-4" /> Register AI agent</button>
                <button onClick={() => void detectThreats()} disabled={detecting} className="inline-flex items-center gap-2 rounded-xl border border-red-400/20 bg-red-400/[0.05] px-4 py-3 text-sm font-semibold text-red-200 hover:bg-red-400/[0.1] disabled:opacity-50"><AlertTriangle className="h-4 w-4" /> {detecting ? "Detecting…" : "Run threat detection"}</button>
                <button onClick={() => void analyzePosture()} disabled={analyzing} className="inline-flex items-center gap-2 rounded-xl border border-cyan-400/20 bg-cyan-400/[0.06] px-4 py-3 text-sm font-semibold text-cyan-200 hover:bg-cyan-400/[0.1] disabled:opacity-50"><Sparkles className="h-4 w-4" /> {analyzing ? "Analyzing evidence…" : "Analyze AI posture"}</button>
                <button onClick={() => void createFindings()} disabled={creatingFindings} className="inline-flex items-center gap-2 rounded-xl border border-purple-400/20 bg-purple-400/[0.05] px-4 py-3 text-sm font-semibold text-purple-200 hover:bg-purple-400/[0.1] disabled:opacity-50"><ShieldCheck className="h-4 w-4" /> {creatingFindings ? "Correlating evidence…" : "Create security findings"}</button>
              </div>
            </div>
          </div>

          <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
            <div className="flex items-center gap-2"><BrainCircuit className="h-4 w-4 text-cyan-300" /><p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Evidence boundary</p></div>
            <p className="mt-3 text-lg font-semibold text-white">No invented AI risk.</p>
            <p className="mt-2 text-sm leading-6 text-slate-500">SentinelX will show observed indicators from registered records and telemetry. Missing telemetry is unknown — never proof that an AI system is safe.</p>
          </div>
        </section>

        <section className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-6">
          {[
            ["AI systems", data.summary.systems, Bot],
            ["AI agents", data.summary.agents, Sparkles],
            ["Active agents", data.summary.activeAgents, Eye],
            ["Autonomous", data.summary.autonomousAgents, AlertTriangle],
            ["High-impact events", data.summary.highImpactEvents, AlertTriangle],
            ["Connected systems", data.summary.connectedSystems, Network],
          ].map(([label, value, Icon]) => (
            <div key={String(label)} className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{String(label)}</p>
              <p className="mt-3 text-2xl font-semibold text-white">{loading ? "—" : String(value)}</p>
            </div>
          ))}
        </section>

        <section className="mt-8 grid gap-5 lg:grid-cols-[1.35fr_0.65fr]">
          <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6 sm:p-7">
            <div className="flex items-start justify-between"><div><p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">01 · AI systems</p><h2 className="mt-1 text-xl font-semibold text-white">AI inventory</h2></div><Database className="h-5 w-5 text-slate-600" /></div>
            <div className="mt-5 space-y-3">
              {data.systems.length ? data.systems.map((system) => (
                <div key={system.id} className="rounded-2xl border border-white/10 bg-black/10 p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div><p className="font-semibold text-white">{system.name}</p><p className="mt-1 text-xs text-slate-500">{system.provider || "Provider unknown"} {system.model ? "· " + system.model : ""}</p></div>
                    <span className={"rounded-full border px-2 py-1 text-[9px] font-semibold uppercase tracking-wider " + badgeTone(system.status)}>{system.status}</span>
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2">
                    <span className="rounded-full border border-white/10 px-2 py-1 text-[9px] text-slate-400">{system.system_type}</span>
                    <span className="rounded-full border border-white/10 px-2 py-1 text-[9px] text-slate-400">{system.environment}</span>
                    <span className="rounded-full border border-white/10 px-2 py-1 text-[9px] text-slate-400">{system.data_classification} data</span>
                    <span className={"rounded-full border px-2 py-1 text-[9px] " + (system.asset_id ? "border-emerald-400/20 text-emerald-300" : "border-amber-400/20 text-amber-300")}>{system.asset_id ? "Graph linked" : "Not graph linked"}</span>
                  </div>
                </div>
              )) : <EmptyState text="No AI systems registered yet." />}
            </div>
          </div>

          <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6 sm:p-7">
            <div><p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">02 · AI agents</p><h2 className="mt-1 text-xl font-semibold text-white">Delegated capability</h2></div>
            <div className="mt-5 space-y-3">
              {data.agents.length ? data.agents.map((agent) => (
                <div key={agent.id} className="rounded-2xl border border-white/10 bg-black/10 p-4">
                  <div className="flex items-start justify-between gap-3"><div><p className="font-semibold text-white">{agent.name}</p><p className="mt-1 text-xs text-slate-500">{agent.purpose || "Purpose not recorded"}</p></div><span className={"rounded-full border px-2 py-1 text-[9px] font-semibold uppercase tracking-wider " + badgeTone(agent.autonomy_level)}>{agent.autonomy_level}</span></div>
                  <div className="mt-4 grid grid-cols-2 gap-2 text-[10px]">
                    <div className="rounded-xl border border-white/10 p-3"><Wrench className="h-3.5 w-3.5 text-cyan-300" /><p className="mt-2 text-slate-400">{agent.tools.length} tools declared</p></div>
                    <div className="rounded-xl border border-white/10 p-3"><Database className="h-3.5 w-3.5 text-cyan-300" /><p className="mt-2 text-slate-400">{agent.data_access.length} data scopes declared</p></div>
                  </div>
                  <p className="mt-3 text-[10px] text-slate-600">{agent.system_id ? "System: " + (systemName.get(agent.system_id) || "registered") : "System relationship unknown"}</p>
                </div>
              )) : <EmptyState text="No AI agents registered yet." />}
            </div>
          </div>
        </section>

        <section className="mt-8 rounded-3xl border border-red-400/10 bg-red-400/[0.025] p-6 sm:p-7">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div><p className="text-xs font-semibold uppercase tracking-wider text-red-300">05 · AI threat detection</p><h2 className="mt-1 text-xl font-semibold text-white">Evidence-grounded detection</h2><p className="mt-2 max-w-3xl text-xs leading-5 text-slate-500">Rules inspect recorded AI telemetry and evidence for explicit security indicators. Potential conditions are surfaced for review; detection never executes a response action.</p></div>
            {detectionSummary && <div className="flex gap-2"><span className="rounded-full border border-white/10 px-3 py-1.5 text-[10px] text-slate-400">{detectionSummary.total} detected</span><span className="rounded-full border border-red-400/20 px-3 py-1.5 text-[10px] text-red-300">{detectionSummary.observed} observed</span><span className="rounded-full border border-amber-400/20 px-3 py-1.5 text-[10px] text-amber-300">{detectionSummary.potential} potential</span></div>}
          </div>
          <div className="mt-5 grid gap-3 lg:grid-cols-2">
            {detections.length ? detections.map((item, index) => <div key={item.title + index} className="rounded-2xl border border-white/10 bg-black/10 p-4">
              <div className="flex items-start justify-between gap-3"><div><span className="text-[9px] font-semibold uppercase tracking-wider text-red-300">{item.category}</span><p className="mt-1 text-sm font-medium text-white">{item.title}</p></div><span className={"rounded-full border px-2 py-1 text-[9px] font-semibold uppercase tracking-wider " + badgeTone(item.state)}>{item.state}</span></div>
              <p className="mt-3 text-xs leading-5 text-slate-500">{item.detail}</p>
              <div className="mt-3 rounded-xl border border-cyan-400/10 bg-cyan-400/[0.025] p-3"><p className="text-[9px] font-semibold uppercase tracking-wider text-cyan-300">Next step</p><p className="mt-1 text-[11px] leading-5 text-slate-400">{item.recommendedNextStep}</p></div>
              {(item.eventIds.length || item.evidenceIds.length) ? <p className="mt-3 text-[9px] text-slate-600">Evidence references: {item.eventIds.length} event(s) · {item.evidenceIds.length} evidence record(s)</p> : null}
            </div>) : <div className="lg:col-span-2 rounded-2xl border border-dashed border-white/10 p-8 text-center"><ShieldCheck className="mx-auto h-5 w-5 text-emerald-300" /><p className="mt-3 text-sm font-medium text-slate-300">No evidence-backed AI threat indicators detected.</p><p className="mt-2 text-xs text-slate-600">This means the current registered telemetry did not match the detection rules. Missing telemetry remains unknown.</p></div>}
          </div>
        </section>

        <section className="mt-8 rounded-3xl border border-rose-400/10 bg-rose-400/[0.025] p-6 sm:p-7">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-rose-300">06 · Security findings intelligence</p>
              <h2 className="mt-1 text-xl font-semibold text-white">Correlated findings, not isolated alerts</h2>
              <p className="mt-2 max-w-3xl text-xs leading-5 text-slate-500">
                SentinelX converts observed high-impact events and explicit AI security indicators into reviewable findings. Confirmed graph context can enrich a finding, but an unverified relationship never becomes a finding.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="rounded-full border border-white/10 px-3 py-1.5 text-[10px] text-slate-400">{findings.length} findings</span>
              <button onClick={() => void loadFindings()} disabled={findingsLoading} className="inline-flex items-center gap-2 rounded-xl border border-white/10 px-3 py-2 text-xs text-slate-400 hover:text-white disabled:opacity-50">
                <RefreshCw className={"h-3.5 w-3.5 " + (findingsLoading ? "animate-spin" : "")} /> Refresh
              </button>
            </div>
          </div>

          <div className="mt-5 space-y-3">
            {findings.length ? findings.slice(0, 12).map((finding) => (
              <div key={finding.id} className="rounded-2xl border border-white/10 bg-black/10 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-medium text-white">{finding.title}</p>
                    <p className="mt-1 text-[10px] capitalize text-slate-600">{finding.finding_type.replaceAll("_", " ")} · {new Date(finding.detected_at).toLocaleString()}</p>
                  </div>
                  <div className="flex gap-2">
                    <span className={"rounded-full border px-2 py-1 text-[9px] font-semibold uppercase tracking-wider " + badgeTone(finding.severity)}>{finding.severity}</span>
                    <span className={"rounded-full border px-2 py-1 text-[9px] font-semibold uppercase tracking-wider " + badgeTone(finding.status)}>{finding.status}</span>
                  </div>
                </div>
                <p className="mt-3 text-xs leading-5 text-slate-500">{finding.summary || "Evidence-backed finding requiring investigation."}</p>
                <div className="mt-3 grid gap-2 sm:grid-cols-2">
                  <div className="rounded-xl border border-white/10 p-3">
                    <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">Affected asset</p>
                    <p className="mt-1 text-[10px] text-slate-400">{finding.asset_id ? "Linked asset: " + finding.asset_id : "Asset linkage not established"}</p>
                  </div>
                  <div className="rounded-xl border border-cyan-400/10 bg-cyan-400/[0.025] p-3">
                    <p className="text-[9px] font-semibold uppercase tracking-wider text-cyan-300">Recommended intervention</p>
                    <p className="mt-1 text-[10px] leading-5 text-slate-400">{finding.remediation || "Review supporting evidence before selecting an authorized response."}</p>
                  </div>
                </div>
              </div>
            )) : (
              <div className="rounded-2xl border border-dashed border-white/10 p-8 text-center">
                <ShieldCheck className="mx-auto h-5 w-5 text-slate-700" />
                <p className="mt-3 text-sm font-medium text-slate-400">{findingsLoading ? "Loading findings…" : "No evidence-backed findings recorded yet."}</p>
                <p className="mt-2 text-xs text-slate-600">Run “Create security findings” after telemetry or evidence has been connected.</p>
              </div>
            )}
          </div>

          <div className="mt-4 rounded-2xl border border-white/10 bg-black/10 p-4">
            <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">Evidence boundary</p>
            <p className="mt-1 text-[10px] leading-5 text-slate-600">A finding is an evidence-backed investigation record. It is not a declaration of compromise, malicious intent, or successful exploitation.</p>
          </div>
        </section>

        <section className="mt-8 rounded-3xl border border-purple-400/10 bg-purple-400/[0.025] p-6 sm:p-7">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div><p className="text-xs font-semibold uppercase tracking-wider text-purple-300">07 · Attack-path intelligence</p><h2 className="mt-1 text-xl font-semibold text-white">AI-connected attack paths</h2><p className="mt-2 max-w-3xl text-xs leading-5 text-slate-500">SentinelX traces only confirmed graph relationships. A path shows exposure context between authorized assets; it does not establish compromise or attacker activity.</p></div>
            <button onClick={() => void loadAttackPaths()} disabled={pathsLoading} className="inline-flex items-center gap-2 rounded-xl border border-white/10 px-3 py-2 text-xs text-slate-400 hover:text-white disabled:opacity-50"><RefreshCw className={"h-3.5 w-3.5 " + (pathsLoading ? "animate-spin" : "")} /> Refresh paths</button>
          </div>
          <div className="mt-5 space-y-3">
            {attackPaths.length ? attackPaths.slice(0, 12).map((path) => (
              <div key={path.id} className="rounded-2xl border border-white/10 bg-black/10 p-4">
                <div className="flex flex-wrap items-center gap-2 text-xs font-medium text-white">
                  <span>{path.source.name}</span><ChevronRight className="h-3.5 w-3.5 text-purple-300" />
                  {path.hops.map((hop, index) => <span key={index} className="inline-flex items-center gap-2"><span className="text-slate-300">{hop.relationship}</span><ChevronRight className="h-3.5 w-3.5 text-slate-600" /><span>{hop.asset.name}</span></span>)}
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  <span className="rounded-full border border-purple-400/20 px-2 py-1 text-[9px] text-purple-200">{path.hops.length} hops</span>
                  <span className="rounded-full border border-emerald-400/20 px-2 py-1 text-[9px] text-emerald-300">confirmed graph</span>
                  <span className="text-[9px] text-slate-600">Minimum edge confidence: {Math.round(path.confidence * 100)}%</span>
                </div>
                <p className="mt-2 text-[10px] leading-5 text-slate-600">{path.rationale}</p>
              </div>
            )) : <div className="rounded-2xl border border-dashed border-white/10 p-8 text-center"><Network className="mx-auto h-5 w-5 text-slate-700" /><p className="mt-3 text-sm font-medium text-slate-400">{pathsLoading ? "Tracing confirmed relationships…" : "No confirmed multi-hop attack paths available."}</p><p className="mt-2 text-xs text-slate-600">Unconfirmed relationships are intentionally excluded.</p></div>}
          </div>
        </section>

        <section className="mt-8 grid gap-5 lg:grid-cols-2">
          <div className="rounded-3xl border border-cyan-400/10 bg-cyan-400/[0.025] p-6">
            <div className="flex items-center justify-between">
              <div><p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">05 · Security reasoning</p><h2 className="mt-1 text-xl font-semibold text-white">AI posture analysis</h2></div>
              <Sparkles className="h-5 w-5 text-cyan-300" />
            </div>
            {posture ? <div className="mt-5 space-y-3">
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
                {Object.entries(posture.summary).map(([label, value]) => <div key={label} className="rounded-xl border border-white/10 p-3"><p className="text-[9px] uppercase tracking-wider text-slate-600">{label.replaceAll("_", " ")}</p><p className="mt-2 text-lg font-semibold text-white">{value}</p></div>)}
              </div>
              {posture.observations.length ? posture.observations.map((item, index) => <div key={item.title + index} className="rounded-2xl border border-white/10 bg-black/10 p-4"><div className="flex items-center justify-between gap-3"><p className="text-sm font-medium text-white">{item.title}</p><span className={"rounded-full border px-2 py-1 text-[9px] uppercase tracking-wider " + badgeTone(item.state)}>{item.state}</span></div><p className="mt-2 text-xs leading-5 text-slate-500">{item.detail}</p></div>) : <EmptyState text="No additional evidence-backed observations were produced." />}
            </div> : <div className="mt-5 rounded-2xl border border-dashed border-white/10 p-5"><p className="text-sm font-medium text-slate-300">Run the analyzer when you want SentinelX to correlate registered AI configuration, telemetry, evidence, and confirmed graph relationships.</p><p className="mt-2 text-xs leading-5 text-slate-600">Potential observations require review. They are not proof of compromise or malicious behavior.</p></div>}
          </div>

          <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
            <div className="flex items-center justify-between"><div><p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">06 · AI graph</p><h2 className="mt-1 text-xl font-semibold text-white">Confirmed AI-connected paths</h2></div><Network className="h-5 w-5 text-cyan-300" /></div>
            <div className="mt-5 space-y-3">
              {data.graphPaths.length ? data.graphPaths.slice(0, 12).map((edge) => <div key={edge.id} className="rounded-2xl border border-white/10 bg-black/10 p-4"><div className="flex items-center gap-2 text-xs font-medium text-white"><span>{edge.source_name}</span><ChevronRight className="h-3.5 w-3.5 text-cyan-300" /><span>{edge.target_name}</span></div><div className="mt-2 flex flex-wrap gap-2"><span className="rounded-full border border-cyan-400/20 px-2 py-1 text-[9px] text-cyan-200">{edge.relationship_type}</span><span className="rounded-full border border-emerald-400/20 px-2 py-1 text-[9px] text-emerald-300">confirmed</span><span className="text-[9px] text-slate-600">Evidence: {edge.evidence_source}</span></div></div>) : <EmptyState text="No confirmed AI-connected asset paths are available yet." />}
            </div>
          </div>
        </section>

        <section className="mt-8 grid gap-5 lg:grid-cols-2">
          <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
            <div className="flex items-center justify-between"><div><p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">03 · Observed indicators</p><h2 className="mt-1 text-xl font-semibold text-white">What the evidence says</h2></div><Eye className="h-5 w-5 text-cyan-300" /></div>
            <div className="mt-5 space-y-3">
              {data.indicators.length ? data.indicators.map((item, index) => (
                <div key={item.label + index} className="rounded-2xl border border-white/10 bg-black/10 p-4">
                  <div className="flex items-center justify-between gap-3"><p className="text-sm font-medium text-white">{item.label}</p><span className={"rounded-full border px-2 py-1 text-[9px] font-semibold uppercase tracking-wider " + badgeTone(item.state)}>{item.state}</span></div>
                  <p className="mt-2 text-xs leading-5 text-slate-500">{item.detail}</p>
                </div>
              )) : <EmptyState text="No AI security indicators have been observed." />}
            </div>
          </div>

          <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-6">
            <div className="flex items-center justify-between"><div><p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">04 · AI security telemetry</p><h2 className="mt-1 text-xl font-semibold text-white">Recent AI events</h2></div><button onClick={() => { setRefreshing(true); void load(); }} className="rounded-xl border border-white/10 p-2 text-slate-400 hover:text-white"><RefreshCw className={"h-4 w-4 " + (refreshing ? "animate-spin" : "")} /></button></div>
            <div className="mt-5 space-y-3">
              {data.events.length ? data.events.slice(0, 8).map((event) => (
                <div key={event.id} className="rounded-2xl border border-white/10 bg-black/10 p-4">
                  <div className="flex items-start justify-between gap-3"><div><p className="text-sm font-medium text-white">{event.title}</p><p className="mt-1 text-[10px] text-slate-600">{new Date(event.observed_at).toLocaleString()}</p></div><span className={"rounded-full border px-2 py-1 text-[9px] font-semibold uppercase tracking-wider " + badgeTone(event.severity)}>{event.severity}</span></div>
                  <p className="mt-2 text-xs text-slate-500">{event.description || event.event_type}</p>
                </div>
              )) : <EmptyState text="No AI telemetry events recorded." />}
            </div>
          </div>
        </section>

        <section className="mt-8 rounded-3xl border border-amber-400/10 bg-amber-400/[0.035] p-6">
          <div className="flex items-start gap-3"><AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-300" /><div><h2 className="text-sm font-semibold text-white">Security boundary</h2><p className="mt-2 text-xs leading-5 text-slate-500">SentinelX can identify registered capabilities and observed AI events. It does not claim prompt injection, data leakage, malicious behavior, compromise, or unsafe tool use unless supporting telemetry or evidence is actually recorded. Response actions remain behind explicit authorization.</p></div></div>
        </section>
      </div>

      {modal && <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
        <div className="w-full max-w-lg rounded-3xl border border-white/10 bg-[#0b151e] p-6 shadow-2xl">
          <div className="flex items-center justify-between"><div><p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">Register</p><h2 className="mt-1 text-xl font-semibold text-white">{modal === "system" ? "AI system" : "AI agent"}</h2></div><button onClick={() => setModal(null)} className="rounded-xl p-2 text-slate-500 hover:bg-white/5 hover:text-white"><X className="h-4 w-4" /></button></div>
          <div className="mt-5 space-y-4">
            <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder={modal === "system" ? "System name" : "Agent name"} className="w-full rounded-xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm text-white outline-none placeholder:text-slate-600 focus:border-cyan-300/30" />
            {modal === "system" ? <>
              <input value={form.provider} onChange={(e) => setForm({ ...form, provider: e.target.value })} placeholder="Provider (optional)" className="w-full rounded-xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm text-white outline-none placeholder:text-slate-600" />
              <input value={form.model} onChange={(e) => setForm({ ...form, model: e.target.value })} placeholder="Model (optional)" className="w-full rounded-xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm text-white outline-none placeholder:text-slate-600" />
              <select value={form.dataClassification} onChange={(e) => setForm({ ...form, dataClassification: e.target.value })} className="w-full rounded-xl border border-white/10 bg-[#0b151e] px-4 py-3 text-sm text-white"><option value="unknown">Data classification unknown</option><option value="public">Public</option><option value="internal">Internal</option><option value="confidential">Confidential</option><option value="restricted">Restricted</option></select>
            </> : <>
              <textarea value={form.purpose} onChange={(e) => setForm({ ...form, purpose: e.target.value })} placeholder="What is this agent authorized to do?" className="min-h-24 w-full rounded-xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm text-white outline-none placeholder:text-slate-600" />
              <select value={form.systemId} onChange={(e) => setForm({ ...form, systemId: e.target.value })} className="w-full rounded-xl border border-white/10 bg-[#0b151e] px-4 py-3 text-sm text-white"><option value="">System relationship unknown</option>{data.systems.map((system) => <option key={system.id} value={system.id}>{system.name}</option>)}</select>
              <select value={form.autonomyLevel} onChange={(e) => setForm({ ...form, autonomyLevel: e.target.value })} className="w-full rounded-xl border border-white/10 bg-[#0b151e] px-4 py-3 text-sm text-white"><option value="assisted">Assisted</option><option value="supervised">Supervised</option><option value="autonomous">Autonomous</option></select>
            </>}
            {message && <p className="rounded-xl border border-amber-400/10 bg-amber-400/[0.04] p-3 text-xs text-amber-200">{message}</p>}
            <button onClick={() => void submit()} className="w-full rounded-xl bg-cyan-300 px-4 py-3 text-sm font-semibold text-slate-950 hover:bg-cyan-200">Register and analyze later</button>
          </div>
        </div>
      </div>}
    </main>
  );
}

function EmptyState({ text }: { text: string }) {
  return <div className="rounded-2xl border border-dashed border-white/10 px-5 py-10 text-center"><ChevronRight className="mx-auto h-5 w-5 rotate-[-90deg] text-slate-700" /><p className="mt-3 text-xs text-slate-600">{text}</p></div>;
}
