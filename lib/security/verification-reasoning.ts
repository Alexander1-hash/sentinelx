import type { AdaptiveInvestigationContext } from "@/lib/security/adaptive-context";

export type VerificationStatus = "verified" | "partially_verified" | "unverified" | "contradicted";
export type VerificationAssessment = { status: VerificationStatus; confidence: number; verificationId: string | null; evidenceIds: string[]; baselineEvidenceIds: string[]; currentEvidenceIds: string[]; gaps: string[]; contradictions: string[]; rationale: string[]; };
export type VerificationReasoningResult = { assessment: VerificationAssessment; rationale: string[]; };
function clamp(value: number) { return Math.max(0, Math.min(100, Math.round(value))); }

export function assessVerification(context: AdaptiveInvestigationContext, now = Date.now()): VerificationReasoningResult {
  const verification = context.historicalState.latestVerification;
  const currentEvidenceIds = context.currentState.correlatedEvidenceIds.slice(0, 20);
  const gaps = [...context.nextEvidenceNeeded];
  const contradictions = [...context.contradictions];
  if (!verification) return { assessment: { status: "unverified", confidence: 15, verificationId: null, evidenceIds: [], baselineEvidenceIds: [], currentEvidenceIds, gaps: [...new Set(["No explicit verification record exists.", ...gaps])].slice(0, 8), contradictions, rationale: ["No explicit post-response verification record is available.", "Current evidence cannot be treated as proof of response success without an explicit verification state."] }, rationale: ["Verification reasoning stopped at the evidence boundary because no verification record exists."] };
  const verificationTime = new Date(verification.occurredAt).getTime();
  const currentEvidence = context.currentState.correlatedEvidenceProfiles.filter((item) => new Date(item.observedAt).getTime() >= verificationTime).map((item) => item.id).slice(0, 20);
  const state = verification.state;
  const hasPostVerificationEvidence = currentEvidence.length > 0;
  let status: VerificationStatus = state === "unknown" ? "unverified" : state === "resolved" && hasPostVerificationEvidence ? "verified" : state === "resolved" ? "partially_verified" : state === "persisting" || state === "returned" ? "contradicted" : "unverified";
  if (context.currentState.findingStatus === "open" && state === "resolved") { status = hasPostVerificationEvidence ? "partially_verified" : "contradicted"; contradictions.push("The finding is still open while the latest verification reports resolution."); }
  const confidence = clamp((state === "resolved" ? 55 : state === "persisting" || state === "returned" ? 60 : 25) + (hasPostVerificationEvidence ? 20 : 0) + Math.min(currentEvidence.length, 5) * 4 - contradictions.length * 12);
  const rationale = [
    `Latest explicit verification is "${state}".`,
    hasPostVerificationEvidence ? `${currentEvidence.length} evidence record(s) were observed at or after the verification timestamp.` : "No correlated evidence was found at or after the verification timestamp.",
    status === "verified" ? "The recorded verification and subsequent evidence are directionally consistent with the recorded outcome." : status === "partially_verified" ? "The verification is recorded, but current-state evidence is insufficient for a fully corroborated outcome." : status === "contradicted" ? "Current investigation state conflicts with the recorded verification outcome." : "The available records do not establish a verified response outcome.",
    `Verification analysis timestamp: ${new Date(now).toISOString()}.`,
  ];
  return { assessment: { status, confidence, verificationId: verification.id, evidenceIds: [...new Set([...currentEvidence, ...currentEvidenceIds])].slice(0, 20), baselineEvidenceIds: currentEvidenceIds, currentEvidenceIds: currentEvidence, gaps: [...new Set(gaps)].slice(0, 8), contradictions: [...new Set(contradictions)].slice(0, 8), rationale }, rationale: [`Verification reasoning classified the latest outcome as ${status}.`, "Verification is evidence-backed state assessment, not an assertion that a security action was universally successful."] };
}