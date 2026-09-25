import {
  getExecutorRequirement,
  type SecurityActionType,
} from "@/lib/security/executors";

export type ExecutorPreview = {
  actionType: SecurityActionType;
  executable: false;
  mode: "preview";
  steps: string[];
  requiredIntegrationTypes: string[];
  boundary: string;
};

const ACTION_STEPS: Record<SecurityActionType, string[]> = {
  investigate_asset: [
    "Validate the authorized target context.",
    "Collect only evidence permitted by the connected investigation source.",
    "Return evidence and unknowns to SentinelX for review.",
  ],
  review_finding: [
    "Validate the finding and its supporting evidence.",
    "Re-check current telemetry before any response decision.",
    "Return the evidence package to the operator.",
  ],
  contain_asset: [
    "Resolve the authorized asset to a configured provider resource.",
    "Validate the provider-specific containment permission and target scope.",
    "Submit the containment request only through an explicitly configured executor.",
    "Record the provider response as an explicit outcome.",
  ],
  disable_integration: [
    "Resolve the authorized integration to a provider resource.",
    "Validate the provider-specific disable permission and target scope.",
    "Submit the disable request only through an explicitly configured executor.",
    "Record the provider response as an explicit outcome.",
  ],
  revoke_access: [
    "Resolve the authorized identity and access target.",
    "Validate the provider-specific revocation permission and target scope.",
    "Submit the revocation request only through an explicitly configured executor.",
    "Record the provider response as an explicit outcome.",
  ],
  isolate_endpoint: [
    "Resolve the authorized endpoint to a provider resource.",
    "Validate the provider-specific isolation permission and target scope.",
    "Submit the isolation request only through an explicitly configured executor.",
    "Record the provider response as an explicit outcome.",
  ],
  block_indicator: [
    "Validate the authorized indicator and target enforcement system.",
    "Validate the provider-specific blocking permission and target scope.",
    "Submit the block request only through an explicitly configured executor.",
    "Record the provider response as an explicit outcome.",
  ],
};

export function buildExecutorPreview(actionType: string): ExecutorPreview | null {
  const requirement = getExecutorRequirement(actionType);
  if (!requirement) return null;

  return {
    actionType: requirement.actionType,
    executable: false,
    mode: "preview",
    steps: ACTION_STEPS[requirement.actionType],
    requiredIntegrationTypes: requirement.requiredIntegrationTypes,
    boundary:
      "Preview only. SentinelX does not call a provider, mutate an external system, or claim execution from this plan.",
  };
}
