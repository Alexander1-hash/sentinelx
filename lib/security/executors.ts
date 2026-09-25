export type SecurityActionType =
  | "investigate_asset"
  | "review_finding"
  | "contain_asset"
  | "disable_integration"
  | "revoke_access"
  | "isolate_endpoint"
  | "block_indicator";

export type ExecutorReadiness =
  | "not_required"
  | "awaiting_integration"
  | "provider_executor_not_configured";

export type ExecutorRequirement = {
  actionType: SecurityActionType;
  requiredIntegrationTypes: string[];
  readiness: ExecutorReadiness;
  boundary: string;
};

/**
 * SentinelX deliberately separates:
 * 1. operator authorization,
 * 2. provider connectivity,
 * 3. provider-specific execution.
 *
 * A connected integration is never treated as proof that an executor exists.
 * This registry is the contract the future executor adapters must satisfy.
 */
const REQUIREMENTS: Record<SecurityActionType, ExecutorRequirement> = {
  investigate_asset: {
    actionType: "investigate_asset",
    requiredIntegrationTypes: [],
    readiness: "not_required",
    boundary: "Investigation is evidence collection and does not execute a containment action.",
  },
  review_finding: {
    actionType: "review_finding",
    requiredIntegrationTypes: [],
    readiness: "not_required",
    boundary: "Review is an analyst workflow and does not execute a provider action.",
  },
  contain_asset: {
    actionType: "contain_asset",
    requiredIntegrationTypes: ["cloud_security", "endpoint_security"],
    readiness: "provider_executor_not_configured",
    boundary: "Provider-specific containment is not executed until an authorized executor adapter is explicitly configured.",
  },
  disable_integration: {
    actionType: "disable_integration",
    requiredIntegrationTypes: ["business_application", "cloud_security"],
    readiness: "provider_executor_not_configured",
    boundary: "Disabling a provider connection is not executed by the generic SentinelX action endpoint.",
  },
  revoke_access: {
    actionType: "revoke_access",
    requiredIntegrationTypes: ["identity_provider"],
    readiness: "provider_executor_not_configured",
    boundary: "Access revocation requires a provider-specific executor with explicit authorization.",
  },
  isolate_endpoint: {
    actionType: "isolate_endpoint",
    requiredIntegrationTypes: ["endpoint_security", "cloud_security"],
    readiness: "provider_executor_not_configured",
    boundary: "Endpoint isolation requires a provider-specific executor with explicit authorization.",
  },
  block_indicator: {
    actionType: "block_indicator",
    requiredIntegrationTypes: ["cloud_security", "network_security"],
    readiness: "provider_executor_not_configured",
    boundary: "Indicator blocking requires a provider-specific executor with explicit authorization.",
  },
};

export function getExecutorRequirement(actionType: string): ExecutorRequirement | null {
  return REQUIREMENTS[actionType as SecurityActionType] ?? null;
}

export function getExecutorRequirements(): ExecutorRequirement[] {
  return Object.values(REQUIREMENTS);
}

export function isMutatingSecurityAction(actionType: string): boolean {
  return [
    "contain_asset",
    "disable_integration",
    "revoke_access",
    "isolate_endpoint",
    "block_indicator",
  ].includes(actionType);
}
