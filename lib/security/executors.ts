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
  | "provider_executor_not_configured"
  | "provider_executor_ready";

export type ExecutorRequirement = {
  actionType: SecurityActionType;
  requiredIntegrationTypes: string[];
  readiness: ExecutorReadiness;
  boundary: string;
};

export type ExecutorAdapter = {
  id: string;
  displayName: string;
  executorType: string;
  supportedActions: SecurityActionType[];
  mode: "manual" | "provider";
  enabled: boolean;
  boundary: string;
};

export const PROVIDER_WEBHOOK_EXECUTOR: ExecutorAdapter = {
  id: "provider_webhook",
  displayName: "Provider Webhook Executor",
  executorType: "provider_webhook",
  supportedActions: [
    "contain_asset",
    "disable_integration",
    "revoke_access",
    "isolate_endpoint",
    "block_indicator",
  ],
  mode: "provider",
  enabled: true,
  boundary:
    "Provider Webhook Executor calls only an explicitly configured, organization-authorized HTTPS endpoint after operator authorization and target validation. The provider response is recorded as the execution outcome.",
};

export const MANUAL_OPERATOR_EXECUTOR: ExecutorAdapter = {
  id: "manual_operator",
  displayName: "Manual Operator",
  executorType: "manual_operator",
  supportedActions: [
    "investigate_asset",
    "review_finding",
    "contain_asset",
    "disable_integration",
    "revoke_access",
    "isolate_endpoint",
    "block_indicator",
  ],
  mode: "manual",
  enabled: true,
  boundary:
    "Manual Operator records an operator-performed result. Trinorin does not call or control the external provider.",
};

export function getExecutorAdapters(): ExecutorAdapter[] {
  return [MANUAL_OPERATOR_EXECUTOR, PROVIDER_WEBHOOK_EXECUTOR];
}

export function getExecutorAdapter(
  executorType: string,
  actionType: string,
): ExecutorAdapter | null {
  return getExecutorAdapters().find(
    (adapter) =>
      adapter.executorType === executorType &&
      adapter.enabled &&
      adapter.supportedActions.includes(actionType as SecurityActionType),
  ) ?? null;
}

/**
 * Trinorin deliberately separates:
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
    requiredIntegrationTypes: ["cloud_security", "cloud", "endpoint_security", "endpoint"],
    readiness: "provider_executor_ready",
    boundary: "Provider-backed containment is available through the configured Provider Webhook Executor only after explicit operator authorization and target validation.",
  },
  disable_integration: {
    actionType: "disable_integration",
    requiredIntegrationTypes: ["business_application", "application", "cloud_security", "cloud"],
    readiness: "provider_executor_ready",
    boundary: "Disabling a provider connection is available through the configured Provider Webhook Executor only after explicit operator authorization and target validation.",
  },
  revoke_access: {
    actionType: "revoke_access",
    requiredIntegrationTypes: ["identity_provider", "identity"],
    readiness: "provider_executor_ready",
    boundary: "Access revocation is available through the configured Provider Webhook Executor only after explicit operator authorization and target validation.",
  },
  isolate_endpoint: {
    actionType: "isolate_endpoint",
    requiredIntegrationTypes: ["endpoint_security", "endpoint", "cloud_security", "cloud"],
    readiness: "provider_executor_ready",
    boundary: "Endpoint isolation is available through the configured Provider Webhook Executor only after explicit operator authorization and target validation.",
  },
  block_indicator: {
    actionType: "block_indicator",
    requiredIntegrationTypes: ["cloud_security", "cloud", "network_security", "network"],
    readiness: "provider_executor_ready",
    boundary: "Indicator blocking is available through the configured Provider Webhook Executor only after explicit operator authorization and target validation.",
  },
};

export function getExecutorRequirement(actionType: string): ExecutorRequirement | null {
  return REQUIREMENTS[actionType as SecurityActionType] ?? null;
}

export function getExecutorRequirements(): ExecutorRequirement[] {
  return Object.values(REQUIREMENTS);
}

export type ExecutionTarget = {
  assetId?: string;
  resourceId?: string;
  resourceType?: string;
  provider?: string;
  integrationId?: string;
  indicator?: string;
};

const TARGET_KEYS: Record<SecurityActionType, Array<keyof ExecutionTarget>> = {
  investigate_asset: ["assetId", "resourceId"],
  review_finding: ["resourceId"],
  contain_asset: ["assetId", "resourceId"],
  disable_integration: ["integrationId", "resourceId"],
  revoke_access: ["assetId", "resourceId"],
  isolate_endpoint: ["assetId", "resourceId"],
  block_indicator: ["indicator", "resourceId"],
};

export function validateExecutionTarget(
  actionType: string,
  target: unknown,
): { valid: true; target: ExecutionTarget } | { valid: false; error: string } {
  if (!target || typeof target !== "object" || Array.isArray(target)) {
    return { valid: false, error: "The authorized action has no valid execution target." };
  }

  const normalized = target as Record<string, unknown>;
  const keys = TARGET_KEYS[actionType as SecurityActionType];
  if (!keys) return { valid: false, error: "Unsupported security action target." };

  const hasStableTarget = keys.some((key) => {
    const value = normalized[key];
    return typeof value === "string" && value.trim().length > 0;
  });

  if (!hasStableTarget) {
    return {
      valid: false,
      error: "The authorized action must contain a stable target identifier before execution can be recorded.",
    };
  }

  return { valid: true, target: normalized as ExecutionTarget };
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
