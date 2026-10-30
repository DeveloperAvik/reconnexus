import { z } from "zod";

export const CapabilitySchema = z.enum([
  "PASSIVE",
  "DNS",
  "ACTIVE_HTTP",
  "CRAWL",
  "JS_ANALYSIS",
  "API_DISCOVERY",
  "SECRET_SCAN",
  "SECURITY_CHECKS",
  "ACTIVE_TEMPLATE_CHECK",
  "TAKEOVER_CHECK",
  "PORT_SCAN",
  "CONTENT_DISCOVERY",
  "INTERNAL_NETWORK",
]);

export const DomainRuleSchema = z.object({
  value: z.string().min(1),
  includeSubdomains: z.boolean().default(false),
});

export const LimitsSchema = z.object({
  maxConcurrency: z.number().int().positive().default(8),
  requestsPerSecond: z.number().positive().default(10),
  crawlDepth: z.number().int().nonnegative().default(2),
  maxRuntimeSeconds: z.number().int().positive().default(1800),
  maxArtifactBytes: z.number().int().positive().default(8 * 1024 * 1024),
});

export const ScopePolicySchema = z.object({
  schemaVersion: z.literal(1),
  policyId: z.string().uuid(),
  projectId: z.string().uuid(),
  policyVersion: z.number().int().positive(),
  authorization: z.object({
    reference: z.string().min(1),
    authorizedBy: z.string().min(1),
    validFrom: z.string().datetime({ offset: true }),
    validUntil: z.string().datetime({ offset: true }),
    capabilities: z.array(CapabilitySchema).min(1),
  }),
  inScope: z.object({
    domains: z.array(DomainRuleSchema).default([]),
    hosts: z.array(z.string()).default([]),
    ips: z.array(z.string()).default([]),
    cidrs: z.array(z.string()).default([]),
  }),
  exclusions: z
    .object({
      domains: z.array(DomainRuleSchema).default([]),
      hosts: z.array(z.string()).default([]),
      ips: z.array(z.string()).default([]),
      cidrs: z.array(z.string()).default([]),
      paths: z.array(z.string()).default([]),
    })
    .default({}),
  limits: LimitsSchema.default({}),
});

export type ScopePolicy = z.infer<typeof ScopePolicySchema>;
export type DomainRule = z.infer<typeof DomainRuleSchema>;
export type Limits = z.infer<typeof LimitsSchema>;
/** The string-literal capability name, distinct from the `Capability` value object. */
export type CapabilityName = z.infer<typeof CapabilitySchema>;

export const ScopeTargetKind = {
  URL: "URL",
  HOST: "HOST",
  DOMAIN: "DOMAIN",
  IP: "IP",
  CIDR: "CIDR",
} as const;
export type ScopeTargetKindValue = (typeof ScopeTargetKind)[keyof typeof ScopeTargetKind];

/** Machine-readable denial reasons. Text is for humans; code is for automation. */
export const ScopeDecisionCode = {
  ALLOWED: "ALLOWED",
  AUTHORIZATION_EXPIRED: "AUTHORIZATION_EXPIRED",
  AUTHORIZATION_NOT_YET_VALID: "AUTHORIZATION_NOT_YET_VALID",
  CAPABILITY_NOT_PERMITTED: "CAPABILITY_NOT_PERMITTED",
  NOT_IN_SCOPE: "NOT_IN_SCOPE",
  EXCLUDED: "EXCLUDED",
  EXCLUDED_PATH: "EXCLUDED_PATH",
  RESTRICTED_ADDRESS_SPACE: "RESTRICTED_ADDRESS_SPACE",
  DNS_REBIND_DETECTED: "DNS_REBIND_DETECTED",
  DNS_RESOLUTION_FAILED: "DNS_RESOLUTION_FAILED",
  INVALID_TARGET: "INVALID_TARGET",
  LIMIT_EXCEEDED: "LIMIT_EXCEEDED",
} as const;
export type ScopeDecisionCodeValue = (typeof ScopeDecisionCode)[keyof typeof ScopeDecisionCode];

export interface ScopeCheckRequest {
  kind: ScopeTargetKindValue;
  value: string;
  capability: CapabilityName;
  /** Override for testing; defaults to now. */
  now?: Date;
  /** Resolved addresses for connection-time validation. */
  resolvedAddresses?: string[];
  /** True when evaluating a redirect hop rather than the initial target. */
  isRedirect?: boolean;
}

export interface AddressDecision {
  address: string;
  allowed: boolean;
  reason: string;
}

export interface ScopeDecision {
  allowed: boolean;
  code: ScopeDecisionCodeValue;
  reason: string;
  matchedRule?: string;
  addressDecisions?: AddressDecision[];
}

/** An append-only audit record for a scope decision. */
export interface ScopeAuditRecord {
  at: string;
  projectId: string;
  policyVersion: number;
  kind: ScopeTargetKindValue;
  value: string;
  capability: CapabilityName;
  decision: ScopeDecision;
}
