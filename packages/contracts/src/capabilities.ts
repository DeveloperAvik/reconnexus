/**
 * Operation classes that a scope policy may authorize. Capabilities are asserted
 * positively; absence of a capability is a denial, never a default allow.
 */
export const Capability = {
  /** Passive collection only: no packets sent to the target from this host. */
  PASSIVE: "PASSIVE",
  /** DNS resolution of in-scope names. */
  DNS: "DNS",
  /** Active HTTP/HTTPS connections to in-scope web services. */
  ACTIVE_HTTP: "ACTIVE_HTTP",
  /** Crawling / spidering of in-scope web services. */
  CRAWL: "CRAWL",
  /** Download and static analysis of JavaScript artifacts. */
  JS_ANALYSIS: "JS_ANALYSIS",
  /** API document discovery and parsing (OpenAPI, GraphQL introspection refs, Postman). */
  API_DISCOVERY: "API_DISCOVERY",
  /** Scanning of retrieved artifacts for potential secrets. */
  SECRET_SCAN: "SECRET_SCAN",
  /** Non-destructive security-header and configuration checks. */
  SECURITY_CHECKS: "SECURITY_CHECKS",
  /** Running approved template-based checks (e.g. selected nuclei templates). */
  ACTIVE_TEMPLATE_CHECK: "ACTIVE_TEMPLATE_CHECK",
  /** Non-destructive subdomain-takeover detection (DNS + one bounded HTTP request). */
  TAKEOVER_CHECK: "TAKEOVER_CHECK",
  /**
   * Permission to reach private/loopback/link-local/metadata address space.
   * This is a distinct, high-risk capability and is never implied by others.
   */
  INTERNAL_NETWORK: "INTERNAL_NETWORK",
} as const;

export type CapabilityValue = (typeof Capability)[keyof typeof Capability];

export const AllCapabilities: CapabilityValue[] = Object.values(Capability);

/** Capabilities that cause packets/requests to be sent to the target. */
export const ActiveCapabilities: ReadonlySet<CapabilityValue> = new Set([
  Capability.ACTIVE_HTTP,
  Capability.CRAWL,
  Capability.JS_ANALYSIS,
  Capability.API_DISCOVERY,
  Capability.SECURITY_CHECKS,
  Capability.ACTIVE_TEMPLATE_CHECK,
  Capability.TAKEOVER_CHECK,
  Capability.DNS,
]);

export function isActiveCapability(c: CapabilityValue): boolean {
  return ActiveCapabilities.has(c);
}
